import asyncio
import io
import json
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import imagehash
from PIL import Image

log = logging.getLogger("exorcist.detection")

INVITE_RE = re.compile(r"(?:discord\.gg|discord(?:app)?\.com/invite)/\S+", re.I)
MONEY_RE = re.compile(r"\$\s?\d[\d,]{2,}|\b\d{3,6}\s?(?:usdt|usd|eth|btc)\b", re.I)
GIFT_WORDS = ("giveaway", "free", "reward", "claim", "bonus", "prize")
MAX_IMAGES = 4
MAX_FRAMES = 4                                 # frames sampled from an animated gif/webp
IMAGE_EMBED_TYPES = {"image", "gifv", "gif"}   # embed types we treat as a scam image source
EMBED_FETCH_TIMEOUT = 10
MAX_EMBED_BYTES = 8_000_000
MAX_ATTACH_BYTES = 8_000_000                   # skip uploads bigger than this before reading them
OCR_CONCURRENCY = 2                            # cap simultaneous tesseract reads so bursts queue
# only fetch embed images from known image CDNs. blocks a posted link from pointing the bot's
# host at an internal/attacker address (SSRF) and keeps the "stays local" promise mostly true.
ALLOWED_EMBED_HOSTS = (
    "discordapp.net", "discordapp.com", "discord.com",
    "tenor.com", "giphy.com", "imgur.com",
)


@dataclass
class Verdict:
    is_scam: bool = False
    score: float = 0.0
    reasons: list = field(default_factory=list)
    text: str = ""
    image_hash: str = None
    image: bytes = None
    image_name: str = None
    hash_learned: bool = False


class BehaviorTracker:
    """Remembers what people posted in the last minute so we can spot one account
    spraying the same thing across a bunch of channels."""

    def __init__(self, window=60, cap=10000):
        self.window = window
        self.events = deque(maxlen=cap)

    def seen_channels(self, guild_id, user_id, channel_id, key):
        now = time.monotonic()
        while self.events and now - self.events[0][0] > self.window:
            self.events.popleft()

        channels = {ch for ts, g, uid, ch, k in self.events
                    if g == guild_id and uid == user_id and k == key}
        channels.add(channel_id)
        self.events.append((now, guild_id, user_id, channel_id, key))
        return len(channels)


class Detector:
    def __init__(self, config, keywords_path, seed_hashes_path, ocr=None):
        self.config = config
        self.ocr = ocr
        self.behavior = BehaviorTracker()
        self._ocr_sem = asyncio.Semaphore(OCR_CONCURRENCY)
        self._http = None            # one shared aiohttp session, opened lazily in the loop
        self._known_cache = None     # parsed known hashes, rebuilt when the pool changes
        self._known_version = None

        words = json.loads(Path(keywords_path).read_text(encoding="utf-8"))
        self.keywords = [k.lower() for k in words.get("keywords", [])]
        self.invite_bait = [b.lower() for b in words.get("invite_bait", [])]

        seed = Path(seed_hashes_path)
        self.seed_hashes = json.loads(seed.read_text(encoding="utf-8")) if seed.exists() else []

    async def close(self):
        if self._http and not self._http.closed:
            await self._http.close()

    async def _session(self):
        if self._http is None or self._http.closed:
            self._http = aiohttp.ClientSession()
        return self._http

    async def first_image_blob(self, message):
        """First usable image (attachment OR embed) as (name, bytes), or None. Shared by the
        honeypot and Mark-as-scam so they see the same sources the scorer does, embeds included."""
        blobs = await self._download_images(message)
        return blobs[0] if blobs else None

    async def evaluate(self, message, guild_conf):
        methods = guild_conf["methods"]
        threshold = guild_conf["threshold"]
        v = Verdict()

        blobs = await self._download_images(message) if ("imagehash" in methods or "keyword" in methods) else []
        if blobs:
            v.image_name, v.image = blobs[0]

        if "imagehash" in methods and blobs:
            score, reasons, h, img, name = await asyncio.to_thread(
                self._imagehash_sync, blobs, guild_conf["hash_distance"]
            )
            v.score += score
            v.reasons += reasons
            if h:
                v.image_hash, v.image, v.image_name = h, img, name
        if "behavior" in methods:
            score, reasons = self._score_behavior(message, record=True)
            v.score += score
            v.reasons += reasons
        if "keyword" in methods:
            # OCR is by far the most expensive step. Once the cheaper signals have already
            # crossed the threshold (e.g. a known-image hit during a raid) the verdict is
            # decided, so skip reading the image text and act faster.
            need_ocr = bool(blobs) and self.ocr is not None and v.score < threshold
            ocr_text = await self._read_images(blobs) if need_ocr else ""
            score, reasons, text = self._score_keywords(message, ocr_text)
            v.score += score
            v.reasons += reasons
            v.text = text

        v.is_scam = v.score >= threshold
        return v

    async def analyze(self, message, guild_conf):
        """Dry run for the test channel. Runs every layer no matter what's enabled so you
        can see what would and wouldn't catch it, but never records or acts."""
        methods = guild_conf["methods"]
        blobs = await self._download_images(message)
        ocr_text = await self._read_images(blobs)

        ih = await asyncio.to_thread(self._imagehash_sync, blobs, guild_conf["hash_distance"]) if blobs else (0.0, [], None, None, None)
        kw = self._score_keywords(message, ocr_text)
        bh = self._score_behavior(message, record=False)

        layers = [
            {"name": "Image match", "enabled": "imagehash" in methods, "score": ih[0], "reasons": ih[1]},
            {"name": "Keywords", "enabled": "keyword" in methods, "score": kw[0], "reasons": kw[1]},
            {"name": "Behavior", "enabled": "behavior" in methods, "score": bh[0], "reasons": bh[1]},
        ]
        total = sum(layer["score"] for layer in layers if layer["enabled"])
        threshold = guild_conf["threshold"]
        return {"is_scam": total >= threshold, "score": total, "threshold": threshold, "layers": layers}

    def hash_bytes(self, data):
        return phash(data)

    async def _download_images(self, message):
        blobs = []
        for a in image_attachments(message)[:MAX_IMAGES]:
            # skip huge uploads before reading them into RAM — Attachment.size is free, and a
            # handful of 25-500MB files across concurrent messages would otherwise OOM the host
            if a.size and a.size > MAX_ATTACH_BYTES:
                log.info("skipping oversized attachment %s (%d bytes)", a.filename, a.size)
                continue
            try:
                blobs.append((a.filename, await a.read()))
            except Exception as e:
                log.warning("couldn't download attachment: %s", e)
        # tenor/giphy gifs and pasted image links come through as embeds, not attachments
        room = MAX_IMAGES - len(blobs)
        urls = embed_images(message)
        if urls and room > 0:
            blobs.extend(await self._fetch_embeds(urls[:room]))
        return blobs

    async def _fetch_embeds(self, urls):
        session = await self._session()
        results = await asyncio.gather(*(self._fetch_one(session, url) for url in urls))
        return [r for r in results if r]

    async def _fetch_one(self, session, url):
        if not _allowed_embed_url(url):
            return None
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=EMBED_FETCH_TIMEOUT),
                allow_redirects=False,
            ) as resp:
                if resp.status != 200 or not resp.content_type.startswith("image/"):
                    return None
                if (resp.content_length or 0) > MAX_EMBED_BYTES:
                    return None
                # stream with a running cap so a chunked response with no Content-Length can't
                # buffer an unbounded body into memory
                data = bytearray()
                async for chunk in resp.content.iter_chunked(65536):
                    data += chunk
                    if len(data) > MAX_EMBED_BYTES:
                        log.info("embed image over size cap, dropping: %s", url)
                        return None
                return (embed_name(url), bytes(data))
        except Exception as e:
            log.warning("couldn't fetch embed image: %s", e)
            return None

    async def _read_images(self, blobs):
        if not blobs or not self.ocr:
            return ""
        chunks = []
        for _, data in blobs:
            try:
                async with self._ocr_sem:
                    chunks.append(await asyncio.to_thread(self.ocr.read, data))
            except Exception as e:
                log.warning("ocr read failed: %s", e)
        return "\n".join(chunks)

    def _imagehash_sync(self, blobs, max_distance):
        # runs in a worker thread (called via to_thread): hashing AND comparison are CPU work
        # and must stay off the event loop. returns (score, reasons, hex_hash, img, name).
        known = self._known_hashes()
        best_hash = best_img = best_name = None
        for name, data in blobs:
            frame_hashes = phashes(data)
            if not frame_hashes:
                continue
            if best_hash is None:
                # for a learn-on keyword/behavior catch we store this image's hash; prefer a
                # non-flat frame so we don't teach a degenerate hash that collides with the
                # blank opening frame of unrelated gifs across every server reading the pool
                best_hash, best_img, best_name = _representative(frame_hashes), data, name
            for h in frame_hashes:
                if self._matches(h, known, max_distance):
                    # learn the frame that actually matched, not frame 0
                    return 1.0, ["Matches a known scam image"], str(h), data, name
        return 0.0, [], (str(best_hash) if best_hash is not None else None), best_img, best_name

    def _known_hashes(self):
        # parse the hex pool into ImageHash objects once and reuse until the pool changes,
        # instead of re-parsing every known hash on every comparison
        version = self.config.hash_version
        if self._known_cache is None or self._known_version != version:
            parsed = []
            for hx in list(self.config.learned_hashes) + self.seed_hashes:
                try:
                    parsed.append(imagehash.hex_to_hash(hx))
                except (ValueError, TypeError):
                    log.warning("skipping unparseable known hash: %r", hx)
            self._known_cache = parsed
            self._known_version = version
        return self._known_cache

    def _matches(self, h, known, max_distance):
        for k in known:
            try:
                if h - k <= max_distance:
                    return True
            except Exception:
                continue
        return False

    def _score_keywords(self, message, ocr_text):
        typed = message_text(message)
        extra = "\n".join(x for x in (ocr_text, embed_text(message)) if x)
        text = f"{typed}\n{extra}" if extra else typed
        low = text.lower()
        typed_low = typed.lower()
        score = 0.0
        reasons = []

        hits = [k for k in self.keywords if k in low]
        if hits:
            score += min(0.4 + 0.18 * (len(hits) - 1), 0.85)
            reasons.append("Scam wording: " + ", ".join(hits[:5]))

        if INVITE_RE.search(typed):
            if any(b in typed_low for b in self.invite_bait):
                score += 0.5
                reasons.append("Server invite next to bait words")
            else:
                score += 0.1
                reasons.append("Contains a server invite")

        if MONEY_RE.search(low) and any(w in low for w in GIFT_WORDS):
            score += 0.25
            reasons.append("Free money pitch")

        return score, reasons, text.strip()

    def _score_behavior(self, message, record):
        score = 0.0
        reasons = []
        if message.mention_everyone:
            score += 0.3
            reasons.append("Pinged everyone")
        if record and worth_tracking(message):
            count = self.behavior.seen_channels(
                message.guild.id, message.author.id, message.channel.id, content_key(message)
            )
            if count >= 3:
                score += min(0.5 + 0.2 * (count - 3), 0.9)
                reasons.append(f"Same post in {count} channels within a minute")
        return score, reasons


def message_parts(message):
    # a forwarded message keeps the original in message_snapshots, each with its own content,
    # attachments and embeds. snapshots expose the same fields as a message, so walking them
    # together lets every check see forwarded scams too.
    return [message, *getattr(message, "message_snapshots", [])]


def part_attachments(part):
    return getattr(part, "attachments", None) or []


def part_embeds(part):
    return getattr(part, "embeds", None) or []


def image_attachments(message):
    out = []
    for part in message_parts(message):
        out.extend(a for a in part_attachments(part) if (a.content_type or "").startswith("image/"))
    return out


def first_image(message):
    images = image_attachments(message)
    return images[0] if images else None


def message_text(message):
    return "\n".join(getattr(p, "content", "") or "" for p in message_parts(message)).strip()


def embed_images(message):
    # tenor/giphy gifs and pasted image links arrive as image-ish embeds, not attachments.
    # ordinary link previews (type 'link'/'article'/'video') are skipped so we aren't pulling a
    # thumbnail for every link someone drops.
    urls = []
    for part in message_parts(message):
        for e in part_embeds(part):
            if e.type not in IMAGE_EMBED_TYPES:
                continue
            for media in (e.image, e.thumbnail):
                url = media.proxy_url or media.url
                if url:
                    urls.append(url)
    return urls


def embed_text(message):
    chunks = []
    for part in message_parts(message):
        for e in part_embeds(part):
            chunks += [e.title, e.description, e.author.name, e.footer.text]
            chunks += [f"{f.name} {f.value}" for f in e.fields]
    return "\n".join(c for c in chunks if c)


def embed_name(url):
    name = url.split("?", 1)[0].rsplit("/", 1)[-1]
    return name or "embed.png"


def content_key(message):
    key = message_text(message).lower()
    names = [a.filename for p in message_parts(message) for a in part_attachments(p)]
    if names:
        key += "|" + "|".join(names)
    return key


def worth_tracking(message):
    # don't let short everyday chatter ('gm', 'lol') count toward the spray check
    if any(part_attachments(p) for p in message_parts(message)):
        return True
    text = message_text(message)
    return len(text) >= 12 or "http" in text.lower()


def phashes(data, max_frames=MAX_FRAMES):
    """Perceptual hashes for an image, as ImageHash objects. A still image gives one, computed
    exactly like phash so the shipped seeds still match. An animated gif or webp gives a few,
    sampled across its frames, so a scam shown only on a later frame is caught and not just
    frame 0."""
    try:
        img = Image.open(io.BytesIO(data))
    except Exception as e:
        log.debug("couldn't open image for hashing: %s", e)
        return []
    total = getattr(img, "n_frames", 1)
    if total <= 1 or max_frames <= 1:
        try:
            return [imagehash.phash(img)]
        except Exception as e:
            log.debug("phash failed: %s", e)
            return []
    out = []
    for i in frame_indexes(total, max_frames):
        try:
            img.seek(i)
            out.append(imagehash.phash(img.convert("RGB")))
        except Exception as e:
            log.debug("frame phash failed: %s", e)
            continue
    return out


def _representative(frame_hashes):
    for h in frame_hashes:
        if not _is_degenerate(h):
            return h
    return frame_hashes[0]


def _is_degenerate(h):
    # a near-uniform (blank/solid) frame hashes to almost-all-equal bits, which matches far too
    # loosely. count the set bits of the 64-bit hash and treat the lopsided ends as degenerate.
    ones = int(h.hash.sum())
    return ones <= 6 or ones >= 58


def frame_indexes(total, count):
    if total <= 1 or count <= 1:
        return [0]
    count = min(count, total)
    return sorted({round(i * (total - 1) / (count - 1)) for i in range(count)})


def phash(data):
    try:
        return str(imagehash.phash(Image.open(io.BytesIO(data))))
    except Exception as e:
        log.debug("phash failed: %s", e)
        return None


def _allowed_embed_url(url):
    if not url.startswith("https://"):
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return any(host == h or host.endswith("." + h) for h in ALLOWED_EMBED_HOSTS)
