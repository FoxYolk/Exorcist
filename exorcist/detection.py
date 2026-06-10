import asyncio
import io
import json
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp

log = logging.getLogger("exorcist.detection")

INVITE_RE = re.compile(r"(?:discord\.gg|discord(?:app)?\.com/invite)/\S+", re.I)
MONEY_RE = re.compile(r"\$\s?\d[\d,]{2,}|\b\d{3,6}\s?(?:usdt|usd|eth|btc)\b", re.I)
GIFT_WORDS = ("giveaway", "free", "reward", "claim", "bonus", "prize")
MAX_IMAGES = 4
MAX_FRAMES = 4                                 # frames sampled from an animated gif/webp
IMAGE_EMBED_TYPES = {"image", "gifv", "gif"}   # embed types we treat as a scam image source
EMBED_FETCH_TIMEOUT = 10
MAX_EMBED_BYTES = 8_000_000


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

        words = json.loads(Path(keywords_path).read_text(encoding="utf-8"))
        self.keywords = [k.lower() for k in words.get("keywords", [])]
        self.invite_bait = [b.lower() for b in words.get("invite_bait", [])]

        seed = Path(seed_hashes_path)
        self.seed_hashes = json.loads(seed.read_text(encoding="utf-8")) if seed.exists() else []

    async def evaluate(self, message, guild_conf):
        methods = guild_conf["methods"]
        v = Verdict()

        blobs = await self._download_images(message) if ("imagehash" in methods or "keyword" in methods) else []
        if blobs:
            v.image_name, v.image = blobs[0]

        if "imagehash" in methods and blobs:
            score, reasons, h, img, name = await self._score_imagehash(blobs, guild_conf["hash_distance"])
            v.score += score
            v.reasons += reasons
            if h:
                v.image_hash, v.image, v.image_name = h, img, name
        if "keyword" in methods:
            score, reasons, text = self._score_keywords(message, await self._read_images(blobs))
            v.score += score
            v.reasons += reasons
            v.text = text
        if "behavior" in methods:
            score, reasons = self._score_behavior(message, record=True)
            v.score += score
            v.reasons += reasons

        v.is_scam = v.score >= guild_conf["threshold"]
        return v

    async def analyze(self, message, guild_conf):
        """Dry run for the test channel. Runs every layer no matter what's enabled so you
        can see what would and wouldn't catch it, but never records or acts."""
        methods = guild_conf["methods"]
        blobs = await self._download_images(message)
        ocr_text = await self._read_images(blobs)

        ih = await self._score_imagehash(blobs, guild_conf["hash_distance"]) if blobs else (0.0, [], None, None, None)
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
        out = []
        async with aiohttp.ClientSession() as session:
            for url in urls:
                if not url.startswith(("http://", "https://")):
                    continue
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=EMBED_FETCH_TIMEOUT)) as resp:
                        if resp.status != 200 or not resp.content_type.startswith("image/"):
                            continue
                        if (resp.content_length or 0) > MAX_EMBED_BYTES:
                            continue
                        out.append((embed_name(url), await resp.read()))
                except Exception as e:
                    log.warning("couldn't fetch embed image: %s", e)
        return out

    async def _read_images(self, blobs):
        if not blobs or not self.ocr:
            return ""
        chunks = []
        for _, data in blobs:
            try:
                chunks.append(await asyncio.to_thread(self.ocr.read, data))
            except Exception as e:
                log.warning("ocr read failed: %s", e)
        return "\n".join(chunks)

    async def _score_imagehash(self, blobs, max_distance):
        try:
            import imagehash
        except ImportError:
            return 0.0, [], None, None, None

        known = list(self.config.learned_hashes) + self.seed_hashes
        best_hash = best_img = best_name = None
        for name, data in blobs:
            frame_hashes = await asyncio.to_thread(phashes, data)
            if not frame_hashes:
                continue
            if best_hash is None:
                best_hash, best_img, best_name = frame_hashes[0], data, name
            if any(self._matches(imagehash, h, known, max_distance) for h in frame_hashes):
                return 1.0, ["Matches a known scam image"], frame_hashes[0], data, name
        return 0.0, [], best_hash, best_img, best_name

    def _matches(self, imagehash, h, known, max_distance):
        target = imagehash.hex_to_hash(h)
        for k in known:
            try:
                if target - imagehash.hex_to_hash(k) <= max_distance:
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
    """Perceptual hashes for an image. A still image gives one hash, computed exactly like
    phash so the shipped seeds still match. An animated gif or webp gives a few, sampled
    across its frames, so a scam shown only on a later frame is caught and not just frame 0."""
    try:
        import imagehash
        from PIL import Image

        img = Image.open(io.BytesIO(data))
    except Exception:
        return []
    total = getattr(img, "n_frames", 1)
    if total <= 1 or max_frames <= 1:
        try:
            return [str(imagehash.phash(img))]
        except Exception:
            return []
    out = []
    for i in frame_indexes(total, max_frames):
        try:
            img.seek(i)
            out.append(str(imagehash.phash(img.convert("RGB"))))
        except Exception:
            continue
    return out


def frame_indexes(total, count):
    if total <= 1 or count <= 1:
        return [0]
    count = min(count, total)
    return sorted({round(i * (total - 1) / (count - 1)) for i in range(count)})


def phash(data):
    try:
        import imagehash
        from PIL import Image

        return str(imagehash.phash(Image.open(io.BytesIO(data))))
    except Exception:
        return None
