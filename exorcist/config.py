import copy
import json
import os
from pathlib import Path

GUILD_DEFAULTS = {
    "enabled": False,
    "channels": "all",            # "all" or a list of channel ids
    "methods": ["behavior", "imagehash", "keyword"],
    "log_channel": None,
    "trap_channel": None,         # honeypot channel, anyone who posts here is caught
    "test_channel": None,         # dry run channel, posts here get analyzed not actioned
    "action_mode": "auto",        # "auto" or "review"
    "punishments": ["timeout", "dm"],
    "timeout_minutes": 60,
    "self_unmute": False,         # let a timed out user lift it themselves after securing their account
    "learn": False,               # feed this server's catches into the shared pool, off by default
    "hash_distance": 14,          # how loose image match is, higher catches more lookalikes
    "threshold": 0.8,
    "exempt_mods": True,
    "stats": {},                  # lifetime counters: caught, honeypot, false_alarms
    "access": {"users": [], "roles": []},
}


class Config:
    """Reads and writes the json store. One file holds every guild's settings,
    the access whitelist, and the scam image hashes we've learned."""

    def __init__(self, path):
        self.path = Path(path)
        self._data = {"guilds": {}, "learned_hashes": []}
        # bumped on any change to learned_hashes so the detector can cache parsed hashes
        self._hash_version = 0
        if self.path.exists():
            self._data.update(json.loads(self.path.read_text(encoding="utf-8")))

    def save(self):
        # write to a temp file and swap it in so a crash mid write can't corrupt the store
        tmp = self.path.with_name(self.path.name + ".tmp")
        payload = json.dumps(self._data, indent=2)
        tmp.write_text(payload, encoding="utf-8")
        try:
            os.replace(tmp, self.path)
        except OSError:
            # os.replace can't rename over a single-file bind mount (EBUSY in Docker), so fall
            # back to writing in place. less crash-safe, but it keeps settings persisting there.
            self.path.write_text(payload, encoding="utf-8")
            tmp.unlink(missing_ok=True)

    def guild(self, guild_id):
        # edit the returned copy, then pass it to set_guild to persist. everything is deep
        # copied so mutating the copy can't leak into the live store before set_guild runs.
        stored = self._data["guilds"].get(str(guild_id), {})
        merged = copy.deepcopy(GUILD_DEFAULTS)
        merged.update(copy.deepcopy(stored))
        access = stored.get("access", {})
        merged["access"] = {
            "users": list(access.get("users", [])),
            "roles": list(access.get("roles", [])),
        }
        return merged

    def set_guild(self, guild_id, data):
        self._data["guilds"][str(guild_id)] = data
        self.save()

    def bump_stat(self, guild_id, key, n=1):
        stats = self._data["guilds"].setdefault(str(guild_id), {}).setdefault("stats", {})
        stats[key] = stats.get(key, 0) + n
        self.save()

    @property
    def hash_version(self):
        return self._hash_version

    @property
    def learned_hashes(self):
        return self._data.setdefault("learned_hashes", [])

    def add_hash(self, hex_hash):
        if hex_hash and hex_hash not in self.learned_hashes:
            self.learned_hashes.append(hex_hash)
            self._hash_version += 1
            self.save()
            return True
        return False

    def forget_hash(self, hex_hash):
        if hex_hash in self.learned_hashes:
            self.learned_hashes.remove(hex_hash)
            self._hash_version += 1
            self.save()

    def wipe_learned(self):
        count = len(self.learned_hashes)
        self._data["learned_hashes"] = []
        self._hash_version += 1
        self.save()
        return count


