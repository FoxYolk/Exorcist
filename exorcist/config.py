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
    "access": {"users": [], "roles": []},
}


class Config:
    """Reads and writes the json store. One file holds every guild's settings,
    the access whitelist, and the scam image hashes we've learned."""

    def __init__(self, path):
        self.path = Path(path)
        self._data = {"guilds": {}, "learned_hashes": []}
        if self.path.exists():
            self._data.update(json.loads(self.path.read_text(encoding="utf-8")))

    def save(self):
        # write to a temp file and swap it in so a crash mid write can't corrupt the store
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def guild(self, guild_id):
        # edit the returned copy, then pass it to set_guild to persist
        stored = self._data["guilds"].get(str(guild_id), {})
        merged = copy.deepcopy(GUILD_DEFAULTS)
        merged.update(stored)
        merged["access"] = {**GUILD_DEFAULTS["access"], **stored.get("access", {})}
        return merged

    def set_guild(self, guild_id, data):
        self._data["guilds"][str(guild_id)] = data
        self.save()

    @property
    def learned_hashes(self):
        return self._data.setdefault("learned_hashes", [])

    def add_hash(self, hex_hash):
        if hex_hash and hex_hash not in self.learned_hashes:
            self.learned_hashes.append(hex_hash)
            self.save()
            return True
        return False

    def forget_hash(self, hex_hash):
        if hex_hash in self.learned_hashes:
            self.learned_hashes.remove(hex_hash)
            self.save()

    def wipe_learned(self):
        count = len(self.learned_hashes)
        self._data["learned_hashes"] = []
        self.save()
        return count


