"""Unit tests for the pure helpers — no Discord objects or network needed.

Run with: pytest  (install dev deps first: pip install -r requirements-dev.txt)
"""
import imagehash

from exorcist import actions, detection, logs, wizard
from exorcist.cogs.watch import parse_message_ref
from exorcist.config import Config, GUILD_DEFAULTS


# --- detection -------------------------------------------------------------

def test_frame_indexes_still_image():
    assert detection.frame_indexes(1, 4) == [0]
    assert detection.frame_indexes(10, 1) == [0]


def test_frame_indexes_samples_ends_and_dedupes():
    idx = detection.frame_indexes(10, 4)
    assert idx[0] == 0 and idx[-1] == 9
    assert idx == sorted(set(idx))
    assert len(idx) <= 4


def test_embed_name():
    assert detection.embed_name("https://cdn/x/y/cat.png?width=1") == "cat.png"
    assert detection.embed_name("https://cdn/x/") == "embed.png"


def test_allowed_embed_url_accepts_known_cdns():
    assert detection._allowed_embed_url("https://media.discordapp.net/x.png")
    assert detection._allowed_embed_url("https://media.tenor.com/x.gif")
    assert detection._allowed_embed_url("https://i.giphy.com/x.gif")


def test_allowed_embed_url_blocks_ssrf_and_lookalikes():
    assert not detection._allowed_embed_url("http://media.discordapp.net/x.png")   # not https
    assert not detection._allowed_embed_url("https://169.254.169.254/latest/meta") # internal
    assert not detection._allowed_embed_url("https://10.0.0.5/x.png")              # private
    assert not detection._allowed_embed_url("https://evil.example.com/x.png")
    assert not detection._allowed_embed_url("https://evil-discordapp.net/x.png")   # suffix trick
    assert not detection._allowed_embed_url("https://discordapp.net.evil.com/x")   # prefix trick


def test_is_degenerate_flags_flat_hashes():
    flat = imagehash.hex_to_hash("0000000000000000")        # all bits equal -> degenerate
    balanced = imagehash.hex_to_hash("00000000ffffffff")    # 32 set bits -> fine
    assert detection._is_degenerate(flat)
    assert not detection._is_degenerate(balanced)


# --- actions ---------------------------------------------------------------

def test_pretty_minutes():
    assert actions.pretty_minutes(45) == "45m"
    assert actions.pretty_minutes(60) == "1h"
    assert actions.pretty_minutes(1440) == "1d"
    assert actions.pretty_minutes(10080) == "1w"


# --- wizard ----------------------------------------------------------------

def test_labels():
    assert wizard.distance_label(14) == "Loose"
    assert wizard.threshold_label(0.8) == "Balanced"
    assert "Custom" in wizard.threshold_label(0.42)


def test_validate_setup():
    good = {"methods": ["keyword"], "log_channel": 1, "channels": "all", "trap_channel": None}
    assert wizard.validate_setup(good) == []

    bad = {"methods": [], "log_channel": None, "channels": [], "trap_channel": None}
    assert len(wizard.validate_setup(bad)) >= 3

    honeypot_no_trap = {"methods": ["honeypot"], "log_channel": 1, "channels": "all", "trap_channel": None}
    assert any("trap" in p for p in wizard.validate_setup(honeypot_no_trap))


# --- logs ------------------------------------------------------------------

def test_safe_name():
    assert logs.safe_name("a/b/c.png") == "c.png"
    assert logs.safe_name("noext") == "noext.png"
    assert logs.safe_name(None) == "scam.png"


def test_clip():
    assert logs.clip("hello", 10) == "hello"
    assert logs.clip("x" * 20, 10) == "x" * 7 + "..."


# --- watch -----------------------------------------------------------------

def test_parse_message_ref():
    assert parse_message_ref("123") == (None, 123)
    assert parse_message_ref("https://discord.com/channels/1/2/3") == (2, 3)
    assert parse_message_ref("not a ref") == (None, None)


# --- config ----------------------------------------------------------------

def test_guild_returns_isolated_copy(tmp_path):
    cfg = Config(tmp_path / "config.json")
    g = cfg.guild(123)
    g["access"]["users"].append(999)
    g["methods"].append("zzz")
    # mutating the returned copy must not leak into the live store or the module defaults
    assert cfg.guild(123)["access"]["users"] == []
    assert "zzz" not in cfg.guild(123)["methods"]
    assert GUILD_DEFAULTS["access"]["users"] == []
    assert "zzz" not in GUILD_DEFAULTS["methods"]


def test_bump_stat_persists(tmp_path):
    cfg = Config(tmp_path / "config.json")
    cfg.bump_stat(123, "caught")
    cfg.bump_stat(123, "caught")
    assert cfg.guild(123)["stats"]["caught"] == 2


def test_hash_version_bumps_only_on_change(tmp_path):
    cfg = Config(tmp_path / "config.json")
    v0 = cfg.hash_version
    assert cfg.add_hash("abc") is True
    assert cfg.hash_version == v0 + 1
    assert cfg.add_hash("abc") is False      # duplicate, no change
    assert cfg.hash_version == v0 + 1
    cfg.forget_hash("abc")
    assert cfg.hash_version == v0 + 2
