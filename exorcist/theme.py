import discord

# four color roles, kept tight so everything feels like one bot
VIOLET = discord.Color.from_str("#a78bfa")   # brand, setup, settings, status, info
CATCH = discord.Color.from_str("#f2557a")    # something got caught
PASS = discord.Color.from_str("#4fd1a1")     # clean, done, would pass
WARN = discord.Color.from_str("#f4c152")     # warning, review, confirm

GHOST = "\N{GHOST}"
SPARK = "\N{WHITE FOUR POINTED STAR}"
BULLET = "\N{BULLET}"

# verdict marks
FLAGGED = "\N{POLICE CARS REVOLVING LIGHT}"
CLEAN = "\N{WHITE HEAVY CHECK MARK}"
WARNING = "\N{WARNING SIGN}️"

# layer state dots for the test breakdown
HIT = "\N{LARGE GREEN CIRCLE}"      # contributed to the score
NONE = "\N{MEDIUM WHITE CIRCLE}"    # on, found nothing
OFF = "\N{MEDIUM BLACK CIRCLE}"     # method is turned off

_BAR_ON = "●"
_BAR_OFF = "○"
_DOT = "·"

_icon = None


def set_icon(url):
    # the bot's avatar, stashed once it's logged in so every card can wear it
    global _icon
    _icon = url


def card(title=None, description=None, color=VIOLET, kind=None):
    e = discord.Embed(title=title, description=description, color=color)
    e.set_author(name=f"Exorcist {_DOT} {kind}" if kind else "Exorcist", icon_url=_icon)
    return e


def progress(step, total):
    return f"{_BAR_ON * step}{_BAR_OFF * (total - step)}  {_DOT}  step {step} of {total}"
