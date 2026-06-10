import io

import discord

from .theme import BULLET, CATCH, CLEAN, FLAGGED, HIT, NONE, OFF, PASS, WARN, WARNING, card


def scam_embed(message, verdict, status):
    member = message.author
    e = card("Scam caught", color=CATCH)
    e.set_thumbnail(url=member.display_avatar.url)

    e.add_field(name="User", value=f"{member.mention}\n`{member.id}`", inline=True)
    e.add_field(name="Account", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    if member.joined_at:
        e.add_field(name="Joined", value=discord.utils.format_dt(member.joined_at, "R"), inline=True)

    e.add_field(name="Channel", value=message.channel.mention, inline=True)
    e.add_field(name="Score", value=f"{verdict.score:.2f}", inline=True)

    if verdict.reasons:
        e.add_field(name="Signals", value="\n".join(f"{BULLET} {r}" for r in verdict.reasons), inline=False)

    body = message.content or verdict.text
    if body:
        e.add_field(name="Message", value=clip(body, 600), inline=False)

    if verdict.image_name:
        e.set_image(url=f"attachment://{safe_name(verdict.image_name)}")

    e.add_field(name="Action", value=status, inline=False)
    e.timestamp = message.created_at
    e.set_footer(text=f"message {message.id}")
    return e


def analysis_embed(message, result):
    flagged = result["is_scam"]
    mark, color = (FLAGGED, CATCH) if flagged else (CLEAN, PASS)
    head = "would be flagged" if flagged else "would pass"
    e = card("Test result", f"{mark}  **It {head}**\n`{result['score']:.2f}` of `{result['threshold']:.2f}` needed", color=color)

    for layer in result["layers"]:
        if not layer["enabled"]:
            dot, body = OFF, "Turned off"
        elif layer["reasons"]:
            dot, body = HIT, "\n".join(f"{BULLET} {r}" for r in layer["reasons"])
        else:
            dot, body = NONE, "Nothing"
        e.add_field(name=f"{dot}  {layer['name']}  +{layer['score']:.2f}", value=body, inline=False)

    e.set_footer(text="Test channel, nothing gets actioned here")
    return e


def trap_warning():
    return card(
        f"{WARNING}  Don't post here",
        "This channel is a trap for spam and hacked accounts. Real members have no reason to "
        "type in here.\n\n"
        "If you post anything you'll get timed out or banned, and your recent messages across the "
        "server get cleaned up.\n\n"
        "If your account starts posting here on its own, it's been compromised. Change your "
        "password and turn on 2FA.",
        color=WARN,
    )


def scam_files(verdict):
    if not verdict.image:
        return []
    return [discord.File(io.BytesIO(verdict.image), filename=safe_name(verdict.image_name))]


def safe_name(name):
    name = (name or "scam.png").rsplit("/", 1)[-1]
    return name if "." in name else name + ".png"


def clip(text, limit):
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."
