import asyncio
import logging
from datetime import timedelta

import discord

log = logging.getLogger("exorcist.actions")

# a member with DMs closed fails fast, but opening a DM channel is heavily rate limited, so a
# burst of catches can make a send hang for a while. cap it so removal and logging never wait
# on the DM.
DM_TIMEOUT = 10

# global off switch for resecure DMs, flipped from EXORCIST_DISABLE_DMS at startup. when off,
# Exorcist never DMs anyone on any server, even if "dm" is in that server's punishments.
_dms_enabled = True


def set_dms_enabled(enabled):
    global _dms_enabled
    _dms_enabled = enabled


def dms_enabled():
    return _dms_enabled


async def try_delete(message):
    """Delete a message, reporting whether it actually went. NotFound means it's already gone
    (fine), Forbidden/other means we couldn't — the caller surfaces that honestly in the log."""
    try:
        await message.delete()
        return True
    except discord.NotFound:
        return True
    except discord.HTTPException:
        return False


async def delete_webhook(message):
    """Remove the webhook a message was posted through (used for honeypot hits from a
    compromised webhook, which timeouts/kicks can't touch). Needs Manage Webhooks."""
    if not message.webhook_id:
        return False
    try:
        for hook in await message.channel.webhooks():
            if hook.id == message.webhook_id:
                await hook.delete(reason="Exorcist: posted in the honeypot")
                return True
    except discord.HTTPException:
        pass
    return False

RESECURE_DM = (
    "Hey, your account just posted a scam in **{guild}**, which almost always means it got "
    "hacked. We took the message down and paused your account there so it can't keep spamming.\n\n"
    "To lock it back down:\n"
    "{steps}\n\n"
    "Once that's sorted, you're good to come back."
)

STEPS = [
    "Change your Discord password right now.",
    "Turn on 2FA under Settings, My Account.",
    "Open Settings, Authorized Apps and remove anything you don't recognize.",
    "If you ran any random program or 'nitro' installer lately, scan your PC.",
]


async def punish(message, guild_conf, reason):
    """Applies whatever the server picked. Returns short strings for the log
    so a mod can see what actually happened."""
    member = message.author
    picks = guild_conf["punishments"]
    done = []

    if "dm" in picks and _dms_enabled:
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(STEPS, 1))
        body = RESECURE_DM.format(guild=message.guild.name, steps=steps)
        view = None
        will_timeout = "timeout" in picks and "ban" not in picks and "kick" not in picks
        if will_timeout and guild_conf["self_unmute"]:
            body += "\n\nOnce it's actually secured, hit the button below to lift your own timeout."
            # bind the button to this specific timeout so it can't be reused later to lift an
            # unrelated, mod-applied timeout
            expiry = discord.utils.utcnow() + timedelta(minutes=guild_conf["timeout_minutes"])
            view = unmute_view(message.guild.id, expiry)
        try:
            await asyncio.wait_for(member.send(body, view=view), timeout=DM_TIMEOUT)
            done.append("DM sent")
        except discord.Forbidden:
            done.append("DM closed")
        except (discord.HTTPException, asyncio.TimeoutError):
            done.append("DM failed")
    elif "dm" in picks and not _dms_enabled:
        # the guild configured a resecure DM but the host turned DMs off everywhere — say so,
        # rather than silently dropping it like every other DM outcome is reported
        done.append("DM skipped (off bot-wide)")

    # only one removal makes sense, strongest wins
    try:
        if "ban" in picks:
            # we already deleted the scam message, no need to wipe an hour of their history too
            await message.guild.ban(member, reason=reason, delete_message_seconds=0)
            done.append("banned")
        elif "kick" in picks:
            await member.kick(reason=reason)
            done.append("kicked")
        elif "timeout" in picks:
            minutes = guild_conf["timeout_minutes"]
            await member.timeout(timedelta(minutes=minutes), reason=reason)
            done.append(f"timed out {pretty_minutes(minutes)}")
    except discord.Forbidden:
        done.append("couldn't remove them, check my role is above theirs")
    except discord.HTTPException as e:
        log.warning("removal failed: %s", e)
        done.append("removal failed")

    return done


async def purge_recent(guild, member, window_minutes=10, per_channel=50):
    """Clears a user's recent messages across the server, used after a honeypot hit
    so a spraying account doesn't leave copies everywhere. Bulk delete only reaches
    messages under 14 days old, which is fine for a live spam wave."""
    cutoff = discord.utils.utcnow() - timedelta(minutes=window_minutes)
    removed = 0
    for channel in guild.text_channels:
        perms = channel.permissions_for(guild.me)
        if not (perms.read_message_history and perms.manage_messages):
            continue
        try:
            deleted = await channel.purge(
                limit=per_channel, after=cutoff, check=lambda m: m.author.id == member.id
            )
            removed += len(deleted)
        except discord.HTTPException:
            continue
    return removed


async def undo(guild, member, guild_conf):
    """Undoes what it can after a false alarm. Can't restore a deleted message
    or a kick, but it lifts a timeout or ban."""
    lifted = []
    try:
        await guild.unban(member, reason="Exorcist: false alarm")
        lifted.append("unbanned")
    except (discord.NotFound, discord.HTTPException):
        pass
    try:
        m = guild.get_member(member.id)
        if m and m.is_timed_out():
            await m.timeout(None, reason="Exorcist: false alarm")
            lifted.append("timeout lifted")
    except discord.HTTPException:
        pass
    return lifted


def pretty_minutes(minutes):
    if minutes % 10080 == 0:
        return f"{minutes // 10080}w"
    if minutes % 1440 == 0:
        return f"{minutes // 1440}d"
    if minutes % 60 == 0:
        return f"{minutes // 60}h"
    return f"{minutes}m"


class UnmuteButton(discord.ui.DynamicItem[discord.ui.Button], template=r"exorcist:unmute:(?P<guild_id>\d+):(?P<expiry>\d+)"):
    """Goes on the resecure DM. The guild id and the timeout's expiry ride in the custom id so
    a click still works after a restart (once the bot registers this with add_dynamic_items)
    and so the button only lifts the exact timeout it was issued for."""

    def __init__(self, guild_id, expiry_ts=0):
        self.guild_id = guild_id
        self.expiry_ts = int(expiry_ts)
        super().__init__(
            discord.ui.Button(
                label="I secured my account, unmute me",
                style=discord.ButtonStyle.success,
                emoji="\N{OPEN LOCK}",
                custom_id=f"exorcist:unmute:{guild_id}:{int(expiry_ts)}",
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(int(match["guild_id"]), int(match["expiry"]))

    async def callback(self, interaction):
        bot = interaction.client
        guild = bot.get_guild(self.guild_id)
        if guild is None:
            return await interaction.response.send_message("I can't reach that server anymore.", ephemeral=True)
        if not bot.config.guild(self.guild_id)["self_unmute"]:
            return await interaction.response.send_message("That server turned self unmute off, reach out to a mod.", ephemeral=True)

        member = guild.get_member(interaction.user.id)
        if member is None:
            # cache miss — don't tell a genuinely timed-out user they're fine
            try:
                member = await guild.fetch_member(interaction.user.id)
            except discord.HTTPException:
                member = None
        if member is None or not member.is_timed_out():
            return await interaction.response.send_message("You're not timed out there, you're all good.", ephemeral=True)
        # only lift the timeout this button was handed out for, so an old DM can't clear a
        # later timeout a mod applied for something unrelated
        if self.expiry_ts:
            until = member.timed_out_until
            if until is None or abs(until.timestamp() - self.expiry_ts) > 120:
                return await interaction.response.send_message(
                    "This looks like a different timeout than the one I set, so I won't lift it. Reach out to a mod.",
                    ephemeral=True,
                )
        try:
            await member.timeout(None, reason="Exorcist: self unmute after securing the account")
        except discord.Forbidden:
            return await interaction.response.send_message("I couldn't lift it, ping a mod.", ephemeral=True)
        await interaction.response.send_message("Done, your timeout's lifted. Stay safe out there.", ephemeral=True)


def unmute_view(guild_id, expiry=None):
    expiry_ts = int(expiry.timestamp()) if expiry else 0
    view = discord.ui.View(timeout=None)
    view.add_item(UnmuteButton(guild_id, expiry_ts))
    return view
