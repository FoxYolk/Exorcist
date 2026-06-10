import logging
import re
from collections import deque

import discord
from discord import app_commands
from discord.ext import commands

from .. import actions, logs
from ..access import DENIED, is_manager
from ..detection import Verdict
from ..theme import SPARK

log = logging.getLogger("exorcist.watch")

# matches the channel and message ids out of a link like
# https://discord.com/channels/<guild>/<channel>/<message>
MSG_LINK_RE = re.compile(r"/channels/\d+/(\d+)/(\d+)")


class Watch(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = bot.config
        self.detector = bot.detector
        self.menu = app_commands.ContextMenu(name="Mark as scam", callback=self.mark_scam)
        bot.tree.add_command(self.menu)
        # message ids we've already acted on, so a later edit can't trigger a second catch
        self._handled = set()
        self._handled_q = deque(maxlen=2000)
        # guilds already warned that their log channel went missing, so we don't repeat it
        self._warned_guilds = set()

    def _mark_handled(self, message_id):
        if len(self._handled_q) == self._handled_q.maxlen:
            self._handled.discard(self._handled_q[0])
        self._handled_q.append(message_id)
        self._handled.add(message_id)

    async def cog_unload(self):
        self.bot.tree.remove_command(self.menu.name, type=self.menu.type)

    @commands.Cog.listener()
    async def on_message(self, message):
        # one bad message shouldn't take detection down or spam tracebacks
        try:
            await self._process(message)
        except Exception:
            gid = message.guild.id if message.guild else "dm"
            log.exception("on_message failed in guild %s", gid)

    @commands.Cog.listener()
    async def on_raw_message_edit(self, payload):
        # tenor/giphy/pasted-link embeds resolve via an edit moments after the message posts,
        # and a scam link can be edited into an innocent message — re-check edits so the embed
        # path actually fires live and edited-in scams don't slip past
        if payload.guild_id is None or payload.message_id in self._handled:
            return
        channel = self.bot.get_channel(payload.channel_id)
        if channel is None:
            return
        try:
            message = await channel.fetch_message(payload.message_id)
        except discord.HTTPException:
            return
        try:
            await self._process(message)
        except Exception:
            log.exception("on_message_edit failed in guild %s", payload.guild_id)

    async def _process(self, message):
        if message.guild is None or message.author.id == self.bot.user.id:
            return
        conf = self.config.guild(message.guild.id)
        is_bot = message.author.bot

        # the test channel works whether or not detection is live, so you can tune before turning it on
        if conf["test_channel"] and message.channel.id == conf["test_channel"]:
            if not is_bot:
                await self._analyze(message, conf)
            return
        if not conf["enabled"]:
            return

        log_channel = message.guild.get_channel(conf["log_channel"]) if conf["log_channel"] else None

        # the honeypot catches anyone — mods, bots, even a compromised webhook — since the
        # channel literally warns not to post there
        if is_trap(message, conf):
            await self._honeypot(message, conf, log_channel)
            return

        if conf["log_channel"] and log_channel is None:
            # the guild set a log channel but it's gone now; tell someone instead of failing silently
            await self._warn_missing_log(message.guild)
            return
        if log_channel is None:
            log.warning("guild %s is on but has no log channel, not acting", message.guild.id)
            return
        # scored detection skips bots/webhooks so legitimate integrations aren't flagged — the
        # honeypot above is what still catches a sprayed webhook
        if is_bot:
            return
        if conf["exempt_mods"] and message.author.guild_permissions.manage_messages:
            return
        if not in_scope(message.channel, conf):
            return
        if message.id in self._handled:
            return

        verdict = await self.detector.evaluate(message, conf)
        if not verdict.is_scam:
            return
        self._mark_handled(message.id)
        if conf["action_mode"] == "review":
            await self._review(message, verdict, conf, log_channel)
        else:
            await self._auto(message, verdict, conf, log_channel)

    async def _warn_missing_log(self, guild):
        if guild.id in self._warned_guilds:
            return
        self._warned_guilds.add(guild.id)
        log.warning("guild %s is on but its log channel is gone, not acting", guild.id)
        text = (f"Heads up: Exorcist is on in **{guild.name}** but its log channel is gone, so it "
                "isn't acting on anything. Pick a new one with `/settings`.")
        try:
            if guild.system_channel and guild.system_channel.permissions_for(guild.me).send_messages:
                await guild.system_channel.send(text)
            elif guild.owner:
                await guild.owner.send(text)
        except discord.HTTPException:
            pass

    async def _honeypot(self, message, conf, log_channel):
        # no scoring needed, posting in the trap channel is the signal
        verdict = Verdict(is_scam=True, score=1.0, reasons=["Posted in the honeypot channel"], text=message.content)
        self._mark_handled(message.id)
        blob = await self.detector.first_image_blob(message)
        if blob:
            verdict.image_name, verdict.image = blob
            verdict.image_hash = self.detector.hash_bytes(verdict.image)

        deleted = await actions.try_delete(message)
        if message.webhook_id:
            # a timeout/kick can't touch a webhook, so pull the webhook itself instead
            removed = await actions.delete_webhook(message)
            done = ["removed the webhook" if removed else "couldn't remove the webhook (needs Manage Webhooks)"]
            cleared = 0
        else:
            done = await actions.punish(message, conf, "Exorcist: posted in the honeypot")
            cleared = await actions.purge_recent(message.guild, message.author)
        if verdict.image_hash and conf["learn"]:
            verdict.hash_learned = self.config.add_hash(verdict.image_hash)
        self.config.bump_stat(message.guild.id, "honeypot")

        parts = ["Deleted" if deleted else "Couldn't delete (check Manage Messages)"] + done
        if cleared:
            parts.append(f"cleared {cleared} recent message{'s' if cleared != 1 else ''}")
        if verdict.hash_learned:
            parts.append("image learned")
        view = UndoView(self, message.author, verdict)
        msg = await self._post(log_channel, message, verdict, ", ".join(parts), view)
        if msg:
            view.log_message = msg
        verdict.image = None  # the bytes were only needed for the log upload; don't pin them

    async def _analyze(self, message, conf):
        result = await self.detector.analyze(message, conf)
        try:
            await message.reply(embed=logs.analysis_embed(message, result), mention_author=False)
        except discord.HTTPException:
            pass

    async def _auto(self, message, verdict, conf, log_channel):
        status = await self._enforce(message, verdict, conf, "Exorcist: scam detected")
        view = UndoView(self, message.author, verdict)
        msg = await self._post(log_channel, message, verdict, status, view)
        if msg:
            view.log_message = msg
        verdict.image = None  # the bytes were only needed for the log upload; don't pin them

    async def _enforce(self, message, verdict, conf, reason, *, confirmer=None):
        """The shared catch sequence — delete, punish, learn the image, count it, build the
        status line. Used by auto mode and the review Confirm button so they can't drift."""
        deleted = await actions.try_delete(message)
        done = await actions.punish(message, conf, reason)
        if verdict.image_hash and conf["learn"]:
            verdict.hash_learned = self.config.add_hash(verdict.image_hash)
        self.config.bump_stat(message.guild.id, "caught")
        parts = ["Deleted" if deleted else "Couldn't delete (check Manage Messages)"] + done
        if verdict.hash_learned:
            parts.append("image learned")
        status = ", ".join(parts)
        if confirmer:
            status = f"Confirmed by {confirmer}, " + status
        return status

    async def _review(self, message, verdict, conf, log_channel):
        view = ReviewView(self, message, verdict, conf)
        msg = await self._post(log_channel, message, verdict, "Waiting for a mod to confirm", view)
        if msg:
            view.log_message = msg
        verdict.image = None  # already uploaded to the log; the buttons only need the hash

    async def _post(self, log_channel, message, verdict, status, view=None):
        if log_channel is None:
            log.warning("guild %s has no log channel set, skipping", message.guild.id)
            return None
        try:
            return await log_channel.send(
                embed=logs.scam_embed(message, verdict, status),
                files=logs.scam_files(verdict),
                view=view,
            )
        except discord.HTTPException as e:
            log.warning("couldn't post to the log channel: %s", e)
            return None

    async def mark_scam(self, interaction, message: discord.Message):
        if not is_manager(interaction.user, self.config.guild(interaction.guild_id)):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        try:
            # first_image_blob covers embed-delivered scams (Tenor/Giphy/pasted links) too, not
            # just uploads, so the most common gif scams can actually be taught by hand
            blob = await self.detector.first_image_blob(message)
        except discord.HTTPException:
            return await interaction.followup.send("That message or its image is gone now.", ephemeral=True)
        if blob is None:
            return await interaction.followup.send("That message has no image for me to learn from.", ephemeral=True)

        _, data = blob
        h = self.detector.hash_bytes(data)
        if not h:
            return await interaction.followup.send("Couldn't read that image, sorry.", ephemeral=True)
        self.config.add_hash(h)
        deleted = await actions.try_delete(message)
        lead = "Deleted it and added" if deleted else "Couldn't delete it (check Manage Messages), but added"
        await interaction.followup.send(
            f"{lead} that image to the scam list, it'll get caught next time. {SPARK}", ephemeral=True
        )

    @app_commands.command(description="Analyze a posted message and its media against the detector")
    @app_commands.guild_only()
    @app_commands.describe(
        message="Message ID, or a message link (right-click a message > Copy Message Link)",
        channel="Channel the message is in, if you passed an ID and it isn't in this channel",
    )
    async def analyze(self, interaction, message: str, channel: discord.TextChannel = None):
        if not is_manager(interaction.user, self.config.guild(interaction.guild_id)):
            return await interaction.response.send_message(DENIED, ephemeral=True)

        chan_id, msg_id = parse_message_ref(message)
        if msg_id is None:
            return await interaction.response.send_message(
                "That isn't a message ID or link. Right-click a message and use Copy Message ID "
                "or Copy Message Link.",
                ephemeral=True,
            )

        # a link carries its own channel, otherwise fall back to the one passed or the current one
        target = channel or interaction.channel
        if chan_id is not None:
            target = interaction.guild.get_channel_or_thread(chan_id) or target

        await interaction.response.defer(ephemeral=True)
        try:
            msg = await target.fetch_message(msg_id)
        except discord.NotFound:
            return await interaction.followup.send(
                f"Couldn't find that message in {target.mention}. If it's in another channel, "
                "pass the channel option or paste the message link.",
                ephemeral=True,
            )
        except discord.Forbidden:
            return await interaction.followup.send(
                f"I can't read messages in {target.mention}, check my permissions there.",
                ephemeral=True,
            )

        conf = self.config.guild(interaction.guild_id)
        result = await self.detector.analyze(msg, conf)
        await interaction.followup.send(
            embed=logs.analysis_embed(msg, result, footer="Analysis only, nothing gets actioned"),
            ephemeral=True,
        )


class ReviewView(discord.ui.View):
    def __init__(self, cog, message, verdict, conf):
        super().__init__(timeout=604800)  # a week to confirm before the buttons go quiet
        self.cog = cog
        self.target = message       # the scam message under review
        self.verdict = verdict
        self.conf = conf
        self.log_message = None     # the log embed this view sits on, for on_timeout
        self._acting = False

    async def _allowed(self, interaction):
        if is_manager(interaction.user, self.cog.config.guild(interaction.guild_id)):
            return True
        await interaction.response.send_message(DENIED, ephemeral=True)
        return False

    @discord.ui.button(label="Confirm scam", style=discord.ButtonStyle.danger, emoji="\N{HAMMER}")
    async def confirm(self, interaction, button):
        if not await self._allowed(interaction):
            return
        if self._acting:
            return await interaction.response.defer()
        self._acting = True
        # the catch can take up to ~10s on the DM, past the 3s interaction window, so defer
        # first; that also keeps a second click from running the whole sequence again
        await interaction.response.defer()
        status = await self.cog._enforce(
            self.target, self.verdict, self.conf, "Exorcist: confirmed by a mod",
            confirmer=interaction.user.mention,
        )
        e = interaction.message.embeds[0]
        set_status(e, status)
        # hand off to the false alarm button so a mistaken confirm can still be walked back
        await interaction.edit_original_response(
            embed=e, view=UndoView(self.cog, self.target.author, self.verdict)
        )
        self.stop()

    @discord.ui.button(label="Ignore", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def ignore(self, interaction, button):
        if not await self._allowed(interaction):
            return
        await self._close(interaction, f"Cleared by {interaction.user.mention}, left it alone")

    async def _close(self, interaction, status):
        for child in self.children:
            child.disabled = True
        e = interaction.message.embeds[0]
        set_status(e, status)
        await interaction.response.edit_message(embed=e, view=self)
        self.stop()

    async def on_timeout(self):
        if self.log_message is None:
            return
        for child in self.children:
            child.disabled = True
        try:
            if self.log_message.embeds:
                e = self.log_message.embeds[0]
                set_status(e, "Review expired — use /analyze and moderate manually")
                await self.log_message.edit(embed=e, view=self)
            else:
                await self.log_message.edit(view=self)
        except discord.HTTPException:
            pass


class UndoView(discord.ui.View):
    def __init__(self, cog, member, verdict):
        super().__init__(timeout=86400)  # a day to flag a false alarm
        self.cog = cog
        self.member = member
        self.verdict = verdict
        self.log_message = None     # the log embed this view sits on, for on_timeout

    @discord.ui.button(label="False alarm", style=discord.ButtonStyle.secondary, emoji="↩️")
    async def false_alarm(self, interaction, button):
        if not is_manager(interaction.user, self.cog.config.guild(interaction.guild_id)):
            return await interaction.response.send_message(DENIED, ephemeral=True)

        conf = self.cog.config.guild(interaction.guild_id)
        lifted = await actions.undo(interaction.guild, self.member, conf)
        # only forget the image if this catch is what taught it, otherwise we'd wipe a real scam hash
        if self.verdict.image_hash and self.verdict.hash_learned:
            self.cog.config.forget_hash(self.verdict.image_hash)
            lifted.append("forgot that image")
        self.cog.config.bump_stat(interaction.guild_id, "false_alarms")

        note = ", ".join(lifted) if lifted else "couldn't auto reverse it, if they got kicked you'll need to re invite them"
        button.disabled = True
        e = interaction.message.embeds[0]
        set_status(e, f"False alarm by {interaction.user.mention}, {note}")
        await interaction.response.edit_message(embed=e, view=self)
        self.stop()

    async def on_timeout(self):
        if self.log_message is None:
            return
        for child in self.children:
            child.disabled = True
        try:
            await self.log_message.edit(view=self)
        except discord.HTTPException:
            pass


def parse_message_ref(raw):
    """Pull (channel_id, message_id) out of a message link, or (None, message_id) from a bare
    id. Returns (None, None) if it's neither."""
    raw = raw.strip()
    m = MSG_LINK_RE.search(raw)
    if m:
        return int(m.group(1)), int(m.group(2))
    if raw.isdigit():
        return None, int(raw)
    return None, None


def is_trap(message, conf):
    return (
        "honeypot" in conf["methods"]
        and conf["trap_channel"]
        and message.channel.id == conf["trap_channel"]
    )


def in_scope(channel, conf):
    if conf["channels"] == "all":
        return True
    watched = conf["channels"]
    parent = getattr(channel, "parent_id", None)
    return channel.id in watched or (parent in watched if parent else False)


def set_status(embed, value):
    for i, f in enumerate(embed.fields):
        if f.name == "Action":
            embed.set_field_at(i, name="Action", value=value, inline=False)
            return
    embed.add_field(name="Action", value=value, inline=False)


async def setup(bot):
    await bot.add_cog(Watch(bot))
