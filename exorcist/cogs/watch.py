import logging

import discord
from discord import app_commands
from discord.ext import commands

from .. import actions, logs
from ..access import DENIED, is_manager
from ..detection import Verdict, first_image
from ..theme import SPARK

log = logging.getLogger("exorcist.watch")


class Watch(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = bot.config
        self.detector = bot.detector
        self.menu = app_commands.ContextMenu(name="Mark as scam", callback=self.mark_scam)
        bot.tree.add_command(self.menu)

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

    async def _process(self, message):
        if message.author.bot or message.guild is None:
            return
        conf = self.config.guild(message.guild.id)

        # the test channel works whether or not detection is live, so you can tune before turning it on
        if conf["test_channel"] and message.channel.id == conf["test_channel"]:
            await self._analyze(message, conf)
            return
        if not conf["enabled"]:
            return

        log_channel = message.guild.get_channel(conf["log_channel"]) if conf["log_channel"] else None

        # the honeypot catches anyone, mods included, since the channel literally warns not to post there
        if is_trap(message, conf):
            await self._honeypot(message, conf, log_channel)
            return

        if log_channel is None:
            log.warning("guild %s is on but has no log channel, not acting", message.guild.id)
            return
        if conf["exempt_mods"] and message.author.guild_permissions.manage_messages:
            return
        if not in_scope(message.channel, conf):
            return

        verdict = await self.detector.evaluate(message, conf)
        if not verdict.is_scam:
            return
        if conf["action_mode"] == "review":
            await self._review(message, verdict, conf, log_channel)
        else:
            await self._auto(message, verdict, conf, log_channel)

    async def _honeypot(self, message, conf, log_channel):
        # no scoring needed, posting in the trap channel is the signal
        verdict = Verdict(is_scam=True, score=1.0, reasons=["Posted in the honeypot channel"], text=message.content)
        img = first_image(message)
        if img:
            try:
                data = await img.read()
                verdict.image, verdict.image_name = data, img.filename
                verdict.image_hash = self.detector.hash_bytes(data)
            except discord.HTTPException:
                pass

        try:
            await message.delete()
        except discord.HTTPException:
            pass
        done = await actions.punish(message, conf, "Exorcist: posted in the honeypot")
        cleared = await actions.purge_recent(message.guild, message.author)
        if verdict.image_hash and conf["learn"]:
            verdict.hash_learned = self.config.add_hash(verdict.image_hash)

        status = ", ".join(["Deleted"] + done)
        if cleared:
            status += f", cleared {cleared} recent message{'s' if cleared != 1 else ''}"
        await self._post(log_channel, message, verdict, status, UndoView(self, message.author, verdict))

    async def _analyze(self, message, conf):
        result = await self.detector.analyze(message, conf)
        try:
            await message.reply(embed=logs.analysis_embed(message, result), mention_author=False)
        except discord.HTTPException:
            pass

    async def _auto(self, message, verdict, conf, log_channel):
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        done = await actions.punish(message, conf, "Exorcist: scam detected")
        if verdict.image_hash and conf["learn"]:
            verdict.hash_learned = self.config.add_hash(verdict.image_hash)
        status = ", ".join(["Deleted"] + done)
        view = UndoView(self, message.author, verdict)
        await self._post(log_channel, message, verdict, status, view)

    async def _review(self, message, verdict, conf, log_channel):
        view = ReviewView(self, message, verdict, conf)
        await self._post(log_channel, message, verdict, "Waiting for a mod to confirm", view)

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
        img = first_image(message)
        if img is None:
            return await interaction.response.send_message("That message has no image for me to learn from.", ephemeral=True)

        data = await img.read()
        h = self.detector.hash_bytes(data)
        if not h:
            return await interaction.response.send_message("Couldn't read that image, sorry.", ephemeral=True)
        self.config.add_hash(h)
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        await interaction.response.send_message(f"Added that image to the scam list, it'll get caught next time. {SPARK}", ephemeral=True)


class ReviewView(discord.ui.View):
    def __init__(self, cog, message, verdict, conf):
        super().__init__(timeout=604800)  # a week to confirm before the buttons go quiet
        self.cog = cog
        self.message = message
        self.verdict = verdict
        self.conf = conf

    async def _allowed(self, interaction):
        if is_manager(interaction.user, self.cog.config.guild(interaction.guild_id)):
            return True
        await interaction.response.send_message(DENIED, ephemeral=True)
        return False

    @discord.ui.button(label="Confirm scam", style=discord.ButtonStyle.danger, emoji="\N{HAMMER}")
    async def confirm(self, interaction, button):
        if not await self._allowed(interaction):
            return
        try:
            await self.message.delete()
        except discord.HTTPException:
            pass
        done = await actions.punish(self.message, self.conf, "Exorcist: confirmed by a mod")
        if self.verdict.image_hash and self.conf["learn"]:
            self.verdict.hash_learned = self.cog.config.add_hash(self.verdict.image_hash)
        status = f"Confirmed by {interaction.user.mention}, " + ", ".join(["deleted"] + done)
        e = interaction.message.embeds[0]
        set_status(e, status)
        # hand off to the false alarm button so a mistaken confirm can still be walked back
        await interaction.response.edit_message(embed=e, view=UndoView(self.cog, self.message.author, self.verdict))
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


class UndoView(discord.ui.View):
    def __init__(self, cog, member, verdict):
        super().__init__(timeout=86400)  # a day to flag a false alarm
        self.cog = cog
        self.member = member
        self.verdict = verdict

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

        note = ", ".join(lifted) if lifted else "couldn't auto reverse it, if they got kicked you'll need to re invite them"
        button.disabled = True
        e = interaction.message.embeds[0]
        set_status(e, f"False alarm by {interaction.user.mention}, {note}")
        await interaction.response.edit_message(embed=e, view=self)
        self.stop()


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
