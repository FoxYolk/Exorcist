import logging

import discord
from discord.ext import commands

from . import theme
from .actions import UnmuteButton
from .config import Config
from .detection import Detector
from .ocr import load_ocr

log = logging.getLogger("exorcist")


class Exorcist(commands.Bot):
    def __init__(self, settings):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(command_prefix=commands.when_mentioned, intents=intents, help_command=None)

        self.config = Config(settings["config_path"])
        ocr = load_ocr(settings["tesseract_cmd"])
        self.detector = Detector(
            self.config, settings["keywords_path"], settings["seed_hashes_path"], ocr
        )

    async def setup_hook(self):
        self.add_dynamic_items(UnmuteButton)
        self.tree.error(self._on_command_error)
        await self.load_extension("exorcist.cogs.setup")
        await self.load_extension("exorcist.cogs.watch")
        await self.tree.sync()

    async def on_ready(self):
        log.info("logged in as %s, watching %d servers", self.user, len(self.guilds))
        theme.set_icon(self.user.display_avatar.url)
        await self.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name="for scams")
        )

    async def _on_command_error(self, interaction, error):
        log.exception("command %s failed: %s", getattr(interaction.command, "name", "?"), error)
        message = "Something broke running that. Give it another go in a sec."
        try:
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)
        except discord.HTTPException:
            pass
