import logging

import discord
from discord.ext import commands

from . import theme
from .actions import UnmuteButton, set_dms_enabled
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
        set_dms_enabled(settings.get("dms_enabled", True))

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

    async def close(self):
        # release the shared aiohttp session the detector opened for embed fetches
        await self.detector.close()
        await super().close()

    async def _on_command_error(self, interaction, error):
        # tag the console log and the user reply with the same short ref so a report can be
        # matched to its traceback
        ref = f"{id(error) & 0xffffff:06x}"
        log.exception("command %s failed [ref %s]: %s", getattr(interaction.command, "name", "?"), ref, error)
        message = f"Something broke running that (ref `{ref}`). Check the bot's console log if it keeps happening."
        try:
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)
        except discord.HTTPException:
            pass
