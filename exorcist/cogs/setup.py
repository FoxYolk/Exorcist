import discord
from discord import app_commands
from discord.ext import commands

from .. import logs
from ..access import DENIED, is_manager
from ..theme import HIT, NONE, PASS, SPARK, VIOLET, WARN, card
from ..wizard import (PUNISH, SettingsPanel, SetupWizard, channel_mention, channels_text,
                      distance_label, methods_text, pretty_minutes)


class Setup(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = bot.config

    def _allowed(self, interaction):
        return is_manager(interaction.user, self.config.guild(interaction.guild_id))

    @app_commands.command(description="Walk through Exorcist setup for this server")
    @app_commands.guild_only()
    async def setup(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        draft = self.config.guild(interaction.guild_id)
        await SetupWizard(self.config, interaction.guild_id, draft).start(interaction)

    @app_commands.command(description="Change any single Exorcist setting for this server")
    @app_commands.guild_only()
    async def settings(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        await SettingsPanel(self.config, interaction.guild_id).start(interaction)

    @app_commands.command(description="Show Exorcist's current settings here")
    @app_commands.guild_only()
    async def status(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)

        c = self.config.guild(interaction.guild_id)
        dot, state = (HIT, "Watching") if c["enabled"] else (NONE, "Paused")
        e = card("Status", f"{dot}  **{state}**  ·  {c['action_mode'].capitalize()} mode",
                 color=PASS if c["enabled"] else VIOLET)

        e.add_field(name="Detection",
                    value=f"Methods  {methods_text(c) or 'None'}\nImage match  {distance_label(c['hash_distance'])}",
                    inline=False)

        where = f"Watching  {channels_text(c)}\nLog  {channel_mention(c['log_channel'])}"
        if "honeypot" in c["methods"]:
            where += f"\nHoneypot  {channel_mention(c['trap_channel'])}"
        if c["test_channel"]:
            where += f"\nTest  {channel_mention(c['test_channel'])}"
        e.add_field(name="Channels", value=where, inline=False)

        punish = ", ".join(PUNISH[p] for p in c["punishments"]) or "Log only"
        if "timeout" in c["punishments"]:
            punish += f" ({pretty_minutes(c['timeout_minutes'])})"
        e.add_field(name="On a catch", value=f"{punish}\nSelf unmute  {'On' if c['self_unmute'] else 'Off'}", inline=False)

        learn = "training" if c["learn"] else "using existing"
        e.add_field(name="Scam data",
                    value=f"Seed {len(self.bot.detector.seed_hashes)}  ·  pool {len(self.config.learned_hashes)}  ·  {learn}",
                    inline=False)
        e.add_field(name="Access", value=self._access_text(c), inline=False)
        await interaction.response.send_message(embed=e, ephemeral=True)

    @app_commands.command(description="Turn Exorcist on or off here")
    @app_commands.guild_only()
    async def toggle(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        c = self.config.guild(interaction.guild_id)
        if not c["enabled"] and c["log_channel"] is None:
            return await interaction.response.send_message("Pick a log channel first with `/setup`, it won't act without one.", ephemeral=True)
        c["enabled"] = not c["enabled"]
        self.config.set_guild(interaction.guild_id, c)
        state = "on" if c["enabled"] else "off"
        await interaction.response.send_message(f"Exorcist is now **{state}** {SPARK}", ephemeral=True)

    @app_commands.command(description="Post the do not post warning in your honeypot channel")
    @app_commands.guild_only()
    async def honeypot(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        c = self.config.guild(interaction.guild_id)
        if "honeypot" not in c["methods"] or not c["trap_channel"]:
            return await interaction.response.send_message(
                "There's no honeypot set up yet. Turn on the honeypot method and pick a channel in `/setup`.",
                ephemeral=True,
            )
        channel = interaction.guild.get_channel(c["trap_channel"])
        if channel is None:
            return await interaction.response.send_message(
                "I can't find your honeypot channel anymore, pick a new one in `/settings`.", ephemeral=True)
        try:
            await channel.send(embed=logs.trap_warning())
        except discord.Forbidden:
            return await interaction.response.send_message(
                "I can't post in that channel, check my permissions there.", ephemeral=True)
        await interaction.response.send_message(f"Posted the warning in {channel.mention}.", ephemeral=True)

    access = app_commands.Group(name="access", description="Manage who can configure Exorcist", guild_only=True)

    @access.command(name="add", description="Let a user or role configure Exorcist")
    @app_commands.describe(user="Person to allow", role="Role to allow")
    async def access_add(self, interaction, user: discord.Member = None, role: discord.Role = None):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        if not user and not role:
            return await interaction.response.send_message("Pick a user or a role to add.", ephemeral=True)

        c = self.config.guild(interaction.guild_id)
        if user and user.id not in c["access"]["users"]:
            c["access"]["users"].append(user.id)
        if role and role.id not in c["access"]["roles"]:
            c["access"]["roles"].append(role.id)
        self.config.set_guild(interaction.guild_id, c)

        target = user.mention if user else role.mention
        await interaction.response.send_message(f"Added {target} to the access list.", ephemeral=True)

    @access.command(name="remove", description="Take a user or role off the access list")
    @app_commands.describe(user="Person to remove", role="Role to remove")
    async def access_remove(self, interaction, user: discord.Member = None, role: discord.Role = None):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        if not user and not role:
            return await interaction.response.send_message("Pick a user or a role to remove.", ephemeral=True)

        c = self.config.guild(interaction.guild_id)
        if user and user.id in c["access"]["users"]:
            c["access"]["users"].remove(user.id)
        if role and role.id in c["access"]["roles"]:
            c["access"]["roles"].remove(role.id)
        self.config.set_guild(interaction.guild_id, c)

        target = user.mention if user else role.mention
        await interaction.response.send_message(f"Removed {target} from the access list.", ephemeral=True)

    @access.command(name="list", description="See who can configure Exorcist")
    async def access_list(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        c = self.config.guild(interaction.guild_id)
        e = card("Access list", "Server admins always have access on top of these.")
        e.add_field(name="Allowed", value=self._access_text(c), inline=False)
        await interaction.response.send_message(embed=e, ephemeral=True)

    def _access_text(self, c):
        users = [f"<@{u}>" for u in c["access"]["users"]]
        roles = [f"<@&{r}>" for r in c["access"]["roles"]]
        return " ".join(users + roles) or "Just admins for now"

    data = app_commands.Group(name="data", description="Manage the shared scam data", guild_only=True)

    @data.command(name="show", description="See how much scam data Exorcist has")
    async def data_show(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        c = self.config.guild(interaction.guild_id)
        e = card("Scam data")
        e.add_field(name="Pretrained seed", value=str(len(self.bot.detector.seed_hashes)), inline=True)
        e.add_field(name="Shared pool", value=str(len(self.config.learned_hashes)), inline=True)
        e.add_field(name="This server", value="Training the pool" if c["learn"] else "Using existing data only", inline=False)
        await interaction.response.send_message(embed=e, ephemeral=True)

    @data.command(name="train", description="Toggle feeding this server's catches into the shared pool")
    async def data_train(self, interaction):
        if not self._allowed(interaction):
            return await interaction.response.send_message(DENIED, ephemeral=True)
        c = self.config.guild(interaction.guild_id)
        c["learn"] = not c["learn"]
        self.config.set_guild(interaction.guild_id, c)
        state = "training the shared pool" if c["learn"] else "using existing data only"
        await interaction.response.send_message(f"This server is now {state} {SPARK}", ephemeral=True)

    @data.command(name="wipe", description="Bot owner only, clears the shared learned pool")
    async def data_wipe(self, interaction):
        if not await self.bot.is_owner(interaction.user):
            return await interaction.response.send_message("Only the bot owner can wipe the shared pool.", ephemeral=True)
        count = len(self.config.learned_hashes)
        if not count:
            return await interaction.response.send_message("The pool is already empty. The pretrained seed isn't touched by this.", ephemeral=True)
        e = card(
            "Wipe the shared pool?",
            f"This clears {count} learned hash{plural(count)} for every server. The pretrained seed stays "
            "put, and this can't be undone.",
            color=WARN,
        )
        await interaction.response.send_message(embed=e, view=WipeConfirm(self.config), ephemeral=True)


def plural(count):
    return "es" if count != 1 else ""


class WipeConfirm(discord.ui.View):
    def __init__(self, config):
        super().__init__(timeout=60)
        self.config = config

    @discord.ui.button(label="Wipe it", style=discord.ButtonStyle.danger, emoji="\N{WASTEBASKET}️")
    async def wipe(self, interaction, button):
        count = self.config.wipe_learned()
        await interaction.response.edit_message(
            embed=card("Done", f"Cleared {count} hash{plural(count)} from the pool. Seed untouched.", color=PASS),
            view=None,
        )
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction, button):
        await interaction.response.edit_message(embed=card("Cancelled", "Left the pool alone."), view=None)
        self.stop()


async def setup(bot):
    await bot.add_cog(Setup(bot))
