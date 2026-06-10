import discord

from . import logs
from .actions import pretty_minutes
from .theme import BULLET, PASS, SPARK, VIOLET, WARN, card, progress

METHOD_LABELS = {
    "behavior": "Behavior",
    "imagehash": "Image match",
    "keyword": "Keywords",
    "honeypot": "Honeypot",
}
METHODS = {
    "behavior": "Mass posting and everyone pings",
    "imagehash": "Known scam pictures",
    "keyword": "Text, and the text inside images",
    "honeypot": "Anyone who posts in a trap channel",
}
MODES = {
    "auto": "Act right away, delete and punish on the spot",
    "review": "Review first, a mod confirms before anything happens",
}
PUNISH = {
    "timeout": "Timeout",
    "kick": "Kick",
    "ban": "Ban",
    "dm": "DM them to resecure",
}
LEARN = {
    "use": "Use the existing data only, recommended",
    "train": "Also feed this server's catches into the shared pool",
}
TIMEOUTS = [("10 minutes", 10), ("30 minutes", 30), ("1 hour", 60),
            ("6 hours", 360), ("1 day", 1440), ("1 week", 10080)]
DISTANCES = [
    ("Strict", 6, "Near identical images only"),
    ("Balanced", 10, "Small edits and recompression"),
    ("Loose", 14, "Catches lookalikes and variants"),
    ("Very loose", 18, "Catches a lot, expect some false hits"),
]
THRESHOLDS = [
    ("Lenient", 1.0, "Needs a strong signal, fewest false hits"),
    ("Balanced", 0.8, "The default"),
    ("Strict", 0.6, "Acts on weaker, stacked signals"),
]

# wizard step number -> the setting that step edits
STEP_FIELD = {
    1: "channels", 2: "methods", 3: "log_channel", 4: "action_mode", 5: "punishments",
    6: "timeout_minutes", 7: "self_unmute", 8: "trap_channel", 9: "learn",
}

# arrows and marks for the buttons
BACK, NEXT, SAVE, CANCEL = "◀️", "▶️", "✅", "✖️"


class SetupWizard(discord.ui.View):
    """First run walkthrough. Nothing is written until the last step saves."""

    def __init__(self, config, guild_id, draft):
        super().__init__(timeout=840)  # under the 15 min interaction token; it asks you to go make channels
        self.config = config
        self.guild_id = guild_id
        self.draft = draft
        self.step = 0
        self._origin = None
        self.pages = [self._welcome, self._channels, self._methods, self._log, self._mode,
                      self._punish, self._timeout, self._self_unmute, self._trap, self._learn,
                      self._summary]

    async def start(self, interaction):
        self._origin = interaction
        self._render()
        await interaction.response.send_message(embed=self.pages[self.step](), view=self, ephemeral=True)

    async def on_timeout(self):
        if self._origin is None:
            return
        try:
            await self._origin.edit_original_response(
                embed=card("Setup timed out", "Nothing was saved. Run `/setup` to start again.", kind="Setup"),
                view=None,
            )
        except discord.HTTPException:
            pass

    async def refresh(self, interaction):
        self._render()
        await interaction.response.edit_message(embed=self.pages[self.step](), view=self)

    def _render(self):
        self.clear_items()
        field = STEP_FIELD.get(self.step)
        if field:
            build_editor(self, field)
        self._add_nav()

    # nav
    def _add_nav(self):
        if self.step > 0:
            self.add_item(_NavButton("Back", discord.ButtonStyle.secondary, self._back, emoji=BACK))
        if self.step < len(self.pages) - 1:
            self.add_item(_NavButton("Next", discord.ButtonStyle.primary, self._next, emoji=NEXT))
        else:
            self.add_item(_NavButton("Save", discord.ButtonStyle.success, self._save, emoji=SAVE))
        self.add_item(_NavButton("Cancel", discord.ButtonStyle.danger, self._cancel, emoji=CANCEL))

    async def _next(self, interaction):
        self.step += 1
        await self.refresh(interaction)

    async def _back(self, interaction):
        self.step -= 1
        await self.refresh(interaction)

    async def _cancel(self, interaction):
        self.clear_items()
        await interaction.response.edit_message(
            embed=card("Cancelled", "Nothing saved. Run `/setup` again whenever.", kind="Setup"),
            view=None,
        )
        self.stop()

    async def _save(self, interaction):
        # don't let setup finish in a state that silently does nothing (no log channel, no
        # channels picked, honeypot method with no trap channel) and then claim it's watching
        problems = validate_setup(self.draft)
        if problems:
            e = self._summary()
            e.color = WARN
            e.add_field(name="Fix these before saving",
                        value="\n".join(f"{BULLET} {p}" for p in problems), inline=False)
            await interaction.response.edit_message(embed=e, view=self)
            return
        # re-read so anything changed while the wizard was open (an /access add, say) survives
        saved = self.config.guild(self.guild_id)
        old_trap = saved.get("trap_channel")
        for key in STEP_FIELD.values():
            saved[key] = self.draft[key]
        saved["enabled"] = True
        self.config.set_guild(self.guild_id, saved)

        await post_trap_warning(interaction, saved, old_trap)
        self.clear_items()
        done = card(f"All set {SPARK}", "Exorcist is watching now. Change anything later with `/settings`.", color=PASS, kind="Setup")
        await interaction.response.edit_message(embed=done, view=None)
        self.stop()

    # step cards
    def _frame(self, title, body, color=VIOLET):
        bar = progress(self.step + 1, len(self.pages))
        return card(title, f"{bar}\n\n{body}", color=color, kind="Setup")

    def _welcome(self):
        return self._frame(
            "Let's set it up",
            "I'll walk you through it, takes about a minute. Use the buttons to move through, "
            "nothing saves until the last step.",
        )

    def _channels(self):
        e = self._frame("Channels", "Pick the channels to watch, or watch the whole server.")
        e.add_field(name="Watching", value=channels_text(self.draft))
        return e

    def _methods(self):
        e = self._frame("Methods", "Choose how Exorcist looks for scams.")
        e.add_field(name="On", value=methods_text(self.draft) or "None yet")
        return e

    def _log(self):
        e = self._frame("Log channel", "Where the catches get posted, with all the details.")
        e.add_field(name="Logging to", value=channel_mention(self.draft["log_channel"]))
        return e

    def _mode(self):
        e = self._frame("Action mode", "Act on its own, or wait for a mod to confirm.")
        e.add_field(name="Mode", value=MODES[self.draft["action_mode"]])
        return e

    def _punish(self):
        e = self._frame("Punishment", "The scam message is always deleted. This is what happens to the user on top.")
        picks = self.draft["punishments"]
        e.add_field(name="Applying", value=", ".join(PUNISH[p] for p in picks) or "Log only, nothing to the user")
        return e

    def _timeout(self):
        e = self._frame("Timeout length", "Only matters if timeout is one of your punishments.")
        e.add_field(name="Length", value=pretty_minutes(self.draft["timeout_minutes"]))
        return e

    def _self_unmute(self):
        e = self._frame(
            "Self unmute",
            "Let someone who got timed out lift it themselves once they secure their account, with a "
            "button in the DM Exorcist sends them. Only does anything if timeout and DM are both on.",
        )
        e.add_field(name="Self unmute", value="On" if self.draft["self_unmute"] else "Off")
        return e

    def _trap(self):
        e = self._frame(
            "Honeypot channel",
            "Make an empty channel members have no reason to use, then pick it here. Only matters "
            "if honeypot is one of your methods.\n\n"
            "Anyone who posts there gets caught right away and their recent messages cleaned up. "
            "Exorcist drops a warning in it so people know not to.",
        )
        e.add_field(name="Trap channel", value=channel_mention(self.draft["trap_channel"]))
        return e

    def _learn(self):
        e = self._frame(
            "Scam data",
            "Everyone uses the shipped scam images plus the shared pool the bot builds over time. "
            "You can also have this server feed its own catches into that pool. Most servers should "
            "just use the existing data so one bad catch doesn't spread.",
        )
        e.add_field(name="This server", value=LEARN["train" if self.draft["learn"] else "use"])
        return e

    def _summary(self):
        e = self._frame("Review", "Give it a look, then save.", color=PASS)
        fill_summary(e, self.draft)
        return e


class SettingsPanel(discord.ui.View):
    """Change one setting at a time after setup. Edits save the moment you make them."""

    FIELDS = [
        ("channels", "Channels to watch"),
        ("methods", "Detection methods"),
        ("hash_distance", "Image match strictness"),
        ("threshold", "Detection threshold"),
        ("log_channel", "Log channel"),
        ("action_mode", "Action mode"),
        ("exempt_mods", "Exempt mods"),
        ("punishments", "Punishments"),
        ("timeout_minutes", "Timeout length"),
        ("self_unmute", "Self unmute"),
        ("trap_channel", "Honeypot channel"),
        ("test_channel", "Test channel"),
        ("learn", "Scam data mode"),
    ]

    def __init__(self, config, guild_id):
        super().__init__(timeout=840)
        self.config = config
        self.guild_id = guild_id
        self.draft = config.guild(guild_id)
        self.field = None
        self._origin = None

    async def start(self, interaction):
        self._origin = interaction
        self._render()
        await interaction.response.send_message(embed=self._embed(), view=self, ephemeral=True)

    async def on_timeout(self):
        if self._origin is None:
            return
        try:
            await self._origin.edit_original_response(
                embed=card("Settings timed out", "Run `/settings` again to make more changes.", kind="Settings"),
                view=None,
            )
        except discord.HTTPException:
            pass

    async def _navigate(self, interaction):
        self._render()
        await interaction.response.edit_message(embed=self._embed(), view=self)

    async def refresh(self, interaction):
        # re-read and write back only the field being edited, so a change another mod made
        # (a different panel, /toggle, /access add) isn't reverted by this panel's stale snapshot
        if self.field is not None:
            saved = self.config.guild(self.guild_id)
            saved[self.field] = self.draft[self.field]
            self.config.set_guild(self.guild_id, saved)
            self.draft = saved
        if self.field == "trap_channel":
            await post_trap_warning(interaction, self.draft, None)
        await self._navigate(interaction)

    def _render(self):
        self.clear_items()
        if self.field is None:
            self.add_item(_FieldPick(self))
        else:
            build_editor(self, self.field)
            self.add_item(_NavButton("Back", discord.ButtonStyle.secondary, self._back, row=4, emoji=BACK))

    async def _back(self, interaction):
        self.field = None
        await self._navigate(interaction)

    def _embed(self):
        if self.field is None:
            body = "Pick a setting to change. Edits save the moment you make them."
        else:
            body = f"Editing **{dict(self.FIELDS)[self.field]}**. Hit back when you're done."
        e = card("Settings", body, kind="Settings")
        fill_summary(e, self.draft)
        return e


def build_editor(host, field):
    """Adds the right component(s) for one setting onto a view. Shared by the wizard and
    the settings panel, both of which expose .draft and an async .refresh."""
    d = host.draft
    if field == "channels":
        host.add_item(_ChannelPick(host))
        host.add_item(_AllChannelsButton(host))
    elif field == "methods":
        opts = [discord.SelectOption(label=METHOD_LABELS[k], description=v, value=k, default=k in d["methods"]) for k, v in METHODS.items()]
        host.add_item(_MultiPick(host, "methods", "Which methods to use", opts, 1))
    elif field == "log_channel":
        host.add_item(_ChannelKeyPick(host, "log_channel", "Pick a log channel", [discord.ChannelType.text, discord.ChannelType.news]))
    elif field == "action_mode":
        opts = [discord.SelectOption(label=k.capitalize(), description=v, value=k, default=k == d["action_mode"]) for k, v in MODES.items()]
        host.add_item(_SinglePick(host, "action_mode", "What happens on a catch", opts))
    elif field == "punishments":
        opts = [discord.SelectOption(label=v, value=k, default=k in d["punishments"]) for k, v in PUNISH.items()]
        host.add_item(_MultiPick(host, "punishments", "Punishments to apply", opts, 0))
    elif field == "timeout_minutes":
        opts = [discord.SelectOption(label=l, value=str(m), default=m == d["timeout_minutes"]) for l, m in TIMEOUTS]
        host.add_item(_IntPick(host, "timeout_minutes", "Timeout length", opts))
    elif field == "hash_distance":
        opts = [discord.SelectOption(label=l, description=desc, value=str(n), default=n == d["hash_distance"]) for l, n, desc in DISTANCES]
        host.add_item(_IntPick(host, "hash_distance", "Image match strictness", opts))
    elif field == "threshold":
        opts = [discord.SelectOption(label=l, description=desc, value=str(v), default=v == d["threshold"]) for l, v, desc in THRESHOLDS]
        host.add_item(_FloatPick(host, "threshold", "Detection threshold", opts))
    elif field == "exempt_mods":
        host.add_item(_TogglePick(host, "exempt_mods", "Skip messages from mods", d["exempt_mods"]))
    elif field == "self_unmute":
        host.add_item(_TogglePick(host, "self_unmute", "Let timed out users unmute themselves", d["self_unmute"]))
    elif field == "trap_channel":
        host.add_item(_ChannelKeyPick(host, "trap_channel", "Pick the trap channel", [discord.ChannelType.text]))
    elif field == "test_channel":
        host.add_item(_ChannelKeyPick(host, "test_channel", "Pick the test channel", [discord.ChannelType.text]))
    elif field == "learn":
        cur = "train" if d["learn"] else "use"
        opts = [discord.SelectOption(label=k.capitalize(), description=v, value=k, default=k == cur) for k, v in LEARN.items()]
        host.add_item(_LearnPick(host, opts))


async def post_trap_warning(interaction, conf, old_trap):
    # only drop the warning when the trap channel is newly set, so it doesn't get spammed
    trap = conf["trap_channel"]
    if "honeypot" not in conf["methods"] or not trap or trap == old_trap:
        return
    channel = interaction.guild.get_channel(trap)
    if channel:
        try:
            await channel.send(embed=logs.trap_warning())
        except discord.HTTPException:
            pass


def fill_summary(e, d):
    methods = methods_text(d) or "None"
    detection = (
        f"Methods  {methods}\n"
        f"Image match  {distance_label(d['hash_distance'])}\n"
        f"Threshold  {threshold_label(d['threshold'])}\n"
        f"Mode  {d['action_mode'].capitalize()}"
    )
    e.add_field(name="Detection", value=detection, inline=False)

    where = f"Watching  {channels_text(d)}\nLog  {channel_mention(d['log_channel'])}"
    if "honeypot" in d["methods"]:
        where += f"\nHoneypot  {channel_mention(d['trap_channel'])}"
    if d["test_channel"]:
        where += f"\nTest  {channel_mention(d['test_channel'])}"
    e.add_field(name="Channels", value=where, inline=False)

    punish = ", ".join(PUNISH[p] for p in d["punishments"]) or "Log only"
    if "timeout" in d["punishments"]:
        punish += f" ({pretty_minutes(d['timeout_minutes'])})"
    e.add_field(name="On a catch", value=f"{punish}\nSelf unmute  {'On' if d['self_unmute'] else 'Off'}", inline=False)

    e.add_field(name="Scam data", value="Training the pool" if d["learn"] else "Using existing data", inline=False)


def methods_text(d):
    return ", ".join(METHOD_LABELS[m] for m in d["methods"])


def distance_label(n):
    for label, val, _ in DISTANCES:
        if val == n:
            return label
    return f"Custom ({n})"


def threshold_label(n):
    for label, val, _ in THRESHOLDS:
        if val == n:
            return label
    return f"Custom ({n:.2f})"


def validate_setup(d):
    problems = []
    if not d["methods"]:
        problems.append("Pick at least one detection method.")
    if d["log_channel"] is None:
        problems.append("Pick a log channel — Exorcist won't act without one.")
    if d["channels"] != "all" and not d["channels"]:
        problems.append("Pick at least one channel to watch, or choose every channel.")
    if "honeypot" in d["methods"] and not d["trap_channel"]:
        problems.append("You turned on the honeypot method but didn't pick a trap channel.")
    return problems


def channels_text(d):
    chans = d["channels"]
    if chans == "all":
        return "Every channel"
    return " ".join(f"<#{c}>" for c in chans) if chans else "None picked yet"


def channel_mention(cid):
    return f"<#{cid}>" if cid else "Not set yet"


class _NavButton(discord.ui.Button):
    def __init__(self, label, style, handler, row=4, emoji=None):
        super().__init__(label=label, style=style, row=row, emoji=emoji)
        self._handler = handler

    async def callback(self, interaction):
        await self._handler(interaction)


class _AllChannelsButton(discord.ui.Button):
    def __init__(self, host):
        super().__init__(label="Watch every channel", style=discord.ButtonStyle.secondary,
                         row=1, emoji="\N{GLOBE WITH MERIDIANS}")
        self.host = host

    async def callback(self, interaction):
        self.host.draft["channels"] = "all"
        await self.host.refresh(interaction)


class _ChannelPick(discord.ui.ChannelSelect):
    def __init__(self, host):
        super().__init__(channel_types=[discord.ChannelType.text, discord.ChannelType.news],
                         min_values=0, max_values=25, placeholder="Pick channels", row=0)
        self.host = host

    async def callback(self, interaction):
        self.host.draft["channels"] = [c.id for c in self.values]
        await self.host.refresh(interaction)


class _ChannelKeyPick(discord.ui.ChannelSelect):
    def __init__(self, host, key, placeholder, types):
        super().__init__(channel_types=types, min_values=1, max_values=1, placeholder=placeholder, row=0)
        self.host = host
        self.key = key

    async def callback(self, interaction):
        self.host.draft[self.key] = self.values[0].id
        await self.host.refresh(interaction)


class _MultiPick(discord.ui.Select):
    def __init__(self, host, key, placeholder, options, min_values):
        super().__init__(placeholder=placeholder, options=options, min_values=min_values, max_values=len(options), row=0)
        self.host = host
        self.key = key

    async def callback(self, interaction):
        self.host.draft[self.key] = list(self.values)
        await self.host.refresh(interaction)


class _SinglePick(discord.ui.Select):
    def __init__(self, host, key, placeholder, options):
        super().__init__(placeholder=placeholder, options=options, min_values=1, max_values=1, row=0)
        self.host = host
        self.key = key

    async def callback(self, interaction):
        self.host.draft[self.key] = self.values[0]
        await self.host.refresh(interaction)


class _IntPick(discord.ui.Select):
    def __init__(self, host, key, placeholder, options):
        super().__init__(placeholder=placeholder, options=options, min_values=1, max_values=1, row=0)
        self.host = host
        self.key = key

    async def callback(self, interaction):
        self.host.draft[self.key] = int(self.values[0])
        await self.host.refresh(interaction)


class _FloatPick(discord.ui.Select):
    def __init__(self, host, key, placeholder, options):
        super().__init__(placeholder=placeholder, options=options, min_values=1, max_values=1, row=0)
        self.host = host
        self.key = key

    async def callback(self, interaction):
        self.host.draft[self.key] = float(self.values[0])
        await self.host.refresh(interaction)


class _LearnPick(discord.ui.Select):
    def __init__(self, host, options):
        super().__init__(placeholder="Scam data", options=options, min_values=1, max_values=1, row=0)
        self.host = host

    async def callback(self, interaction):
        self.host.draft["learn"] = self.values[0] == "train"
        await self.host.refresh(interaction)


class _TogglePick(discord.ui.Select):
    def __init__(self, host, key, placeholder, current):
        options = [discord.SelectOption(label="On", value="on", default=current),
                   discord.SelectOption(label="Off", value="off", default=not current)]
        super().__init__(placeholder=placeholder, options=options, min_values=1, max_values=1, row=0)
        self.host = host
        self.key = key

    async def callback(self, interaction):
        self.host.draft[self.key] = self.values[0] == "on"
        await self.host.refresh(interaction)


class _FieldPick(discord.ui.Select):
    def __init__(self, panel):
        options = [discord.SelectOption(label=label, value=key) for key, label in SettingsPanel.FIELDS]
        super().__init__(placeholder="What do you want to change", options=options, min_values=1, max_values=1, row=0)
        self.panel = panel

    async def callback(self, interaction):
        self.panel.field = self.values[0]
        await self.panel._navigate(interaction)
