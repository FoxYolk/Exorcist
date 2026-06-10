DENIED = (
    "You're not on the access list for Exorcist. "
    "If you run this server, use `/access add` to let yourself or your mods in."
)


def is_manager(member, guild_conf):
    """Admins always get in so the whitelist can be set up from scratch.
    After that it's whoever the server added with /access add."""
    perms = member.guild_permissions
    if perms.administrator or perms.manage_guild:
        return True

    access = guild_conf.get("access", {})
    if member.id in access.get("users", []):
        return True

    allowed_roles = set(access.get("roles", []))
    return any(role.id in allowed_roles for role in member.roles)
