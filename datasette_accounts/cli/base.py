"""Shared plumbing for the ``datasette accounts`` command package.

The ``accounts`` group and every cross-command helper live here; one module per
subcommand (``create.py``, ``delete.py``, …) imports what it needs and registers
itself on ``accounts``. See ``cli/__init__.py`` for the wiring.

The commands never touch the internal tables directly. Each reconstructs a
Datasette from ``-i/--internal`` (+ optional ``-m/--metadata``), runs the startup
hook to apply migrations, then calls the **same async ``db.*`` functions** the
HTTP routes call — inheriting their audit trail, last-admin guard, session
revocation, and config fidelity for free.

The one new concept is a synthetic actor id for audit attribution: HTTP
mutations pass ``request.actor["id"]``; the CLI has no actor, so it passes
``cli:$USER`` (overridable with ``--actor``).
"""

import asyncio
import getpass
import json as jsonlib
import os
import sys

import click

from .. import db, security
from ..passwords import (
    PasswordLengthError,
    check_password_length,
    generate_password,
)


# --------------------------------------------------------------------------
# Datasette reconstruction
# --------------------------------------------------------------------------


def _load_config(metadata):
    """Load a ``-m/--metadata`` file (YAML or JSON) into a config dict.

    Returns None when no path is given. datasette-accounts settings
    (``password_min_length`` etc.) are read via ``datasette.plugin_config``,
    which resolves from the ``config`` dict's ``plugins`` key — so we pass the
    file through as Datasette's ``config``.
    """
    if not metadata:
        return None
    try:
        with open(metadata) as fp:
            text = fp.read()
    except OSError as e:
        raise click.ClickException(f"Could not read {metadata}: {e}")
    try:
        if metadata.endswith((".yml", ".yaml")):
            import yaml

            return yaml.safe_load(text)
        return jsonlib.loads(text)
    except Exception as e:
        raise click.ClickException(f"Could not parse {metadata}: {e}")


def _is_ephemeral(internal):
    """True when the internal path looks like Datasette's throwaway temp file.

    Mirrors the ``startup`` hook's warning; the CLI turns it into a hard error
    since a mutating command whose writes vanish is almost always a mistake.
    """
    return os.path.basename(internal or "").startswith("datasette_temp_")


async def _open_internal(internal, metadata):
    """Rebuild a Datasette, apply migrations via the startup hook, and return
    ``(datasette, internal_db)``."""
    if _is_ephemeral(internal):
        raise click.ClickException(
            f"{internal!r} is an ephemeral internal database — its writes would "
            "be lost. Pass a persistent path to --internal."
        )
    # Imported lazily: importing Datasette at module load pulls in the full app
    # before this plugin's own submodules finish importing.
    from datasette.app import Datasette

    ds = Datasette(internal=internal, config=_load_config(metadata))
    await ds.invoke_startup()
    return ds, ds.get_internal_database()


def _actor_id(actor):
    """Audit actor id for a shell action: ``--actor`` verbatim, else
    ``cli:$USER``."""
    if actor:
        return actor
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    return f"cli:{user}"


def _run(coro):
    """Drive one async command body to completion on a fresh event loop."""
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# Shared option decorators
# --------------------------------------------------------------------------


def _db_options(f):
    """Attach the shared ``-i/-m/--actor`` options to a command."""
    f = click.option(
        "-i",
        "--internal",
        required=True,
        metavar="PATH",
        help="Path to the persistent internal database.",
    )(f)
    f = click.option(
        "-m",
        "--metadata",
        metavar="PATH",
        help="Path to a metadata/config file (for plugin settings).",
    )(f)
    f = click.option(
        "--actor",
        metavar="ID",
        help="Audit actor id for this action (default: cli:$USER).",
    )(f)
    return f


def _yes_option(f):
    """Attach ``-y/--yes`` (skip the confirmation prompt) to a mutating command."""
    return click.option(
        "-y",
        "--yes",
        is_flag=True,
        help="Skip the confirmation prompt (required for non-interactive use).",
    )(f)


def _interactive_option(f):
    """Attach ``-I/--interactive`` (prompt for any inputs not given) to a
    command."""
    return click.option(
        "-I",
        "--interactive",
        is_flag=True,
        help="Prompt for any options not supplied on the command line.",
    )(f)


def _confirm(summary, yes):
    """Gate a mutation on an "are you sure?" prompt unless ``--yes`` was passed.

    Uses ``click.confirm``, so a non-interactive caller (CI, an entrypoint
    script) must pass ``--yes`` — on EOF the default is to abort, which keeps an
    unattended run from mutating without an explicit go-ahead.
    """
    if yes:
        return
    click.confirm(summary, abort=True)


# --------------------------------------------------------------------------
# Users + passwords
# --------------------------------------------------------------------------


async def _require_user(internal, username):
    """Resolve a username to its user dict, or exit 1 ``no such user``."""
    user = await db.get_user_by_username(internal, username)
    if user is None:
        raise click.ClickException(f"no such user: {username}")
    return user


def _set_password_link(base_url, raw_token):
    """The one-time set-password link for ``invite`` / ``reset-link``.

    Path only unless ``--base-url`` supplies the site origin to prefix (the
    CLI can't know where the site is served). The raw token is urlsafe, so
    plain concatenation needs no encoding.
    """
    path = f"/-/set-password?token={raw_token}"
    if base_url:
        return base_url.rstrip("/") + path
    return path


def _base_url_option(f):
    """Attach ``--base-url`` (origin prefix for printed links) to a command."""
    return click.option(
        "--base-url",
        metavar="URL",
        help="Site origin to prefix the printed link (e.g. "
        "https://data.example.com). Without it only the path is printed — "
        "prefix your site's origin before sending it.",
    )(f)


def _read_password(password, password_stdin):
    """Resolve a caller-supplied password from ``--password`` / ``--password-stdin``.

    Returns the plaintext, or None when neither flag was given (caller then
    decides whether to generate). ``--password-stdin`` reads one line so the
    secret never lands in argv or shell history.
    """
    if password_stdin:
        if password is not None:
            raise click.ClickException(
                "Pass only one of --password / --password-stdin."
            )
        return sys.stdin.readline().rstrip("\n")
    return password


def _resolve_password(datasette, provided, generate):
    """CLI mirror of ``routes/api.py::_resolve_password``.

    Returns ``(plaintext, generated)``. With ``--generate`` (or no password at
    all) a strong random password is minted; an explicit one is length-checked
    against ``password_min_length`` (a violation is exit 1).
    """
    min_length = security.config(datasette, "password_min_length")
    if generate or not provided:
        return generate_password(min_length), True
    try:
        check_password_length(provided, min_length)
    except PasswordLengthError as e:
        raise click.ClickException(str(e))
    return provided, False


def _prompt_password(datasette):
    """Interactively choose a password: offer to generate one, else read a
    hidden (confirmed) entry, re-prompting until it satisfies the length rule.

    Returns ``(plaintext, generated)`` like ``_resolve_password``.
    """
    min_length = security.config(datasette, "password_min_length")
    if click.confirm("Generate a random password?", default=True):
        return generate_password(min_length), True
    while True:
        pw = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        try:
            check_password_length(pw, min_length)
            return pw, False
        except PasswordLengthError as e:
            click.echo(str(e))


def _resolve_password_interactive(datasette, provided, generate, interactive):
    """Resolve the password for create/reset: prompt interactively when
    ``--interactive`` is set and nothing was supplied, else fall back to the
    non-interactive ``_resolve_password`` rules."""
    if interactive and not generate and provided is None:
        return _prompt_password(datasette)
    return _resolve_password(datasette, provided, generate)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def _emit(data, as_json, human):
    """Print ``data`` as JSON when ``--json``, else call ``human()``."""
    if as_json:
        click.echo(jsonlib.dumps(data, indent=2))
    else:
        human()


def _table(rows, columns):
    """Render a list of dicts as a simple aligned text table."""
    if not rows:
        return "(none)"
    widths = {c: len(c) for c in columns}
    cells = []
    for r in rows:
        row = {c: ("" if r.get(c) is None else str(r.get(c))) for c in columns}
        cells.append(row)
        for c in columns:
            widths[c] = max(widths[c], len(row[c]))
    lines = ["  ".join(c.ljust(widths[c]) for c in columns)]
    lines.append("  ".join("-" * widths[c] for c in columns))
    for row in cells:
        lines.append("  ".join(row[c].ljust(widths[c]) for c in columns))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# The `accounts` group
# --------------------------------------------------------------------------


class AccountsGroup(click.Group):
    """Group whose ``--help`` lists commands in task-ordered sections rather
    than one alphabetical blob."""

    SECTIONS = (
        ("Provisioning", ("create", "invite", "bootstrap-admin")),
        (
            "Account lifecycle",
            (
                "list",
                "approve",
                "reject",
                "reset-password",
                "reset-link",
                "expire",
                "promote",
                "demote",
                "disable",
                "enable",
                "unlock",
                "logout",
                "delete",
            ),
        ),
        (
            "Sign-in providers",
            (
                "providers",
                "enable-provider",
                "disable-provider",
                "set-signups",
                "registration",
            ),
        ),
        (
            "Inspection & utility",
            ("audit", "login-attempts", "hash-password"),
        ),
    )

    def list_commands(self, ctx):
        # Section order first, then any command not placed in a section.
        ordered = [name for _, names in self.SECTIONS for name in names]
        return ordered + [c for c in self.commands if c not in ordered]

    def format_commands(self, ctx, formatter):
        for title, names in self.SECTIONS:
            rows = [
                (name, self.commands[name].get_short_help_str())
                for name in names
                if name in self.commands and not self.commands[name].hidden
            ]
            if rows:
                with formatter.section(title):
                    formatter.write_dl(rows)


@click.group(name="accounts", cls=AccountsGroup)
def accounts():
    """Manage datasette-accounts users from the shell."""


# --------------------------------------------------------------------------
# Command factories shared by the lifecycle subcommands
# --------------------------------------------------------------------------


def _set_admin_command(name, target_admin, help_text, summary):
    """Build a promote/demote command as an explicit is_admin state-setter."""

    @accounts.command(name=name)
    @click.argument("username")
    @click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
    @_yes_option
    @_db_options
    def cmd(username, as_json, yes, internal, metadata, actor):
        async def go():
            _, db_ = await _open_internal(internal, metadata)
            user = await _require_user(db_, username)
            if bool(user["is_admin"]) == target_admin:
                state = "already an admin" if target_admin else "already not an admin"
                _emit(
                    {"ok": True, "changed": False},
                    as_json,
                    lambda: click.echo(f"{username} is {state} — no change."),
                )
                return
            _confirm(summary(username), yes)
            # We read current state and it's the opposite, so a toggle lands on
            # the target value; toggle_admin runs the last-admin guard on demote.
            try:
                await db.toggle_admin(db_, _actor_id(actor), user["id"])
            except db.LastAdminError:
                raise click.ClickException("Cannot demote the last admin")
            _emit(
                {"ok": True, "changed": True, "is_admin": target_admin},
                as_json,
                lambda: click.echo(
                    f"{'Promoted' if target_admin else 'Demoted'} {username}."
                ),
            )

        _run(go())

    cmd.help = help_text
    return cmd


def _simple_mutation(name, fn_name, help_text, past, summary):
    """Build a thin lifecycle command wrapping a single ``db.<fn_name>`` call."""

    @accounts.command(name=name)
    @click.argument("username")
    @click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
    @_yes_option
    @_db_options
    def cmd(username, as_json, yes, internal, metadata, actor):
        async def go():
            _, db_ = await _open_internal(internal, metadata)
            user = await _require_user(db_, username)
            _confirm(summary(username), yes)
            fn = getattr(db, fn_name)
            try:
                await fn(db_, _actor_id(actor), user["id"])
            except db.LastAdminError:
                raise click.ClickException(f"Cannot {name} the last admin")
            _emit(
                {"ok": True},
                as_json,
                lambda: click.echo(f"{past} {username}."),
            )

        _run(go())

    cmd.help = help_text
    return cmd
