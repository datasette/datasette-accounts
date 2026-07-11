"""``datasette accounts providers / enable-provider / disable-provider /
set-signups`` + the registration alias, and the break-glass recovery.

Mirrors tests/test_cli_registration.py: a persistent internal DB on disk, the
CliRunner, and a real HTTP app rebuilt from the same file for end-to-end checks.
A test external provider is registered through pluggy so the registry the CLI
builds at startup (and the HTTP app) both see it.
"""

import asyncio
import getpass
import json
import types

import pytest
from datasette import hookimpl
from datasette.plugins import pm

from cli_util import make_admin, query, run

from datasette_accounts.providers import AuthProvider

JSON_HEADERS = {"content-type": "application/json"}


class ExternProvider(AuthProvider):
    key = "extern"
    label = "Extern IdP"
    start_path = "/-/extern-auth/start"


@pytest.fixture
def register_extern():
    """Register the test external provider through pluggy for the duration of a
    test; both the CLI's Datasette and the HTTP app pick it up at startup."""
    name = "test-extern-provider"
    mod = types.ModuleType(name)

    @hookimpl
    def datasette_accounts_auth_providers(datasette):
        return [ExternProvider()]

    mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
    pm.register(mod, name=name)
    try:
        yield
    finally:
        if pm.get_plugin(name) is not None:
            pm.unregister(name=name)


def http(db_path, method, path, body=None):
    """Drive the real HTTP app against the CLI's internal DB (same trick as
    base._open_internal), for end-to-end liveness checks."""
    from datasette.app import Datasette

    async def go():
        ds = Datasette(internal=db_path)
        await ds.invoke_startup()
        if method == "GET":
            return await ds.client.get(path)
        return await ds.client.post(
            path, content=json.dumps(body or {}), headers=JSON_HEADERS
        )

    return asyncio.run(go())


def can_log_in(db_path, username, password):
    r = http(
        db_path,
        "POST",
        "/-/login/api/authenticate",
        {"username": username, "password": password},
    )
    return r.status_code == 200


# --- providers (list) -------------------------------------------------------


def test_providers_list_default_state(tmp_path, register_extern):
    db = str(tmp_path / "a.db")
    make_admin(db)  # migrate the schema

    result = run("providers", "-i", db)
    assert result.exit_code == 0
    # Password is enabled by default; the external provider is disabled + off.
    assert "password" in result.output
    assert "extern" in result.output

    result = run("providers", "--json", "-i", db)
    providers = {p["key"]: p for p in json.loads(result.output)["providers"]}
    assert providers["password"]["enabled"] is True
    assert providers["password"]["signups"] == "off"
    assert providers["extern"]["enabled"] is False
    assert providers["extern"]["signups"] == "off"
    assert providers["extern"]["label"] == "Extern IdP"
    # Source is the provider class's top-level package.
    assert providers["password"]["source"] == "datasette_accounts"


# --- enable / disable round-trip --------------------------------------------


def test_enable_disable_provider_round_trip(tmp_path, register_extern):
    db = str(tmp_path / "a.db")
    make_admin(db)

    enabled = run("enable-provider", "extern", "-y", "-i", db)
    assert enabled.exit_code == 0
    assert "Enabled extern." in enabled.output
    assert json.loads(run("providers", "--json", "-i", db).output)
    providers = {
        p["key"]: p
        for p in json.loads(run("providers", "--json", "-i", db).output)["providers"]
    }
    assert providers["extern"]["enabled"] is True

    # Re-enabling is a no-op — no confirmation, no audit noise.
    again = run("enable-provider", "extern", "-i", db)
    assert "already enabled — no change." in again.output

    disabled = run("disable-provider", "extern", "-y", "-i", db)
    assert disabled.exit_code == 0
    assert "Disabled extern." in disabled.output

    # Audit: one enable-provider + one disable-provider, CLI-attributed, with
    # the provider in the detail. The no-op flip wrote nothing.
    audit = query(
        db,
        "SELECT operation, actor_id, detail FROM datasette_accounts_admin_audit "
        "WHERE operation IN ('enable-provider', 'disable-provider') ORDER BY id",
    )
    assert [a["operation"] for a in audit] == ["enable-provider", "disable-provider"]
    assert all(a["actor_id"] == f"cli:{getpass.getuser()}" for a in audit)
    assert json.loads(audit[0]["detail"]) == {"provider": "extern"}


def test_disable_last_provider_refused(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    # Only password is installed + enabled: disabling it is refused.
    result = run("disable-provider", "password", "-y", "-i", db)
    assert result.exit_code == 1
    assert "Cannot disable the last sign-in provider." in result.output


def test_unknown_provider_key_errors(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    for cmd in ("enable-provider", "disable-provider"):
        result = run(cmd, "ghost", "-y", "-i", db)
        assert result.exit_code == 1, cmd
        assert "no such provider: ghost" in result.output


# --- set-signups ------------------------------------------------------------


def test_set_signups_validation_and_round_trip(tmp_path, register_extern):
    db = str(tmp_path / "a.db")
    make_admin(db)

    # Bad mode rejected by click.Choice.
    bad = run("set-signups", "extern", "sometimes", "-y", "-i", db)
    assert bad.exit_code != 0

    ok = run("set-signups", "extern", "approval", "-y", "-i", db)
    assert ok.exit_code == 0
    assert "Set extern signups to approval." in ok.output
    providers = {
        p["key"]: p
        for p in json.loads(run("providers", "--json", "-i", db).output)["providers"]
    }
    assert providers["extern"]["signups"] == "approval"

    # No-op flip writes nothing.
    again = run("set-signups", "extern", "approval", "-i", db)
    assert "already approval — no change." in again.output

    audit = query(
        db,
        "SELECT detail FROM datasette_accounts_admin_audit "
        "WHERE operation = 'set-provider-signups'",
    )
    assert len(audit) == 1
    assert json.loads(audit[0]["detail"]) == {"provider": "extern", "mode": "approval"}


# --- registration alias -----------------------------------------------------


def test_registration_alias_points_at_set_signups(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    on = run("registration", "on", "-y", "-i", db)
    assert "Enabled self-registration." in on.output
    assert "accounts set-signups password approval" in on.output

    # It writes the same setting the new command would.
    providers = {
        p["key"]: p
        for p in json.loads(run("providers", "--json", "-i", db).output)["providers"]
    }
    assert providers["password"]["signups"] == "approval"


# --- break-glass recovery ---------------------------------------------------


def test_break_glass_enable_provider_recovers_password(tmp_path, register_extern):
    """Disable password (allowed because an external provider is enabled), watch
    password login go dead, then recover it with `enable-provider password` from
    the CLI — no web session used for the recovery step (decision D9)."""
    db = str(tmp_path / "a.db")
    make_admin(db)  # admin / adminpass123, password login works

    assert can_log_in(db, "admin", "adminpass123")

    # Enable the external provider so password is no longer the last one.
    run("enable-provider", "extern", "-y", "-i", db)

    # Disabling password is now allowed.
    off = run("disable-provider", "password", "-y", "-i", db)
    assert off.exit_code == 0
    assert "Disabled password." in off.output

    # Password login is dead: the canonical endpoint 404s.
    assert (
        http(
            db,
            "POST",
            "/-/login/api/authenticate",
            {"username": "admin", "password": "adminpass123"},
        ).status_code
        == 404
    )
    assert not can_log_in(db, "admin", "adminpass123")

    # Break-glass: restore password with only disk access, no web auth.
    recover = run("enable-provider", "password", "-y", "-i", db)
    assert recover.exit_code == 0
    assert "Enabled password." in recover.output

    # Password login works again.
    assert can_log_in(db, "admin", "adminpass123")
