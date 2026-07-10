"""Inspection subcommands: list filters/JSON and the admin-audit actor id."""

import json

from cli_util import make_admin, run


def test_list_json_and_filters(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db, "admin")
    run("create", "alice", "-y", "-i", db)
    data = json.loads(run("list", "--admins", "--json", "-i", db).output)
    assert [u["username"] for u in data["users"]] == ["admin"]


def test_audit_records_cli_actor(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db, "--actor", "cli:opsbot")
    data = json.loads(run("audit", "--json", "-i", db).output)
    assert data["audit"][0]["actor_id"] == "cli:opsbot"
    assert data["audit"][0]["operation"] == "create"


def test_audit_operation_filter(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    run("disable", "alice", "-y", "-i", db)

    data = json.loads(run("audit", "--operation", "disable", "--json", "-i", db).output)
    ops = {row["operation"] for row in data["audit"]}
    assert ops == {"disable"}

    data = json.loads(
        run(
            "audit",
            "--user",
            "alice",
            "--operation",
            "create",
            "--json",
            "-i",
            db,
        ).output
    )
    assert [row["operation"] for row in data["audit"]] == ["create"]
