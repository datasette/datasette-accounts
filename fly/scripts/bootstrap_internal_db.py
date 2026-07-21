"""Build a local internal.db ready to upload to the Fly volume.

Creates the first admin account and flips the runtime switches that a fresh
install ships in the safe-off position: each sample provider's enabled bit
and its signups policy. Uses the same async ``db.*`` functions the HTTP
routes and the ``datasette accounts`` CLI call — the CLI itself can't do the
provider steps here because ``enable-provider`` validates keys against the
provider registry, and the samples are ``--plugins-dir`` modules the CLI's
reconstructed Datasette never loads. We construct Datasette with
``plugins_dir=plugins/`` ourselves, which also lets the bluesky sample's
startup hook create its flow table.

Run from the project root (the venv has the datasette-accounts wheel):

    uv run python scripts/bootstrap_internal_db.py internal.db
"""

import argparse
import asyncio
import secrets
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", help="internal DB to create/update")
    parser.add_argument("--username", default="admin", help="admin username")
    parser.add_argument(
        "--password",
        help="admin password (default: generate a strong one and print it)",
    )
    parser.add_argument(
        "--providers",
        default="discord,github,bluesky",
        help="comma-separated provider keys to enable",
    )
    parser.add_argument(
        "--signups",
        choices=["off", "approval", "auto"],
        default="approval",
        help="signups policy for the enabled providers: off = only admin-linked "
        "identities may sign in; approval = new identities queue for admin "
        "approval; auto = new identities get active accounts immediately "
        "(default: approval)",
    )
    return parser.parse_args()


async def build(args):
    from datasette.app import Datasette
    from datasette_accounts import db
    from datasette_accounts.passwords import hash_password
    from datasette_accounts.providers import REGISTRY_ATTR

    ds = Datasette(internal=args.db_path, plugins_dir=str(ROOT / "plugins"))
    await ds.invoke_startup()  # migrations + the bluesky flow table
    internal = ds.get_internal_database()
    registry = getattr(ds, REGISTRY_ATTR, {})
    actor = "cli:bootstrap"

    if await db.count_enabled_admins(internal) == 0:
        password = args.password or secrets.token_urlsafe(16)
        await db.create_user(
            internal, actor, args.username, hash_password(password), True, False
        )
        print(f"created admin {args.username!r}")
        if not args.password:
            print(f"password (shown once, not stored anywhere else): {password}")
    else:
        print("an enabled admin already exists — skipping account creation")

    for key in [k.strip() for k in args.providers.split(",") if k.strip()]:
        if key not in registry:
            sys.exit(f"provider {key!r} not installed (registry: {sorted(registry)})")
        await db.set_provider_enabled(
            internal, actor, key, True, installed_keys=list(registry)
        )
        await db.set_provider_signups(internal, actor, key, args.signups)
        print(f"enabled provider {key} (signups={args.signups})")


def main():
    args = parse_args()
    asyncio.run(build(args))
    # Fold any WAL back into the main file so the single .db we upload is
    # complete and consistent on its own.
    conn = sqlite3.connect(args.db_path)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    print(f"wrote {args.db_path}")


if __name__ == "__main__":
    main()
