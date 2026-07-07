"""datasette-user-profiles integration (M6).

We emit a stable actor id for every account so people appear in the profiles
directory / people-search without first visiting the edit page. Per decision
D13 we store no display_name/email ourselves, so we seed actor_id only; those
fields are owned and edited through datasette-user-profiles (a hard dependency).
"""

from datasette import hookimpl
from datasette_user_profiles.hookspecs import ProfileSeed

from . import db


@hookimpl
def datasette_user_profile_seeds(datasette):
    async def inner():
        internal = datasette.get_internal_database()
        # Startup hook order is not guaranteed: if user-profiles seeds before
        # our migrations create the table, tolerate its absence (accounts get
        # seeded on the next startup — the fill-missing pass is idempotent).
        exists = await internal.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            [db.USERS],
        )
        if not exists.first():
            return []
        result = await internal.execute(f"SELECT id FROM {db.USERS}")
        return [ProfileSeed(actor_id=row[0]) for row in result.rows]

    return inner
