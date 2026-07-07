"""datasette-user-profiles integration (M6).

We emit a stable actor id for every account so people appear in the profiles
directory / people-search without first visiting the edit page. Per decision
D13 we store no display_name/email ourselves, so we seed actor_id only; those
fields are owned and edited through datasette-user-profiles. The import is
guarded so this plugin works with user-profiles absent.
"""

from datasette import hookimpl

from . import db

try:
    from datasette_user_profiles.hookspecs import ProfileSeed

    HAVE_USER_PROFILES = True
except ImportError:  # user-profiles not installed
    HAVE_USER_PROFILES = False


@hookimpl
def datasette_user_profile_seeds(datasette):
    if not HAVE_USER_PROFILES:
        return None

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
