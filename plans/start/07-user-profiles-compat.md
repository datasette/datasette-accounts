# 07 — Compatibility with datasette-user-profiles

`datasette-user-profiles` (studied at `../datasette-user-profiles`, v0.1.0a9) is a
**directory layer**, not an auth plugin. It stores editable profile rows
(`datasette_user_profiles`: `actor_id`, `display_name`, `bio`, `email`, avatar) keyed
on `actor["id"]`. It has **no `username`**, **no `actor_from_request`**, and does not
enrich the live actor. Our job is to be the auth layer; its job is the directory.

## The contract we honor

1. **Emit a stable string actor `id`.** Our `users.id` (ULID) is the sole join key and
   equals the profiles `actor_id`. It never changes (username is the mutable part).

2. **Seed the directory via the hook, never write its tables.** Implement
   `datasette_user_profile_seeds` returning `ProfileSeed` objects:

   ```python
   from datasette_user_profiles.hookspecs import ProfileSeed

   @hookimpl
   def datasette_user_profile_seeds(datasette):
       async def inner():
           rows = await get_accounts_with_profile_fields(datasette)
           return [
               ProfileSeed(actor_id=r["id"], display_name=r["display_name"], email=r["email"])
               for r in rows
           ]
       return inner
   ```

   Seeding is **fill-missing / idempotent** (COALESCE on existing rows, INSERT OR
   IGNORE on photos), so running it every startup never clobbers a user's own edits.

3. **No `username` field in `ProfileSeed`.** Passing `username=` to the dataclass
   raises and skips that seed; a dict with `username` drops it with a warning. So we
   fold nothing extra in — we seed only `actor_id` + optional `display_name`/`email`.

4. **We store display_name/email nowhere in our own tables** (decision D9, Option 2):
   they are captured at account creation and passed straight to the seed. profiles is
   the single home for that data.

## Known consequence of Option 2 (accepted)

The seed hook runs **only at startup**. Accounts created at runtime through the admin
UI therefore do **not** appear in the profiles directory until the next Datasette
restart re-runs the seed, or until that user first visits the profiles self-edit page
(which lazily creates their row). Our own admin UI does not depend on profiles data,
so this is cosmetic for us; it only affects other consumers of the directory.

If this becomes a problem, the fix is additive: either write the profile row directly
at creation (accepting schema coupling to profiles) or ask upstream for a runtime
"upsert one seed" API.

## What we do NOT do

- We do **not** implement `actors_from_ids` (it's `firstresult=True`; grabbing it
  would lock out other identity sources — profiles deliberately avoids it too). If we
  later want profile data merged into resolved actors, we'd implement it ourselves and
  merge `resolve_profile_actors(datasette, ids)`, defaulting unknowns to `{"id": id}`.
- We do **not** duplicate or gate profiles' `profile_access` action; operators grant
  that separately (via config/acl) so users can reach the profile UI.

## No table collision

Both plugins use the internal DB; profiles' tables are `datasette_user_profiles` /
`datasette_user_profile_photos`. Our `users` / `sessions` / `login_audit` and our
`datasette-auth-basic-login.internal` migration namespace do not collide.
