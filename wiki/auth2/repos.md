# Sibling plugin repos

Local-only git repos (A2-D5 — nothing on GitHub until the core train is on
main). Each: packaged plugin, entry point `[project.entry-points.datasette]`,
editable uv path source on `../datasette-accounts`, CI workflow file present
but inert. Module code ported **byte-identical outside docstrings** from the
reference branches (diff-verified at review).

| Repo | Commit | Port source | Suite status |
|------|--------|-------------|--------------|
| ../datasette-accounts-github | `38d90d8` | bluesky-auth:samples/github-auth | **10 passed** (2026-07-21, vs core @ b96b020) |
| ../datasette-accounts-discord | `5545c5c` | bluesky-auth:samples/discord-auth | **13 passed** (same) |
| ../datasette-accounts-bluesky | `c03466b` | bluesky-auth:samples/bluesky-auth | **38 passed** (same; authlib pre-2.0 deprecation warning — watch on authlib bumps) |

**First green run done 2026-07-21** against the train @ core-06 — the
phase-2 integration check passed on the first attempt, incl. bluesky's
native entry-point `startup`. The editable dep reads this checkout live, so
never re-run suites while a train agent is mid-edit.

## API-pressure lists (imports beyond the public provider contract)

Tracked for the core-07 public-surface decision (promote vs blessed test
helper vs rework-test). Flagged inline in each repo's test docstring.

- github tests: `db` (several helpers + table consts), `STATE_COOKIE`,
  `get_registry`, `provider_source`, `COOKIE_NAME`
- discord tests: same, plus `SIGN_NAMESPACE`, `sessions.mint_token`/
  `token_sha256`, `passwords.hash_password`, `db.new_id`/`now_iso`/
  `create_session`
- bluesky tests: `db` helpers + consts, `STATE_COOKIE`, `get_registry`,
  `provider_source`, `COOKIE_NAME`
- All three provider **modules** import only the public contract
  (`AuthProvider`, `ExternalIdentity`, `finish_login`, `make_state`,
  `read_state`, `provider_gate`, `security` module) — that surface is
  load-bearing, keep it stable.

## Port adaptations (same shape in all three)

plugins_dir loading → installed-distribution discovery; `_unregister_sample`
fixture dropped; `_mock_httpx` targets the imported module object; discovery
test asserts `provider_source == "<package name>"`; dev-plugins-loader test
deleted (subject gone; bluesky native-startup covered by
`test_flow_table_exists_after_startup`). Bluesky: authlib is a runtime dep;
loader-relay hack not ported (entry-point startup fires natively).

## Pending

repo-04 (dev harness: just dev sibling installs, authlib out of core dev
deps, CLAUDE.md, fly harness repoint) — backlog, after core train.
repo-05 (hardening batch from research) — see
`plans/auth2/tickets/repo-05-hardening.md`; bluesky SSRF guard first.
Phase-2 exit: suites green + README walkthroughs accurate; then (post-merge)
PyPI alpha, flip path sources to pins, create GitHub repos, enable CI.
