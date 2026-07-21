# Open work, ordered

Update as items complete; move done items to the bottom with their commit.

## Now / next (blocking the train)

1. **core-07** — building (background agent): demo package +
   provider-author docs; resolves the API-pressure lists (repos.md) into
   promote/bless/rework decisions. Then review, commit, push, PR #18.
2. **GHA pass**: `gh pr checks` on all seven; fix failures; rebase train
   with `--update-refs`; force-push all branches together. (User asked for
   this explicitly once all drafts are in.)

## Then (phases 3–4)

7. **Email train** (auth2/email-01…06) — tickets ready; cut from train tip
   or main-post-merge. get_user_by_verified_email lands in email-03.
8. **repo-04 dev harness** — just dev sibling installs, authlib out of core
   dev deps, CLAUDE.md rewrite, fly harness repoint.
9. **ml-01 magic-link repo** — after email train (needs sender + lookup).

## Post-merge (not tickets)

PyPI alpha → flip path sources to pins → create GitHub repos (org/account
decision deferred, A2-D5) → enable CI → redeploy fly harness from main →
docs-site page for providers (old post-merge TODO) → delete email worktree
+ old branches once replaced (A2-D10).

## Future features (research-derived, unscheduled)

See research.md shortlist. Biggest architectural unlock: a DID-keyed token
store for bluesky (enables posting, silent re-sign-in, revocation).

## Done

- Plugin repos scaffolded + committed (38d90d8 / 5545c5c / c03466b)
- core-01…06 committed (12020ce / 72f24b4 / 3011abf / 20065db / 9e0c63d /
  b96b020); PRs #12–17 opened; #10/#11 closed w/ pointers; origin/main pushed
- First plugin-suite run: ALL GREEN vs core @ b96b020 (10/13/38)
- Platform research ×3 → repo-05 hardening COMPLETE: bluesky 711a057
  (SSRF guard, 70 tests), github 10f655e (13), discord 90566b4 (17)
