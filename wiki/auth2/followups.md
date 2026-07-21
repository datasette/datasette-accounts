# Open work, ordered

Update as items complete; move done items to the bottom with their commit.

## Now / next (blocking the train)

1. **core-06** — building (background agent). Then: review (frontend +
   page-data), commit, run `just shots` state check.
2. **First plugin-suite run** (github/discord/bluesky) — right after
   core-06 commits; record results in repos.md. Don't run mid-agent-edit.
3. **core-07** — demo package + provider-author docs; resolves the
   API-pressure lists (repos.md) into promote/bless/rework decisions.
   Dispatchable in parallel with the hardening agents (different dirs).
4. **repo-05 hardening batch** — per plans/auth2/tickets/repo-05-hardening.md;
   bluesky SSRF guard first; each repo re-tested.
5. **Push 05/06/07, open PRs #16–18** (bases: #15's branch, then chain).
6. **GHA pass**: `gh pr checks` on all seven; fix failures; rebase train
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
- core-01…05 committed (12020ce / 72f24b4 / 3011abf / 20065db / 9e0c63d)
- PRs #12–15 opened; #10/#11 closed w/ pointers; origin/main pushed
- Platform research ×3 → hardening ticket
