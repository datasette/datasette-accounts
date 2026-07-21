# auth2 wiki — living state of the rebuild

Local-only (excluded via `.git/info/exclude`, like `plans/` and `todos/`).
This is the **current-state record** for agentic loops: what exists, where,
why, and what's next. The *plan* lives in `plans/auth2/` (tickets +
decisions A2-D1…D10 — those don't change); this wiki tracks what actually
happened and gets **updated whenever state changes** (new commit, new PR,
rebase, review finding, agent dispatched/landed).

## Pages

- [train.md](train.md) — the core PR train: branch ⇄ PR ⇄ commit map,
  per-PR contents, review findings, test counts. **The page to read before
  touching any train branch or PR.**
- [repos.md](repos.md) — the sibling plugin repos (github/discord/bluesky):
  commits, port fidelity, test-run status, API-pressure lists.
- [build-deltas.md](build-deltas.md) — where the build deviated from the
  plan/reference and why (each verified during review). Read before
  assuming a ticket's text is literally what landed.
- [research.md](research.md) — the 2026-07-21 platform-research outcome +
  the hardening batch derived from it.
- [followups.md](followups.md) — open work, ordered; who/what is blocked
  on what.
- [process.md](process.md) — how the loop runs: agent dispatch pattern,
  review discipline, rebase/PR conventions. Follow it when continuing the
  train.

## One-paragraph state (update me)

*As of 2026-07-21 ~11:45:* core-01…05 committed on stacked branches
(auth2/01…05), PRs #12–#15 open as drafts (#12=core-01 … #15=core-04);
core-05 committed locally (`9e0c63d`), not yet pushed/PR'd. core-06
(frontend) building via background agent on `auth2/06-frontend`. Three
plugin repos scaffolded + committed, suites runnable once core-06 lands
(they import through core-05's surface). Research done → hardening ticket
`plans/auth2/tickets/repo-05-hardening.md`. Old PRs #10/#11 closed with
pointers. origin/main pushed to `a3965e5`. Pending: core-07, PRs #16–18,
GHA failure pass + train rebase (`--update-refs`), plugin green run,
hardening batch, email train (phase 3), magic-link repo (phase 4).
