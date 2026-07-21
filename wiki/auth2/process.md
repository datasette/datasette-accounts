# How the loop runs

The operating procedure that produced the train so far — follow it when
continuing (especially in a fresh session).

## Dispatch pattern

- One Opus background agent per ticket, prompt structure: READ FIRST (ticket
  + decisions + current code) → REFERENCE (git show commands into the old
  branches — they're refs in this repo; `email` branch is in the worktree
  but readable via `git show email:path` from here) → SCOPE (with explicit
  EXCLUDEs naming the ticket that owns each excluded piece) → VERIFY
  commands → RETURN format (files+purpose, deviations+why, results).
- Agents NEVER commit. The main loop reviews, runs tests independently,
  commits, cuts the next branch, dispatches the next agent.
- Parallelize only across directories (core agent in this checkout; repo
  agents in siblings; research agents read-only). Never two agents in one
  checkout. Plugin suites read this checkout live via editable dep — don't
  run them while a core agent is mid-edit.

## Review discipline (the main loop's job, not delegated)

- Security-critical code gets a line-by-line read: finish_login paths,
  state signing/verification, gates/guards, anything minting sessions.
- Diff ported code against its reference (`git show ref:path > /tmp/...;
  diff`) — scaffold ports must be byte-identical outside docstrings.
- Interrogate every agent-reported deviation against the reference before
  accepting (three so far were reference-faithful; one — M3 link-intent
  ordering — was a real latent flaw worth hardening; see build-deltas.md).
- Rerun `uv run pytest -q`, `just check`, `just check-queries-fresh`
  yourself before committing. Screenshots: `git diff --stat docs/screenshots/`.

## Conventions

- Branches `auth2/NN-name`; commit messages explain the *why* and end with
  the Claude co-author + session footer.
- PR bodies: 1-line train context + stacked-on link + content summary +
  the standard footer. Draft until train review.
- Ticket statuses live in plans/auth2/README.md's table; wiki pages track
  live state. Update BOTH the followups.md checklist and index.md's
  one-paragraph state after every landing.
- Stale-PR-diff fix: push the base, then close/reopen the PR.
