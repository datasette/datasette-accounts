# Platform research (2026-07-21)

Three Opus research agents, doc-verified (every claim URL'd in the reports):
`plans/auth2/research/{github,discord,bluesky}.md`. Actionable outcome:
`plans/auth2/tickets/repo-05-hardening.md`.

## Verdicts

- **github: healthy.** Errors-as-200 gate, no-scope GET /user, numeric-id
  subject, token discard all verified correct; OAuth Apps (not GitHub Apps)
  remain right for sign-in. Gap: stale "no PKCE" premise (S256 now
  supported) + unwrapped raise_for_status.
- **discord: healthy.** Snowflake-id keying, identify scope, form-encoded
  exchange verified. Gaps: same raise_for_status; dangling 7-day grant
  (add best-effort revoke); prompt=none is best-effort (staff-confirmed).
- **bluesky: healthy, closely spec-aligned.** We do the authoritative
  sub→DID→PDS→issuer re-verification the official cookbook skips. DID
  keying makes PDS migration seamless. Gap: **SSRF guard missing** on
  DID-doc-derived URLs (the one LOW–MEDIUM item) + 3 LOW spec-tightenings
  (atproto-scope check, bidirectional handle verify, metadata validation).

## Decisions taken from research

- **PKCE for github/discord: deferred.** Confidential clients with
  core-signed state get marginal value (both reports agree); adopting would
  need a core State field or provider cookie. Revisit only for a
  public-client mode. (Bluesky already does PKCE — mandatory there.)
- Email from any provider stays **metadata, never a match key** (D6) — the
  ExternalIdentity.email/email_verified fields await the email scopes.

## Future-features shortlist (per platform, verified APIs)

github: org-gated signups (read:org), team→group mapping, verified-email
capture, allow_signup=false knob. discord: guild-gated signups (guilds),
role→group mapping (guilds.members.read), email scope. bluesky:
transition:email (shipped 2025-06), granular scopes (posting/RPC,
proposal 0011), confidential-client mode (private_key_jwt) for silent
re-sign-in, logout revocation — all unblocked by adding a DID-keyed token
store (v1 deliberately discards tokens).
