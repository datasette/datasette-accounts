# 06 — Brute-force protection (hard lockout)

## Policy

This policy applies to **any current-password verification for an account** —
both `POST /-/login/api/authenticate` and `POST /-/account/api/change-password`
([`05-self-service.md`](05-self-service.md)) share the same counter and lock, so
an attacker with a live session can't brute-force the current password outside
the lockout.

- Track consecutive failed verifications per account in `users.failed_attempts`
  (incremented atomically: `UPDATE ... SET failed_attempts = failed_attempts + 1`,
  lock decision derived from the post-update value).
- After **`lockout_threshold`** consecutive failures (default **5**), set
  `users.locked_until = now + lockout_minutes` (default **15** min).
- While `locked_until > now`, the authenticate endpoint refuses the login with **429**
  regardless of whether the password is correct, and records an audit row.
- A successful login resets `failed_attempts = 0` and clears `locked_until`.
- **Auto-unlock** when `locked_until` passes.
- **Manual unlock** by an admin (clears `locked_until` + `failed_attempts`) from the
  admin UI.
- All attempts (success and failure) are recorded in `login_audit` for visibility.

## Accepted tradeoff — login DoS

Lockout is **account-keyed**. An attacker who knows a username can lock that real
user out by deliberately submitting bad passwords (a denial-of-service against a
known account). This was chosen knowingly over softer alternatives.

Mitigations available later without a schema change:
- Also key the counter/lock on **IP + username** (lock the attacking source, not the
  victim account). Requires trustworthy client IPs — see the IP-trust rule in
  [`02-data-model.md`](02-data-model.md).
- Fall back to **soft throttle** (exponential delay / temporary 429) instead of a
  hard account lock.
- Exempt/relax lockout for admins, or add an allow-list of trusted IPs.

## Accepted tradeoff — CPU exhaustion

Account lockout does **not** mitigate CPU exhaustion. Every authenticate attempt
now pays exactly one PBKDF2 verify (including unknown usernames, via the dummy
hash — [`03-authentication.md`](03-authentication.md)), and hashing runs in a
thread executor: threads unblock the event loop but still burn CPU. An attacker
firing parallel login attempts can therefore saturate CPU regardless of response
code. A **global rate limit** on the authenticate endpoint is the mitigation;
it's out of scope for v1.

## Enumeration note

A locked account returns 429 while unknown/wrong-password returns 401, so lock state
is observable. Acceptable under the hard-lockout model; if enumeration hardening
matters, return a uniform 401 with the delay applied silently.

## Config knobs

`lockout_threshold` (int, default 5), `lockout_minutes` (int, default 15). Set to `0`
to disable lockout entirely (falls back to constant-time verify only).
