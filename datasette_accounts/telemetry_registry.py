"""Every span, attribute and metric datasette-accounts emits — the single
source of truth, built on Datasette's plugin telemetry kit.

``Attribute`` / ``SpanName`` / ``MetricName`` subclass ``str``, so an entry
here *is* the name handed to OpenTelemetry; ``tests/test_telemetry_registry.py``
drives a broad workload and checks emitted-vs-registered in both directions
(plus enum membership, instrument kind/unit, and a privacy walk) with the kit's
conformance helpers.

Privacy: nothing here names a person or a secret — no username, actor id,
email, IP, user-agent, session token or hash, state value, external subject,
``next`` URL or invite/reset token. Every attribute is a closed enum, a bool or
a count; the one open value, ``datasette_accounts.provider``, is bounded by the
provider plugins installed on the instance.
"""

from datasette.telemetry_registry import (
    COUNTER,
    DURATION_BUCKETS,
    ERROR_TYPE,
    HISTOGRAM,
    Attribute,
    MetricName,
    SpanName,
)

# --- Vocabularies ----------------------------------------------------------

ACTOR_OUTCOMES = (
    "no_cookie",
    "bad_signature",
    "no_session",
    "session_expired",
    "no_user",
    "disabled",
    "user_expired",
    "pending",
    "ok",
)
CALLERS = ("asgi_wrapper", "actor_from_request", "finish_login")
# The login_audit refusal reasons, verbatim (one vocabulary for the audit page
# and for telemetry; the success words `success` / `reauth` never label a
# refusal). tests/test_telemetry_registry.py asserts this equals the
# set of reason literals in the source.
AUDIT_REASONS = (
    "no_such_user",
    "disabled",
    "expired",
    "pending_approval",
    "no_password",
    "bad_password",
    "locked",
    "register",
    "bad_token",
    "provider_bad_subject",
    "provider_disabled",
    "provider_no_account",
    "provider_expired",
    "provider_pending",
    "provider_state_invalid",
)
# Telemetry-only: the register endpoint audits every refusal as the coarse
# `register` (it hides which cap tripped from the visitor) and doesn't audit
# its 400s at all. `capped` is both the per-IP and the pending-queue cap.
REGISTRATION_REASONS = ("closed", "capped", "invalid", "taken")
LOGIN_OUTCOMES = (
    "ok",
    "provisioned",
    "pending",
    "refused",
    "linked",
    "unlinked",
    "step_up",
    "error",
)
REGISTRATION_OUTCOMES = ("ok", "pending", "refused")
KDF_OPERATIONS = ("verify", "dummy", "hash")
GATES = ("ok", "disabled", "csrf", "method")
STATE_OUTCOMES = (
    "ok",
    "missing",
    "bad_signature",
    "not_dict",
    "mismatch",
    "wrong_provider",
    "expired",
)
TRIGGERS = ("startup", "login")
PURGE_TABLES = ("sessions", "password_tokens", "login_audit", "admin_audit")

# --- Attributes ------------------------------------------------------------

PROVIDER = Attribute(
    "datasette_accounts.provider",
    "The sign-in provider key (``password`` for the built-in provider). "
    "Bounded by the provider plugins installed on the instance.",
)
ACTOR_OUTCOME = Attribute(
    "datasette_accounts.outcome",
    "How session-cookie resolution ended: the first check that failed, or "
    "``ok`` when an actor was rebuilt.",
    values=ACTOR_OUTCOMES,
)
CALLER = Attribute(
    "datasette_accounts.caller",
    "Which code path resolved the actor: the forced-password-change "
    "``asgi_wrapper``, core's ``actor_from_request`` hook, or a link / "
    "step-up callback re-checking the live session (``finish_login``).",
    values=CALLERS,
)
LAST_SEEN_TOUCHED = Attribute(
    "datasette_accounts.last_seen_touched",
    "``True`` if the throttled ``last_seen_at`` update wrote this time. "
    "Present only when an actor was resolved.",
    optional=True,
)
LOGIN_OUTCOME = Attribute(
    "datasette_accounts.outcome",
    "How the sign-in ended: ``ok`` (session minted for an existing account), "
    "``provisioned`` (account auto-created and signed in), ``pending`` "
    "(account created awaiting approval), ``refused``, ``linked`` / "
    "``unlinked`` (an identity was attached to / removed from the signed-in "
    "account), ``step_up`` (a re-authentication was proven), or ``error`` "
    "(an exception escaped).",
    values=LOGIN_OUTCOMES,
)
REASON = Attribute(
    "datasette_accounts.reason",
    "Why a sign-in was refused — the same word written to the admin-only "
    "login audit log. Absent on success and on refusals with no audited "
    "reason.",
    optional=True,
    values=AUDIT_REASONS,
)
REGISTRATION_REASON = Attribute(
    "datasette_accounts.reason",
    "Why a registration was refused: ``closed`` (sign-ups off), ``capped`` "
    "(per-IP or pending-queue cap), ``invalid`` (bad username or password "
    "length), ``taken`` (username exists).",
    optional=True,
    values=REGISTRATION_REASONS,
)
IDENTITY = Attribute(
    "datasette_accounts.identity",
    "``local`` (an existing account id: password, invite or reset "
    "completion) or ``external`` (an identity proven by a sign-in provider).",
    values=("local", "external"),
)
INTENT = Attribute(
    "datasette_accounts.intent",
    "What the flow was for: ``login``, ``link`` (attach an identity to the "
    "signed-in account) or ``step-up`` (re-prove an existing one).",
    values=("login", "link", "step-up"),
)
SIGNUPS = Attribute(
    "datasette_accounts.signups",
    "The provider's sign-ups policy, present when an unmatched external "
    "identity consulted it.",
    optional=True,
    values=("auto", "approval", "off"),
)
RESPONSE_MODE = Attribute(
    "datasette_accounts.response_mode",
    "Whether the caller asked for a ``json`` or a ``redirect`` response.",
    values=("json", "redirect"),
)
VERIFY_OUTCOME = Attribute(
    "datasette_accounts.outcome",
    "``ok`` or ``refused``.",
    values=("ok", "refused"),
)
VERIFY_KDF = Attribute(
    "datasette_accounts.kdf",
    "Which PBKDF2 branch ran: ``verify`` against the account's hash, or "
    "``dummy`` (the constant-time decoy for an unusable account). Absent on "
    "a locked account, which refuses before hashing.",
    optional=True,
    values=("verify", "dummy"),
)
KDF_OPERATION = Attribute(
    "datasette_accounts.kdf.operation",
    "``verify``, ``dummy`` (decoy verify) or ``hash`` (new password).",
    values=KDF_OPERATIONS,
)
GATE = Attribute(
    "datasette_accounts.gate",
    "Which ``provider_gate`` check stopped the request — ``disabled`` (404), "
    "``csrf`` (403), ``method`` (405) — or ``ok`` when the handler ran.",
    values=GATES,
)
STATE = Attribute(
    "datasette_accounts.state",
    "Result of validating the signed provider ``state`` cookie: ``ok``, or "
    "the first check that failed. Set on the current span by ``read_state``.",
    optional=True,
    values=STATE_OUTCOMES,
)
TRIGGER = Attribute(
    "datasette_accounts.trigger",
    "What ran housekeeping: ``startup`` or a successful ``login``.",
    values=TRIGGERS,
)
PURGED_SESSIONS = Attribute(
    "datasette_accounts.purged.sessions", "Expired sessions deleted."
)
PURGED_PASSWORD_TOKENS = Attribute(
    "datasette_accounts.purged.password_tokens",
    "Expired invite / reset tokens deleted.",
)
PURGED_LOGIN_AUDIT = Attribute(
    "datasette_accounts.purged.login_audit",
    "Login audit rows older than ``audit_retention_days`` deleted.",
)
PURGED_ADMIN_AUDIT = Attribute(
    "datasette_accounts.purged.admin_audit",
    "Admin audit rows older than ``admin_audit_retention_days`` deleted.",
)
PURGE_TABLE = Attribute(
    "datasette_accounts.table",
    "Which retention purge deleted the rows.",
    values=PURGE_TABLES,
)
PROVIDERS_INSTALLED = Attribute(
    "datasette_accounts.providers.installed",
    "Sign-in providers in the registry, including the built-in password one.",
)

# --- Spans -----------------------------------------------------------------

S_RESOLVE_ACTOR = SpanName(
    "datasette_accounts.resolve_actor",
    "Rebuild the actor from the session cookie and the internal database. "
    "Emitted only when a session cookie is present — anonymous requests "
    "only increment ``datasette_accounts.actor.resolutions``. Expect two "
    "per signed-in request (the forced-password-change gate and core's "
    "``actor_from_request``).",
    (ACTOR_OUTCOME, CALLER, LAST_SEEN_TOUCHED),
)
S_LOGIN = SpanName(
    "datasette_accounts.login",
    "``finish_login``: the single termination point of every sign-in, link "
    "and step-up flow — account gates, sign-ups policy, then the mint.",
    (
        PROVIDER,
        IDENTITY,
        INTENT,
        LOGIN_OUTCOME,
        REASON,
        SIGNUPS,
        RESPONSE_MODE,
        ERROR_TYPE,
    ),
)
S_MINT_SESSION = SpanName(
    "datasette_accounts.mint_session",
    "Create the session row and set the session cookie.",
    (PROVIDER,),
)
S_PASSWORD_VERIFY = SpanName(
    "datasette_accounts.password.verify",
    "The password provider's credential check: lockout, exactly one PBKDF2 "
    "verify (real or decoy), audit and failed-attempt bookkeeping.",
    (VERIFY_OUTCOME, REASON, VERIFY_KDF),
)
S_PASSWORD_KDF = SpanName(
    "datasette_accounts.password.kdf",
    "One PBKDF2 operation, including the hop to a worker thread.",
    (KDF_OPERATION, ERROR_TYPE),
)
S_PROVIDER_ROUTE = SpanName(
    "datasette_accounts.provider.route",
    "A provider-owned route wrapped in ``provider_gate``. The provider's own "
    "work, and its ``finish_login`` call, nest underneath.",
    (PROVIDER, GATE, STATE),
)
S_HOUSEKEEPING = SpanName(
    "datasette_accounts.housekeeping",
    "Retention purges, run at startup and after every successful login.",
    (
        TRIGGER,
        PURGED_SESSIONS,
        PURGED_PASSWORD_TOKENS,
        PURGED_LOGIN_AUDIT,
        PURGED_ADMIN_AUDIT,
    ),
)
S_REGISTRY_BUILD = SpanName(
    "datasette_accounts.registry.build",
    "Collect and validate the sign-in provider registry at startup.",
    (PROVIDERS_INSTALLED,),
)

SPANS = (
    S_RESOLVE_ACTOR,
    S_LOGIN,
    S_MINT_SESSION,
    S_PASSWORD_VERIFY,
    S_PASSWORD_KDF,
    S_PROVIDER_ROUTE,
    S_HOUSEKEEPING,
    S_REGISTRY_BUILD,
)

# --- Metrics ---------------------------------------------------------------

M_ACTOR_RESOLUTIONS = MetricName(
    "datasette_accounts.actor.resolutions",
    COUNTER,
    "{resolution}",
    "Session-cookie resolutions by outcome and caller. ``no_cookie`` is "
    "anonymous traffic; a spike in ``bad_signature`` / ``no_session`` / "
    "``session_expired`` is stale or replayed cookies.",
    (ACTOR_OUTCOME, CALLER),
)
M_ACTOR_RESOLVE_DURATION = MetricName(
    "datasette_accounts.actor.resolve.duration",
    HISTOGRAM,
    "s",
    "Time spent resolving the actor — the per-request cost of auth.",
    (ACTOR_OUTCOME,),
    buckets=DURATION_BUCKETS,
)
M_FORCED_CHANGE_BLOCKED = MetricName(
    "datasette_accounts.forced_password_change.blocked",
    COUNTER,
    "{request}",
    "Requests bounced because the account must change its password first. "
    "Non-zero ``json`` means an API client is stuck behind a forced change.",
    (RESPONSE_MODE,),
)
M_LOGINS = MetricName(
    "datasette_accounts.logins",
    COUNTER,
    "{login}",
    "``finish_login`` outcomes. ``ok`` + ``provisioned`` equals sessions "
    "minted; ``reason=provider_disabled`` means a provider is calling "
    "``finish_login`` while switched off.",
    (PROVIDER, LOGIN_OUTCOME, REASON),
)
M_LOGIN_DURATION = MetricName(
    "datasette_accounts.login.duration",
    HISTOGRAM,
    "s",
    "Time in ``finish_login``, including per-login housekeeping.",
    (PROVIDER, IDENTITY),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)
M_PASSWORD_VERIFICATIONS = MetricName(
    "datasette_accounts.password.verifications",
    COUNTER,
    "{verification}",
    "Password credential checks. ``reason=bad_password`` is the brute-force "
    "signal; ``locked`` is attempts against a locked account.",
    (VERIFY_OUTCOME, REASON),
)
M_LOCKOUTS = MetricName(
    "datasette_accounts.lockouts",
    COUNTER,
    "{lockout}",
    "Failed attempts that reached ``lockout_threshold`` and locked an account.",
)
M_KDF_DURATION = MetricName(
    "datasette_accounts.password.kdf.duration",
    HISTOGRAM,
    "s",
    "PBKDF2 time including the worker-thread hop. ``verify`` and ``dummy`` "
    "should have the same distribution — that is what keeps account "
    "existence from leaking through response timing.",
    (KDF_OPERATION,),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 0.75, 1, 2, 5),
)
M_REGISTRATIONS = MetricName(
    "datasette_accounts.registrations",
    COUNTER,
    "{registration}",
    "Self-registrations (password) and external-identity provisioning "
    "(sign-ups ``approval`` / ``auto``). A rising ``capped`` rate means the "
    "abuse caps are set too low, or are working.",
    (PROVIDER, LOGIN_OUTCOME, REGISTRATION_REASON),
)
M_STATE_READS = MetricName(
    "datasette_accounts.state.reads",
    COUNTER,
    "{read}",
    "Provider ``state`` cookie validations. Rising ``expired`` means "
    "``provider_state_ttl_minutes`` is too short for a slow identity "
    "provider; ``mismatch`` / ``bad_signature`` are forged or replayed "
    "callbacks.",
    (STATE,),
)
M_ROWS_PURGED = MetricName(
    "datasette_accounts.housekeeping.rows_purged",
    COUNTER,
    "{row}",
    "Rows deleted by retention housekeeping.",
    (PURGE_TABLE, TRIGGER),
)

METRICS = (
    M_ACTOR_RESOLUTIONS,
    M_ACTOR_RESOLVE_DURATION,
    M_FORCED_CHANGE_BLOCKED,
    M_LOGINS,
    M_LOGIN_DURATION,
    M_PASSWORD_VERIFICATIONS,
    M_LOCKOUTS,
    M_KDF_DURATION,
    M_REGISTRATIONS,
    M_STATE_READS,
    M_ROWS_PURGED,
)
