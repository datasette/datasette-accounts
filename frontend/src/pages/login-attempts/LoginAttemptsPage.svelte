<script lang="ts">
  import type { LoginAttemptsPageData } from "../../page_data/LoginAttemptsPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import AdminNav from "../../lib/AdminNav.svelte";

  type Attempt = LoginAttemptsPageData["attempts"][number];
  const pageData = loadPageData<LoginAttemptsPageData>();

  let attempts = $state<Attempt[]>(pageData.attempts);
  let username = $state(pageData.filter_username ?? "");
  let ip = $state(pageData.filter_ip ?? "");
  let loading = $state(false);
  let error = $state("");

  // Human-readable labels for the stored machine reasons.
  const REASONS: Record<string, string> = {
    success: "Signed in",
    bad_password: "Wrong password",
    no_such_user: "No such account",
    disabled: "Account disabled",
    expired: "Account expired",
    locked: "Account locked",
    reauth: "Re-authentication",
    pending_approval: "Awaiting approval",
    register: "Registration attempt",
  };
  function reasonLabel(r: string | null | undefined): string {
    if (!r) return "—";
    return REASONS[r] ?? r;
  }

  // Render a stored ISO timestamp in the viewer's locale; fall back to the raw
  // value if it can't be parsed.
  function fmtDate(iso: string | null | undefined): string {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime())
      ? iso
      : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  async function apply(e?: Event) {
    e?.preventDefault();
    loading = true;
    error = "";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string; attempts?: Attempt[] }>(
      "/-/admin/api/login-attempts",
      { username: username.trim(), ip: ip.trim() },
    );
    loading = false;
    if (!ok || !data.ok) {
      error = data.error || "Could not load login attempts";
      return;
    }
    attempts = data.attempts ?? [];
  }

  function clear() {
    username = "";
    ip = "";
    apply();
  }

  const hasFilter = $derived(username.trim() !== "" || ip.trim() !== "");
</script>

<div class="page">
  <header class="bar">
    <h1>Login attempts</h1>
  </header>
  <AdminNav current="login-attempts" />

  <p class="intro">
    Every sign-in attempt, most recent first. Filter by the exact username entered
    or the client IP address. Rows are kept for the configured retention window.
  </p>

  <form class="filters" onsubmit={apply}>
    <label class="field">
      <span>Username</span>
      <input class="input" bind:value={username} placeholder="Any account" />
    </label>
    <label class="field">
      <span>IP address</span>
      <input class="input" bind:value={ip} placeholder="Any IP" />
    </label>
    <div class="actions">
      <button class="btn-primary btn-sm" type="submit" disabled={loading}>
        {loading ? "Loading…" : "Apply"}
      </button>
      {#if hasFilter}
        <button class="btn-sm" type="button" onclick={clear} disabled={loading}>Clear</button>
      {/if}
    </div>
  </form>

  {#if error}<p class="msg msg-error">{error}</p>{/if}

  <div class="card table-wrap">
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Username</th>
          <th>IP</th>
          <th>Result</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        {#each attempts as a (a.id)}
          <tr>
            <td class="time">{fmtDate(a.timestamp)}</td>
            <td class="uname">{a.username ?? "—"}</td>
            <td class="ip">{a.ip ?? "—"}</td>
            <td>
              {#if a.success}
                <span class="badge ok">success</span>
              {:else}
                <span class="badge fail">failed</span>
              {/if}
            </td>
            <td class="reason">{reasonLabel(a.reason)}</td>
          </tr>
        {/each}
        {#if attempts.length === 0}
          <tr><td colspan="5" class="empty">No login attempts match these filters.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .bar {
    margin-bottom: 1rem;
  }
  .bar h1 {
    margin: 0;
  }
  .intro {
    color: var(--muted);
    margin: 0 0 1.25rem;
    max-width: 42rem;
  }

  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  .field span {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
  }
  .field .input {
    min-width: 200px;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
  }

  .table-wrap {
    padding: 0;
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.7rem 0.9rem;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    white-space: nowrap;
  }
  th {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  .uname {
    font-weight: 600;
  }
  .ip {
    font-variant-numeric: tabular-nums;
  }
  .reason {
    color: var(--muted);
  }
  .empty {
    text-align: center;
    color: var(--muted);
    padding: 1.5rem;
  }

  /* Result badges — green for success, red for a failed attempt. */
  .badge.ok {
    color: var(--ok);
  }
  .badge.fail {
    color: var(--danger);
  }
</style>
