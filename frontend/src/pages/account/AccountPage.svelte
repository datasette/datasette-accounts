<script lang="ts">
  import type { AccountPageData } from "../../page_data/AccountPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<AccountPageData>();

  // Client-side tab "routing" via the URL hash — /-/account#sessions is
  // linkable and the back button walks tab switches; no server round-trip.
  // During the forced-password-change state the tabs are hidden entirely and
  // the page stays password-only.
  type Tab = "password" | "sessions";
  const tabFromHash = (): Tab =>
    window.location.hash === "#sessions" ? "sessions" : "password";
  let tab = $state<Tab>(tabFromHash());

  let current = $state("");
  let next = $state("");
  let confirmNext = $state("");
  let message = $state("");
  let error = $state("");
  let busy = $state(false);

  type OwnSession = NonNullable<AccountPageData["sessions"]>[number];

  // Sessions arrive sorted most-recent-last_seen_at-first from the server;
  // the refresh endpoint returns the same shape and order.
  let sessions = $state<OwnSession[]>(pageData.sessions ?? []);
  let sessionsError = $state("");
  let sessionsBusy = $state(false);
  const hasOthers = $derived(sessions.some((s) => !s.current));

  // Render a stored ISO timestamp in the viewer's locale; fall back to the raw
  // value if it can't be parsed.
  function fmtDate(iso: string | null | undefined): string {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime())
      ? iso
      : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  async function refreshSessions() {
    const { data } = await postJSON<{ ok: boolean; sessions?: OwnSession[] }>(
      "/-/account/api/sessions",
      {},
    );
    if (data.sessions) sessions = data.sessions;
  }

  async function sessionOp(path: string, body: Record<string, unknown>) {
    sessionsError = "";
    sessionsBusy = true;
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(path, body);
    if (!ok || !data.ok) {
      sessionsError = data.error || "Operation failed";
    } else {
      await refreshSessions();
    }
    sessionsBusy = false;
  }

  async function revoke(token: string) {
    await sessionOp("/-/account/api/revoke-session", { token_sha256: token });
  }

  async function logoutOthers() {
    if (!confirm("Log out all other sessions? Other devices will be signed out.")) {
      return;
    }
    await sessionOp("/-/account/api/logout-others", {});
  }

  async function submit(e: Event) {
    e.preventDefault();
    error = "";
    message = "";
    if (next !== confirmNext) {
      error = "Passwords don't match";
      return;
    }
    busy = true;
    const body: Record<string, unknown> = { new_password: next };
    // First-login forced change doesn't ask for the current password again.
    if (!pageData.must_change_password) body.current_password = current;
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/account/api/change-password",
      body,
    );
    busy = false;
    if (ok && data.ok) {
      message = "Password changed.";
      setTimeout(() => (window.location.href = "/"), 800);
    } else {
      error = data.error || "Failed";
    }
  }
</script>

<svelte:window onhashchange={() => (tab = tabFromHash())} />

<!-- Not .narrow: the sessions table needs room; the password card caps its
     own width instead. -->
<div class="page">
  <h1>Your account</h1>
  <p class="who">Signed in as <strong class="me">{pageData.username}</strong></p>

  {#if pageData.must_change_password}
    <p class="msg msg-error">Set a new password before continuing.</p>
  {:else}
    <nav class="tabs" aria-label="Account sections">
      <a href="#password" class:active={tab === "password"} aria-current={tab === "password" ? "page" : undefined}>Password</a>
      <a href="#sessions" class:active={tab === "sessions"} aria-current={tab === "sessions" ? "page" : undefined}>Sessions</a>
    </nav>
  {/if}

  {#if pageData.must_change_password || tab === "password"}
  <form class="card pw-card" onsubmit={submit}>
    <h2>Change password</h2>
    {#if message}<p class="msg msg-ok">{message}</p>{/if}
    {#if error}<p class="msg msg-error">{error}</p>{/if}
    <!-- Hidden username so password managers (1Password, Chrome, …) associate the
         new password with this account and offer to update the saved entry. -->
    <input
      class="pw-username"
      type="text"
      name="username"
      autocomplete="username"
      value={pageData.username}
      readonly
      tabindex="-1"
      aria-hidden="true"
    />
    {#if !pageData.must_change_password}
      <label class="field">
        <span>Current password</span>
        <input
          id="current-password"
          name="current-password"
          type="password"
          bind:value={current}
          autocomplete="current-password"
          required
        />
      </label>
    {/if}
    <label class="field">
      <span>New password</span>
      <input
        id="new-password"
        name="new-password"
        type="password"
        bind:value={next}
        autocomplete="new-password"
        required
      />
    </label>
    <label class="field">
      <span>Confirm new password</span>
      <input
        id="confirm-password"
        name="confirm-password"
        type="password"
        bind:value={confirmNext}
        autocomplete="new-password"
        required
      />
    </label>
    <button type="submit" class="btn-primary" disabled={busy}>
      {busy ? "Saving…" : "Change password"}
    </button>
  </form>
  {:else}
    <div class="card">
      <h2>Sessions</h2>
      {#if sessionsError}<p class="msg msg-error">{sessionsError}</p>{/if}
      {#if sessions.length === 0}
        <p class="muted">No active sessions.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>IP</th>
                <th>Signed in</th>
                <th>Last seen</th>
                <th><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {#each sessions as s (s.token_sha256)}
                <tr>
                  <td class="device">
                    {#if s.user_agent}
                      <span class="ua" title={s.user_agent}>{s.user_agent}</span>
                    {:else}
                      <span class="muted">—</span>
                    {/if}
                    {#if s.current}
                      <span class="badge badge-current">This device</span>
                    {/if}
                  </td>
                  <td>{s.ip ?? "—"}</td>
                  <td class="nowrap">{fmtDate(s.created_at)}</td>
                  <td class="nowrap">{fmtDate(s.last_seen_at)}</td>
                  <td class="row-actions">
                    {#if !s.current}
                      <button
                        class="btn-sm btn-danger"
                        disabled={sessionsBusy}
                        onclick={() => revoke(s.token_sha256)}
                      >
                        Revoke
                      </button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if hasOthers}
          <div class="sessions-foot">
            <button class="btn-sm btn-danger" disabled={sessionsBusy} onclick={logoutOthers}>
              Log out other sessions
            </button>
          </div>
        {/if}
      {/if}
    </div>
  {/if}
</div>

<style>
  .who {
    margin: 0 0 1.25rem;
    color: var(--muted);
  }
  .me {
    color: var(--acc-d);
  }
  h2 {
    margin: 0 0 1rem;
    font-size: 1.05rem;
  }
  /* Present in the DOM for password managers, but not shown or focusable.
     `display:none` is avoided because some managers skip such fields. */
  .pw-username {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    border: 0;
  }

  /* Same look as the admin pages' AdminNav tab strip. */
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 1.25rem;
    border-bottom: 1px solid var(--border);
  }
  .tabs a {
    padding: 0.5rem 0.9rem;
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--muted);
    text-decoration: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tabs a:hover {
    color: var(--ink);
  }
  .tabs a.active {
    color: var(--acc);
    border-bottom-color: var(--acc);
  }

  .pw-card {
    max-width: 460px;
  }
  .muted {
    color: var(--muted);
  }
  .table-wrap {
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.55rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  th {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    white-space: nowrap;
  }
  tbody tr:last-child td {
    border-bottom: none;
  }
  .device {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    flex-wrap: wrap;
  }
  .ua {
    display: inline-block;
    max-width: 340px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .nowrap {
    white-space: nowrap;
  }
  .row-actions {
    text-align: right;
    white-space: nowrap;
  }
  .sessions-foot {
    margin-top: 0.9rem;
    display: flex;
    justify-content: flex-end;
  }
  /* Visually-hidden header text for the actions column. */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    border: 0;
  }
</style>
