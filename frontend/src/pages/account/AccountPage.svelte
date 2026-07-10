<script lang="ts">
  import type { AccountPageData } from "../../page_data/AccountPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<AccountPageData>();

  let current = $state("");
  let next = $state("");
  let message = $state("");
  let error = $state("");
  let busy = $state(false);

  // Sessions are already sorted most-recent-last_seen_at-first by the server;
  // no revoke / log-out-others here — read-only in this slice.
  const sessions = pageData.sessions ?? [];

  // Render a stored ISO timestamp in the viewer's locale; fall back to the raw
  // value if it can't be parsed.
  function fmtDate(iso: string | null | undefined): string {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime())
      ? iso
      : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = "";
    message = "";
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

<div class="page narrow">
  <h1>Your account</h1>
  <p class="who">Signed in as <strong class="me">{pageData.username}</strong></p>

  {#if pageData.must_change_password}
    <p class="msg msg-error">Set a new password before continuing.</p>
  {/if}

  <form class="card" onsubmit={submit}>
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
    <button type="submit" class="btn-primary" disabled={busy}>
      {busy ? "Saving…" : "Change password"}
    </button>
  </form>

  {#if !pageData.must_change_password}
    <div class="card sessions-card">
      <h2>Sessions</h2>
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
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
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

  .sessions-card {
    margin-top: 1.5rem;
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
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .nowrap {
    white-space: nowrap;
  }
</style>
