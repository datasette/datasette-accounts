<script lang="ts">
  import type { AdminPageData } from "../../page_data/AdminPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import Modal from "../../lib/Modal.svelte";
  import PasswordReveal from "../../lib/PasswordReveal.svelte";

  type User = AdminPageData["users"][number];
  type Session = {
    token_sha256: string;
    last_seen_at: string;
    ip: string | null;
    user_agent: string | null;
  };
  const pageData = loadPageData<AdminPageData>();

  const KEBAB =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0m0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0m0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0"/></svg>';
  const TRASH =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M2.5 1a1 1 0 0 0-1 1v1a1 1 0 0 0 1 1H3v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V4h.5a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H10a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1zm3 4a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 .5-.5M8 5a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7A.5.5 0 0 1 8 5m3 .5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 1 0"/></svg>';

  let users = $state<User[]>(pageData.users);
  let error = $state("");
  let search = $state("");
  let openMenu = $state<string | null>(null);

  function toggleMenu(e: Event, id: string) {
    e.stopPropagation();
    openMenu = openMenu === id ? null : id;
  }

  // Close the menu, then run the chosen action.
  function pick(fn: () => void) {
    openMenu = null;
    fn();
  }

  const filtered = $derived(
    users.filter((u) => u.username.toLowerCase().includes(search.trim().toLowerCase())),
  );

  // Create-account modal
  let createOpen = $state(false);
  let newUsername = $state("");
  let newPassword = $state("");
  let newIsAdmin = $state(false);
  let newGenerate = $state(true);
  let createError = $state("");
  // Set once the account is created with a generated password (shown once).
  let createdCred = $state<{ username: string; password: string } | null>(null);

  // Reset-password modal
  let resetTarget = $state<User | null>(null);
  let resetPassword = $state("");
  let resetGenerate = $state(true);
  let resetError = $state("");
  // The generated password to reveal once after a reset (null while editing).
  let resetCred = $state<string | null>(null);

  // Delete-confirm modal
  let deleteTarget = $state<User | null>(null);

  // Sessions modal
  let sessionsTarget = $state<User | null>(null);
  let sessions = $state<Session[]>([]);

  async function refresh() {
    const { data } = await postJSON<{ users: User[] }>("/-/admin/api/list", {});
    if (data.users) users = data.users;
  }

  async function op(path: string, body: Record<string, unknown>) {
    error = "";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(path, body);
    if (!ok || !data.ok) {
      error = data.error || "Operation failed";
      return false;
    }
    return true;
  }

  function openCreate() {
    newUsername = "";
    newPassword = "";
    newIsAdmin = false;
    newGenerate = true;
    createError = "";
    createdCred = null;
    createOpen = true;
  }

  async function create(e: Event) {
    e.preventDefault();
    createError = "";
    const body: Record<string, unknown> = { username: newUsername, is_admin: newIsAdmin };
    if (newGenerate) body.generate = true;
    else body.password = newPassword;
    const { ok, data } = await postJSON<{ ok: boolean; error?: string; password?: string }>(
      "/-/admin/api/create",
      body,
    );
    if (!ok || !data.ok) {
      createError = data.error || "Could not create account";
      return;
    }
    await refresh();
    if (data.password) {
      // Keep the modal open to reveal the generated password once.
      createdCred = { username: newUsername, password: data.password };
    } else {
      createOpen = false;
    }
  }

  async function toggle(u: User, path: string) {
    if (await op(path, { id: u.id })) await refresh();
  }

  async function confirmDelete() {
    const u = deleteTarget;
    if (!u) return;
    deleteTarget = null;
    if (await op("/-/admin/api/delete", { id: u.id })) await refresh();
  }

  async function submitReset(e: Event) {
    e.preventDefault();
    const u = resetTarget;
    if (!u) return;
    resetError = "";
    const body: Record<string, unknown> = { id: u.id };
    if (resetGenerate) body.generate = true;
    else body.password = resetPassword;
    const { ok, data } = await postJSON<{ ok: boolean; error?: string; password?: string }>(
      "/-/admin/api/reset-password",
      body,
    );
    if (!ok || !data.ok) {
      resetError = data.error || "Could not reset password";
      return;
    }
    resetPassword = "";
    if (data.password) {
      // Keep the modal open to reveal the generated password once.
      resetCred = data.password;
    } else {
      resetTarget = null;
    }
  }

  async function openSessions(u: User) {
    const { data } = await postJSON<{ sessions: Session[] }>("/-/admin/api/list-sessions", {
      id: u.id,
    });
    sessions = data.sessions || [];
    sessionsTarget = u;
  }

  async function revoke(token: string) {
    const u = sessionsTarget;
    if (!u) return;
    if (await op("/-/admin/api/revoke-session", { id: u.id, token_sha256: token })) {
      const { data } = await postJSON<{ sessions: Session[] }>("/-/admin/api/list-sessions", {
        id: u.id,
      });
      sessions = data.sessions || [];
    }
  }

  function openReset(u: User) {
    resetTarget = u;
    resetPassword = "";
    resetGenerate = true;
    resetError = "";
    resetCred = null;
  }
</script>

<svelte:window
  onclick={() => (openMenu = null)}
  onkeydown={(e) => e.key === "Escape" && (openMenu = null)}
/>

<div class="page">
  <header class="bar">
    <h1>Accounts</h1>
    <button class="btn-primary" onclick={openCreate}>
      + New account
    </button>
  </header>

  {#if error}<p class="msg msg-error">{error}</p>{/if}

  <div class="search">
    <span class="ico" aria-hidden="true">⌕</span>
    <input class="input" placeholder="Search accounts…" bind:value={search} />
  </div>

  <div class="card table-wrap">
    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>Role</th>
          <th>Status</th>
          <th class="right">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as u (u.id)}
          <tr>
            <td class="uname">{u.username}</td>
            <td>
              {#if u.is_admin}<span class="badge badge-admin">admin</span>{/if}
            </td>
            <td>
              <div class="status">
                {#if u.disabled}<span class="badge badge-disabled">disabled</span>{/if}
                {#if u.locked}<span class="badge badge-locked">locked</span>{/if}
              </div>
            </td>
            <td class="actions">
              <div class="menu-wrap">
                <button
                  class="icon-btn"
                  aria-label="Actions for {u.username}"
                  aria-haspopup="menu"
                  aria-expanded={openMenu === u.id}
                  onclick={(e) => toggleMenu(e, u.id)}>{@html KEBAB}</button
                >
                {#if openMenu === u.id}
                  <div class="menu" role="menu" tabindex="-1">
                    <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/toggle-admin"))}>
                      {u.is_admin ? "Revoke admin" : "Make admin"}
                    </button>
                    {#if u.disabled}
                      <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/enable"))}>Enable</button>
                    {:else}
                      <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/disable"))}>Disable</button>
                    {/if}
                    {#if u.locked}
                      <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/unlock"))}>Unlock</button>
                    {/if}
                    <div class="sep"></div>
                    <button role="menuitem" onclick={() => pick(() => openReset(u))}>Reset password…</button>
                    <button role="menuitem" onclick={() => pick(() => openSessions(u))}>Active sessions…</button>
                  </div>
                {/if}
              </div>
              <button
                class="icon-btn danger"
                aria-label="Delete {u.username}"
                onclick={() => (deleteTarget = u)}>{@html TRASH}</button
              >
            </td>
          </tr>
        {/each}
        {#if filtered.length === 0}
          <tr><td colspan="4" class="empty">No accounts match “{search}”.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<!-- Create account -->
<Modal bind:open={createOpen} onclose={() => (createdCred = null)} title="New account">
  {#if createdCred}
    <p class="lead">Account <strong>{createdCred.username}</strong> was created.</p>
    <PasswordReveal username={createdCred.username} password={createdCred.password} />
  {:else}
    <form id="create-form" onsubmit={create}>
      {#if createError}<p class="msg msg-error">{createError}</p>{/if}
      <label class="field">
        <span>Username</span>
        <input bind:value={newUsername} required />
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={newGenerate} />
        <span>Generate a secure password</span>
      </label>
      {#if !newGenerate}
        <label class="field">
          <span>Initial password</span>
          <input type="password" bind:value={newPassword} required />
        </label>
      {/if}
      <label class="check">
        <input type="checkbox" bind:checked={newIsAdmin} />
        <span>Grant admin permission</span>
      </label>
    </form>
  {/if}
  {#snippet footer()}
    {#if createdCred}
      <button class="btn-primary btn-sm" onclick={() => (createOpen = false)}>Done</button>
    {:else}
      <button class="btn-sm" onclick={() => (createOpen = false)}>Cancel</button>
      <button class="btn-primary btn-sm" type="submit" form="create-form">Create account</button>
    {/if}
  {/snippet}
</Modal>

<!-- Reset password -->
<Modal open={resetTarget !== null} onclose={() => (resetTarget = null)} title="Reset password">
  {#if resetCred}
    <p class="lead">Password reset for <strong>{resetTarget?.username}</strong>.</p>
    <PasswordReveal username={resetTarget?.username} password={resetCred} />
  {:else}
    <form id="reset-form" onsubmit={submitReset}>
      <p class="lead">Set a new password for <strong>{resetTarget?.username}</strong>.</p>
      {#if resetError}<p class="msg msg-error">{resetError}</p>{/if}
      <label class="check">
        <input type="checkbox" bind:checked={resetGenerate} />
        <span>Generate a secure password</span>
      </label>
      {#if !resetGenerate}
        <label class="field">
          <span>New password</span>
          <!-- svelte-ignore a11y_autofocus -->
          <input type="password" bind:value={resetPassword} required autofocus />
        </label>
      {/if}
    </form>
  {/if}
  {#snippet footer()}
    {#if resetCred}
      <button class="btn-primary btn-sm" onclick={() => (resetTarget = null)}>Done</button>
    {:else}
      <button class="btn-sm" onclick={() => (resetTarget = null)}>Cancel</button>
      <button class="btn-primary btn-sm" type="submit" form="reset-form">Reset password</button>
    {/if}
  {/snippet}
</Modal>

<!-- Delete confirm -->
<Modal open={deleteTarget !== null} onclose={() => (deleteTarget = null)} title="Delete account">
  <p class="lead">
    Delete <strong>{deleteTarget?.username}</strong>? This removes the account and all of its
    sessions. This cannot be undone.
  </p>
  {#snippet footer()}
    <button class="btn-sm" onclick={() => (deleteTarget = null)}>Cancel</button>
    <button class="btn-danger-solid btn-sm" onclick={confirmDelete}>Delete account</button>
  {/snippet}
</Modal>

<!-- Sessions -->
<Modal
  open={sessionsTarget !== null}
  onclose={() => (sessionsTarget = null)}
  title="Active sessions"
>
  <p class="lead"><strong>{sessionsTarget?.username}</strong></p>
  {#if sessions.length === 0}
    <p class="muted">No active sessions.</p>
  {:else}
    <ul class="sessions">
      {#each sessions as s (s.token_sha256)}
        <li>
          <div class="sinfo">
            <div class="stime">{s.last_seen_at}</div>
            <div class="smeta">{s.ip ?? "unknown IP"} · {s.user_agent ?? "unknown device"}</div>
          </div>
          <button class="btn-sm btn-danger" onclick={() => revoke(s.token_sha256)}>Revoke</button>
        </li>
      {/each}
    </ul>
  {/if}
</Modal>

<style>
  .bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1rem;
  }
  .bar h1 {
    margin: 0;
  }

  .search {
    position: relative;
    margin-bottom: 1rem;
    max-width: 340px;
  }
  .search .ico {
    position: absolute;
    left: 0.7rem;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    font-size: 1.25rem;
    line-height: 1;
    pointer-events: none;
  }

  .table-wrap {
    padding: 0;
    /* visible so row dropdown menus can escape the card bounds */
    overflow: visible;
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
  tbody tr:hover td {
    background: #fafbfc;
  }
  .uname {
    font-weight: 600;
  }
  .status {
    display: flex;
    gap: 0.9rem;
  }
  .right {
    text-align: right;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    justify-content: flex-end;
  }
  .empty {
    text-align: center;
    color: var(--muted);
    padding: 1.5rem;
  }

  .lead {
    margin: 0 0 1rem;
  }
  .muted {
    color: var(--muted);
  }
  .check {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .check input {
    width: auto;
  }

  .sessions {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .sessions li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.6rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .stime {
    font-weight: 600;
    font-size: 0.85rem;
  }
  .smeta {
    color: var(--muted);
    font-size: 0.78rem;
    word-break: break-word;
  }
</style>
