<script lang="ts">
  import type { AdminPageData } from "../../page_data/AdminPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import Modal from "../../lib/Modal.svelte";
  import PasswordReveal from "../../lib/PasswordReveal.svelte";
  import LinkReveal from "../../lib/LinkReveal.svelte";
  import AdminNav from "../../lib/AdminNav.svelte";

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

  // Self-registered accounts awaiting a verdict — rendered in their own
  // pinned section and excluded from the main table (and its search) so the
  // two states stay unmistakable.
  const pending = $derived(users.filter((u) => u.pending_approval));
  const filtered = $derived(
    users.filter(
      (u) =>
        !u.pending_approval &&
        u.username.toLowerCase().includes(search.trim().toLowerCase()),
    ),
  );

  // Render a stored ISO timestamp in the viewer's locale; fall back to the raw
  // value if it can't be parsed.
  function fmtDate(iso: string | null | undefined): string {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime())
      ? iso
      : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  // Create-account modal
  let createOpen = $state(false);
  let newUsername = $state("");
  let newPassword = $state("");
  let newIsAdmin = $state(false);
  // How the new account gets its credentials: a one-time invite link (the
  // user picks their own password), a server-generated password, or one the
  // admin types.
  let newMode = $state<"invite" | "generate" | "set">("invite");
  let createError = $state("");
  // Set once the account is created with a generated password (shown once).
  let createdCred = $state<{ username: string; password: string } | null>(null);
  // Set once the account is created via an invite link (shown once).
  let createdLink = $state<{ username: string; url: string } | null>(null);

  // Reset-password modal
  let resetTarget = $state<User | null>(null);
  let resetPassword = $state("");
  let resetGenerate = $state(true);
  let resetError = $state("");
  // The generated password to reveal once after a reset (null while editing).
  let resetCred = $state<string | null>(null);

  // Delete-confirm modal
  let deleteTarget = $state<User | null>(null);

  // Reject-confirm modal (approval queue — see plans/self-registration)
  let rejectTarget = $state<User | null>(null);

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
    newMode = "invite";
    createError = "";
    createdCred = null;
    createdLink = null;
    createOpen = true;
  }

  async function create(e: Event) {
    e.preventDefault();
    createError = "";
    if (newMode === "invite") {
      const { ok, data } = await postJSON<{ ok: boolean; error?: string; url?: string }>(
        "/-/admin/api/invite",
        { username: newUsername, is_admin: newIsAdmin },
      );
      if (!ok || !data.ok || !data.url) {
        createError = data.error || "Could not create account";
        return;
      }
      await refresh();
      // Keep the modal open to reveal the one-time invite URL.
      createdLink = { username: newUsername, url: data.url };
      return;
    }
    const body: Record<string, unknown> = { username: newUsername, is_admin: newIsAdmin };
    if (newMode === "generate") body.generate = true;
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

  // One-click mutations get a native are-you-sure prompt; the destructive
  // flows (delete, reject) keep their richer confirm modals.
  async function toggle(u: User, path: string, confirmMsg: string) {
    if (!window.confirm(confirmMsg)) return;
    if (await op(path, { id: u.id })) await refresh();
  }

  async function confirmDelete() {
    const u = deleteTarget;
    if (!u) return;
    deleteTarget = null;
    if (await op("/-/admin/api/delete", { id: u.id })) await refresh();
  }

  async function approve(u: User) {
    if (!window.confirm(`Approve the account request from “${u.username}”?`)) return;
    if (await op("/-/admin/api/approve", { id: u.id })) await refresh();
  }

  async function confirmReject() {
    const u = rejectTarget;
    if (!u) return;
    rejectTarget = null;
    if (await op("/-/admin/api/reject", { id: u.id })) await refresh();
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
    if (!window.confirm(`Revoke this session for “${u.username}”? They will be signed out on that device.`)) return;
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

  // Set-expiry modal (row-menu "Set expiry…"): quick relative presets or an
  // exact local date-time; "Clear expiry" when a deadline is set.
  let expiryTarget = $state<User | null>(null);
  let expiryLocal = $state(""); // the datetime-local input's value
  let expiryError = $state("");

  function openExpiry(u: User) {
    expiryTarget = u;
    expiryLocal = "";
    expiryError = "";
  }

  async function postExpiry(body: Record<string, unknown>) {
    const u = expiryTarget;
    if (!u) return;
    expiryError = "";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/admin/api/set-expiry",
      { id: u.id, ...body },
    );
    if (!ok || !data.ok) {
      // Surface validation 400s and the last-admin 409 verbatim, like the
      // reset-password modal does.
      expiryError = data.error || "Could not update expiry";
      return;
    }
    expiryTarget = null;
    await refresh();
  }

  async function submitExpiry(e: Event) {
    e.preventDefault();
    if (!expiryLocal) {
      expiryError = "Choose a date and time";
      return;
    }
    // A datetime-local value ("2026-08-01T17:30") carries no offset. POSTed
    // raw, SQLite would read it as UTC and silently shift the admin's local
    // intent — so convert to UTC ISO here, where the browser knows the zone.
    await postExpiry({ expires_at: new Date(expiryLocal).toISOString() });
  }

  // One-time link modal (row-menu "New invite link…" / "Reset link…").
  let linkTarget = $state<User | null>(null);
  let linkKind = $state<"invite" | "reset">("invite");
  let linkUrl = $state("");

  async function mintLink(u: User, kind: "invite" | "reset") {
    error = "";
    const path = kind === "invite" ? "/-/admin/api/invite-link" : "/-/admin/api/reset-link";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string; url?: string }>(path, {
      id: u.id,
    });
    if (!ok || !data.ok || !data.url) {
      // Surface failures (e.g. 404 for a just-deleted account) like other
      // row actions do.
      error = data.error || "Could not create link";
      return;
    }
    linkTarget = u;
    linkKind = kind;
    linkUrl = data.url;
    // Minting can change invited state (one live link per account).
    await refresh();
  }
</script>

<svelte:window
  onclick={() => (openMenu = null)}
  onkeydown={(e) => e.key === "Escape" && (openMenu = null)}
/>

<div class="page">
  <header class="bar">
    <h1>Accounts</h1>
  </header>
  <AdminNav current="accounts" />

  {#if error}<p class="msg msg-error">{error}</p>{/if}

  {#if pending.length > 0}
    <section class="card pending-queue" aria-label="Awaiting approval">
      <h2>Awaiting approval</h2>
      <p class="queue-note">
        Self-registered account requests — they can't sign in until approved.
      </p>
      <ul>
        {#each pending as u (u.id)}
          <li>
            <div class="req">
              <span class="uname">{u.username}</span>
              <span class="requested">Requested {fmtDate(u.created_at)}</span>
            </div>
            <div class="verdict">
              <button class="btn-primary btn-sm" onclick={() => approve(u)}>Approve</button>
              <button class="btn-sm btn-danger" onclick={() => (rejectTarget = u)}>Reject</button>
            </div>
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <div class="toolbar">
    <div class="search">
      <span class="ico" aria-hidden="true">⌕</span>
      <input class="input" placeholder="Search accounts…" bind:value={search} />
    </div>
    <button class="btn-primary" onclick={openCreate}>
      + New account
    </button>
  </div>

  <div class="card table-wrap">
    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>Role</th>
          <th>Status</th>
          <th>Last sign-in</th>
          <th>Expires</th>
          <th class="right">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as u (u.id)}
          <tr>
            <td class="uname">
              {u.username}{#if u.id === pageData.viewer_id}<span class="you">(you)</span>{/if}
            </td>
            <td>
              {#if u.is_admin}<span class="badge badge-admin">admin</span>{/if}
            </td>
            <td>
              <div class="status">
                {#if u.disabled}<span class="badge badge-disabled">disabled</span>{/if}
                {#if u.expired}<span class="badge badge-expired">expired</span>{/if}
                {#if u.locked}<span class="badge badge-locked">locked</span>{/if}
                {#if u.invited}<span class="badge badge-invited">invited</span>{/if}
                {#if !u.last_login_at}<span class="badge badge-pending">pending</span>{/if}
              </div>
            </td>
            <td>
              {#if u.last_login_at}
                <span class="lastseen">{fmtDate(u.last_login_at)}</span>
              {:else}
                <span class="never" title="This account has never signed in.">Never</span>
              {/if}
            </td>
            <td>
              {#if u.expires_at}
                <span class="lastseen">{fmtDate(u.expires_at)}</span>
              {:else}
                <span class="never" title="This account never expires.">—</span>
              {/if}
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
                    <button
                      role="menuitem"
                      onclick={() =>
                        pick(() =>
                          toggle(
                            u,
                            "/-/admin/api/toggle-admin",
                            u.is_admin
                              ? `Revoke admin from “${u.username}”?`
                              : `Make “${u.username}” an admin?`,
                          ))}
                    >
                      {u.is_admin ? "Revoke admin" : "Make admin"}
                    </button>
                    {#if u.disabled}
                      <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/enable", `Enable the account “${u.username}”?`))}>Enable</button>
                    {:else}
                      <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/disable", `Disable the account “${u.username}”? They will no longer be able to sign in.`))}>Disable</button>
                    {/if}
                    {#if u.locked}
                      <button role="menuitem" onclick={() => pick(() => toggle(u, "/-/admin/api/unlock", `Unlock the account “${u.username}”?`))}>Unlock</button>
                    {/if}
                    <button role="menuitem" onclick={() => pick(() => openExpiry(u))}>Set expiry…</button>
                    <div class="sep"></div>
                    {#if u.invited}
                      <button role="menuitem" onclick={() => pick(() => mintLink(u, "invite"))}>New invite link…</button>
                    {:else}
                      <button role="menuitem" onclick={() => pick(() => mintLink(u, "reset"))}>Reset link…</button>
                    {/if}
                    <button role="menuitem" onclick={() => pick(() => openReset(u))}>Reset password…</button>
                    <button role="menuitem" onclick={() => pick(() => openSessions(u))}>Active sessions…</button>
                    <a role="menuitem" href="/-/admin/login-attempts?username={encodeURIComponent(u.username)}">Login attempts…</a>
                    <a role="menuitem" href="/-/admin/audit?username={encodeURIComponent(u.username)}">History…</a>
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
          <tr><td colspan="6" class="empty">No accounts match “{search}”.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<!-- Create account -->
<Modal
  bind:open={createOpen}
  onclose={() => {
    createdCred = null;
    createdLink = null;
  }}
  title="New account"
>
  {#if createdCred}
    <p class="lead">Account <strong>{createdCred.username}</strong> was created.</p>
    <PasswordReveal username={createdCred.username} password={createdCred.password} />
  {:else if createdLink}
    <p class="lead">
      Account <strong>{createdLink.username}</strong> was created. Send them this link to choose
      their password.
    </p>
    <LinkReveal url={createdLink.url} />
  {:else}
    <form id="create-form" onsubmit={create}>
      {#if createError}<p class="msg msg-error">{createError}</p>{/if}
      <label class="field">
        <span>Username</span>
        <input bind:value={newUsername} required />
      </label>
      <fieldset class="modes">
        <legend>Password</legend>
        <label class="check">
          <input type="radio" bind:group={newMode} value="invite" />
          <span>Send an invite link — the user chooses their own password</span>
        </label>
        <label class="check">
          <input type="radio" bind:group={newMode} value="generate" />
          <span>Generate a secure password</span>
        </label>
        <label class="check">
          <input type="radio" bind:group={newMode} value="set" />
          <span>Set a password now</span>
        </label>
      </fieldset>
      {#if newMode === "set"}
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
    {#if createdCred || createdLink}
      <button class="btn-primary btn-sm" onclick={() => (createOpen = false)}>Done</button>
    {:else}
      <button class="btn-sm" onclick={() => (createOpen = false)}>Cancel</button>
      <button class="btn-primary btn-sm" type="submit" form="create-form">Create account</button>
    {/if}
  {/snippet}
</Modal>

<!-- One-time link (row menu: New invite link… / Reset link…) -->
<Modal
  open={linkTarget !== null}
  onclose={() => (linkTarget = null)}
  title={linkKind === "invite" ? "New invite link" : "Reset link"}
>
  <p class="lead">
    {#if linkKind === "invite"}
      New invite link for <strong>{linkTarget?.username}</strong> — any previous link no longer
      works.
    {:else}
      Reset link for <strong>{linkTarget?.username}</strong>. They stay signed in until they use
      it; completing it sets the new password and signs them out everywhere else.
    {/if}
  </p>
  <LinkReveal url={linkUrl} />
  {#snippet footer()}
    <button class="btn-primary btn-sm" onclick={() => (linkTarget = null)}>Done</button>
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

<!-- Set expiry -->
<Modal open={expiryTarget !== null} onclose={() => (expiryTarget = null)} title="Set expiry">
  <form id="expiry-form" onsubmit={submitExpiry}>
    <p class="lead">
      Set a deadline for <strong>{expiryTarget?.username}</strong> — past it the account behaves
      like a disabled one until the expiry is extended or cleared.
    </p>
    {#if expiryTarget?.expires_at}
      <p class="muted current">Currently expires {fmtDate(expiryTarget.expires_at)}.</p>
    {/if}
    {#if expiryError}<p class="msg msg-error">{expiryError}</p>{/if}
    <div class="presets">
      <button type="button" class="btn-sm" onclick={() => postExpiry({ in_days: 30 })}>
        In 30 days
      </button>
      <button type="button" class="btn-sm" onclick={() => postExpiry({ in_days: 90 })}>
        In 90 days
      </button>
    </div>
    <label class="field">
      <span>Or an exact date and time (your local time)</span>
      <input type="datetime-local" bind:value={expiryLocal} />
    </label>
  </form>
  {#snippet footer()}
    {#if expiryTarget?.expires_at}
      <button class="btn-sm btn-danger" onclick={() => postExpiry({})}>Clear expiry</button>
    {/if}
    <button class="btn-sm" onclick={() => (expiryTarget = null)}>Cancel</button>
    <button class="btn-primary btn-sm" type="submit" form="expiry-form">Set expiry</button>
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

<!-- Reject confirm (approval queue) -->
<Modal open={rejectTarget !== null} onclose={() => (rejectTarget = null)} title="Reject request">
  <p class="lead">
    Reject the account request from <strong>{rejectTarget?.username}</strong>? This deletes the
    request. They can submit a new one while signups are open.
  </p>
  {#snippet footer()}
    <button class="btn-sm" onclick={() => (rejectTarget = null)}>Cancel</button>
    <button class="btn-danger-solid btn-sm" onclick={confirmReject}>Reject request</button>
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
            <div class="stime">{fmtDate(s.last_seen_at)}</div>
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
    margin-bottom: 1rem;
  }
  .bar h1 {
    margin: 0;
  }

  /* Awaiting-approval queue — pinned above the main table with a warn accent
     so pending verdicts can't be mistaken for regular accounts. */
  .pending-queue {
    margin-bottom: 1.25rem;
    border-left: 4px solid #b45309;
  }
  .pending-queue h2 {
    margin: 0 0 0.25rem;
    font-size: 1rem;
  }
  .queue-note {
    margin: 0 0 0.75rem;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .pending-queue ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .pending-queue li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.6rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .req {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }
  .requested {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .verdict {
    display: flex;
    gap: 0.5rem;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 1rem;
  }
  .search {
    position: relative;
    flex: 1;
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
  .you {
    margin-left: 0.4rem;
    font-weight: 400;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .status {
    display: flex;
    flex-wrap: wrap;
    gap: 0.9rem;
  }
  .lastseen {
    font-size: 0.85rem;
    white-space: nowrap;
  }
  .never {
    font-size: 0.85rem;
    color: var(--muted);
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

  .presets {
    display: flex;
    gap: 0.5rem;
    margin: 0 0 1rem;
  }
  .current {
    margin: -0.5rem 0 1rem;
    font-size: 0.85rem;
  }

  .modes {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    margin: 0 0 1rem;
    padding: 0;
    border: none;
  }
  .modes legend {
    font-weight: 600;
    font-size: 0.85rem;
    color: var(--muted);
    padding: 0;
    margin-bottom: 0.35rem;
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
