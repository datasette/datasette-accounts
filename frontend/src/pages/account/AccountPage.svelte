<script lang="ts">
  import type { AccountPageData } from "../../page_data/AccountPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import Modal from "../../lib/Modal.svelte";

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

  // --- Sign-in methods (design §6). Password status + linked identities +
  // the enabled external providers still available to link.
  type Identity = NonNullable<AccountPageData["identities"]>[number];
  type Linkable = NonNullable<AccountPageData["linkable_providers"]>[number];
  const identities = pageData.identities ?? [];
  const linkable = pageData.linkable_providers ?? [];
  const hasPassword = pageData.has_password !== false;
  let methodsError = $state("");

  // Link modal: a password account confirms its password (step-up), a
  // password-less account re-completes one already-linked provider's flow.
  let linkTarget = $state<Linkable | null>(null);
  let linkPassword = $state("");
  let linkStepUp = $state("");
  let linkError = $state("");
  let linkBusy = $state(false);

  function openLink(p: Linkable) {
    linkTarget = p;
    linkPassword = "";
    linkStepUp = identities[0]?.provider ?? "";
    linkError = "";
  }

  async function submitLink(e: Event) {
    e.preventDefault();
    const p = linkTarget;
    if (!p) return;
    linkError = "";
    linkBusy = true;
    const body: Record<string, unknown> = { provider: p.key };
    if (hasPassword) body.password = linkPassword;
    else body.step_up_provider = linkStepUp;
    const { ok, data } = await postJSON<{
      ok: boolean;
      start_url?: string;
      error?: string;
    }>("/-/account/api/link-start", body);
    linkBusy = false;
    if (ok && data.ok && data.start_url) {
      // Redirect-based flow — hand the browser off to the provider's start.
      window.location.href = data.start_url;
    } else {
      linkError = data.error || "Could not start linking.";
    }
  }

  async function unlink(i: Identity) {
    if (!window.confirm(`Unlink ${i.label} from your account?`)) return;
    methodsError = "";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/account/api/unlink",
      { provider: i.provider, subject: i.subject },
    );
    if (!ok || !data.ok) {
      // Render the strand-guard 400 verbatim ("Set a password first…").
      methodsError = data.error || "Could not unlink.";
      return;
    }
    // Reload so identities + linkable recompute server-side (the hash tab is
    // preserved across the reload).
    window.location.reload();
  }

  // Render a stored ISO timestamp in the viewer's locale; fall back to the raw
  // value if it can't be parsed.
  function fmtDate(iso: string | null | undefined): string {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime())
      ? iso
      : d.toLocaleString(undefined, {
          dateStyle: "medium",
          timeStyle: "short",
        });
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
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      path,
      body,
    );
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
    if (
      !confirm("Log out all other sessions? Other devices will be signed out.")
    ) {
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
  <p class="who">
    Signed in as <strong class="me">{pageData.username}</strong>
  </p>

  {#if pageData.must_change_password}
    <p class="msg msg-error">Set a new password before continuing.</p>
  {:else}
    <nav class="tabs" aria-label="Account sections">
      <a
        href="#password"
        class:active={tab === "password"}
        aria-current={tab === "password" ? "page" : undefined}>Password</a
      >
      <a
        href="#sessions"
        class:active={tab === "sessions"}
        aria-current={tab === "sessions" ? "page" : undefined}
        >Sign-in methods</a
      >
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
    <div class="card methods-card">
      <h2>Sign-in methods</h2>
      {#if methodsError}<p class="msg msg-error">{methodsError}</p>{/if}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>Identity</th>
              <th>Last used</th>
              <th><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><span class="badge badge-pw">password</span></td>
              <td>
                {#if hasPassword}
                  Set
                  <span class="muted small"
                    >· <a href="#password">change below</a></span
                  >
                {:else}
                  <span class="muted">Not set</span>
                {/if}
              </td>
              <td></td>
              <td></td>
            </tr>
            {#each identities as i (i.provider + i.subject)}
              <tr>
                <td><span class="badge badge-provider">{i.label}</span></td>
                <td>
                  subject <code>{i.subject}</code>
                  <span class="muted small"
                    >· linked {fmtDate(i.created_at)}</span
                  >
                </td>
                <td class="nowrap">
                  {#if i.last_login_at}{fmtDate(i.last_login_at)}{:else}<span
                      class="muted">—</span
                    >{/if}
                </td>
                <td class="row-actions">
                  <button class="btn-sm btn-danger" onclick={() => unlink(i)}
                    >Unlink</button
                  >
                </td>
              </tr>
            {/each}
            {#each linkable as p (p.key)}
              <tr>
                <td><span class="badge badge-provider">{p.label}</span></td>
                <td class="muted">Not linked</td>
                <td></td>
                <td class="row-actions">
                  <button class="btn-sm" onclick={() => openLink(p)}
                    >Link…</button
                  >
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h2>Sessions</h2>
      {#if sessionsError}<p class="msg msg-error">{sessionsError}</p>{/if}
      {#if sessions.length === 0}
        <p class="muted">No active sessions.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <!-- "Signed in via" is the new provenance column (design §7),
                   beside the existing IP / created / last-seen columns. -->
              <tr>
                <th>Device</th>
                <th>Signed in via</th>
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
                      <span class="ua" title={s.user_agent}>{s.user_agent}</span
                      >
                    {:else}
                      <span class="muted">—</span>
                    {/if}
                    {#if s.current}
                      <span class="badge badge-current">This device</span>
                    {/if}
                  </td>
                  <td>
                    {#if s.provider === "password"}
                      <span class="badge badge-pw">password</span>
                    {:else}
                      <span class="badge badge-provider">{s.provider}</span>
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
            <button
              class="btn-sm btn-danger"
              disabled={sessionsBusy}
              onclick={logoutOthers}
            >
              Log out other sessions
            </button>
          </div>
        {/if}
      {/if}
    </div>
  {/if}
</div>

<!-- Link a provider (design §6). Password accounts confirm their password
     (step-up); password-less accounts pick an already-linked provider to
     re-complete. Either way, success returns a start_url we navigate to. -->
<Modal
  open={linkTarget !== null}
  onclose={() => (linkTarget = null)}
  title={linkTarget ? `Link ${linkTarget.label} to your account` : "Link"}
>
  <form id="link-form" onsubmit={submitLink}>
    {#if linkError}<p class="msg msg-error">{linkError}</p>{/if}
    {#if hasPassword}
      <p class="lead muted">
        Confirm your password to continue. You'll then be sent to
        {linkTarget?.label} to sign in once.
      </p>
      <label class="field">
        <span>Password</span>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          type="password"
          name="password"
          bind:value={linkPassword}
          autocomplete="current-password"
          required
          autofocus
        />
      </label>
    {:else if identities.length > 0}
      <p class="lead muted">
        Confirm an existing sign-in method to continue. You'll re-sign-in with
        it once, then be sent to {linkTarget?.label}.
      </p>
      <label class="field">
        <span>Confirm with</span>
        <select bind:value={linkStepUp}>
          {#each identities as i (i.provider + i.subject)}
            <option value={i.provider}>{i.label}</option>
          {/each}
        </select>
      </label>
    {:else}
      <p class="lead muted">
        This account has no other sign-in method to confirm with. Set a password
        first, then link {linkTarget?.label}.
      </p>
    {/if}
  </form>
  {#snippet footer()}
    <button class="btn-sm" onclick={() => (linkTarget = null)}>Cancel</button>
    {#if hasPassword || identities.length > 0}
      <button
        class="btn-primary btn-sm"
        type="submit"
        form="link-form"
        disabled={linkBusy}
      >
        {linkBusy ? "Continuing…" : `Continue to ${linkTarget?.label ?? ""}`}
      </button>
    {/if}
  {/snippet}
</Modal>

<style>
  .lead {
    margin: 0 0 1rem;
  }
  .small {
    font-size: 0.85rem;
  }
  .methods-card {
    margin-bottom: 1.25rem;
  }
  .badge-pw {
    color: var(--ok);
  }
  .badge-provider {
    color: var(--acc);
  }
  select {
    width: 100%;
    padding: 0.55rem 0.7rem;
    font: inherit;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--ink);
  }
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
    /* Capped tighter now that the table carries an extra "Signed in via"
       column, so the row's actions stay on-screen (full UA in the title). */
    max-width: 220px;
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
