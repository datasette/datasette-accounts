<script lang="ts">
  import type { AdminPageData } from "../../page_data/AdminPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  type User = AdminPageData["users"][number];
  const pageData = loadPageData<AdminPageData>();

  let users = $state<User[]>(pageData.users);
  let newUsername = $state("");
  let newPassword = $state("");
  let newIsAdmin = $state(false);
  let error = $state("");

  // session drawer
  let openSessions = $state<string | null>(null);
  let sessions = $state<
    { token_sha256: string; last_seen_at: string; ip: string | null; user_agent: string | null }[]
  >([]);

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

  async function create(e: Event) {
    e.preventDefault();
    const ok = await op("/-/admin/api/create", {
      username: newUsername,
      password: newPassword,
      is_admin: newIsAdmin,
    });
    if (ok) {
      newUsername = "";
      newPassword = "";
      newIsAdmin = false;
      await refresh();
    }
  }

  async function toggle(u: User, path: string) {
    if (await op(path, { id: u.id })) await refresh();
  }

  async function del(u: User) {
    if (!confirm(`Delete ${u.username}?`)) return;
    if (await op("/-/admin/api/delete", { id: u.id })) await refresh();
  }

  async function reset(u: User) {
    const pw = prompt(`New password for ${u.username}:`);
    if (!pw) return;
    await op("/-/admin/api/reset-password", { id: u.id, password: pw });
  }

  async function showSessions(u: User) {
    if (openSessions === u.id) {
      openSessions = null;
      return;
    }
    const { data } = await postJSON<{ sessions: typeof sessions }>(
      "/-/admin/api/list-sessions",
      { id: u.id },
    );
    sessions = data.sessions || [];
    openSessions = u.id;
  }

  async function revoke(u: User, token: string) {
    await op("/-/admin/api/revoke-session", { id: u.id, token_sha256: token });
    await showSessions(u);
    openSessions = u.id;
  }
</script>

<h1>Accounts</h1>

<form onsubmit={create} class="create">
  <label>New username <input bind:value={newUsername} required /></label>
  <label>Initial password <input type="password" bind:value={newPassword} required /></label>
  <label><input type="checkbox" bind:checked={newIsAdmin} /> Admin</label>
  <button type="submit">Create account</button>
</form>
{#if error}<p class="error">{error}</p>{/if}

<table>
  <thead>
    <tr><th>Username</th><th>Admin</th><th>Status</th><th>Lock</th><th>Actions</th></tr>
  </thead>
  <tbody>
    {#each users as u (u.id)}
      <tr>
        <td>{u.username}</td>
        <td>{u.is_admin ? "✓" : ""}</td>
        <td>{u.disabled ? "disabled" : "active"}</td>
        <td>{u.locked ? "locked" : ""}</td>
        <td class="actions">
          <button onclick={() => toggle(u, "/-/admin/api/toggle-admin")}>
            {u.is_admin ? "Revoke admin" : "Make admin"}
          </button>
          {#if u.disabled}
            <button onclick={() => toggle(u, "/-/admin/api/enable")}>Enable</button>
          {:else}
            <button onclick={() => toggle(u, "/-/admin/api/disable")}>Disable</button>
          {/if}
          {#if u.locked}
            <button onclick={() => toggle(u, "/-/admin/api/unlock")}>Unlock</button>
          {/if}
          <button onclick={() => reset(u)}>Reset password</button>
          <button onclick={() => showSessions(u)}>Sessions</button>
          <button onclick={() => del(u)}>Delete</button>
        </td>
      </tr>
      {#if openSessions === u.id}
        <tr>
          <td colspan="5">
            {#if sessions.length === 0}
              <em>No active sessions.</em>
            {:else}
              <ul>
                {#each sessions as s (s.token_sha256)}
                  <li>
                    {s.last_seen_at} — {s.ip ?? "?"} — {s.user_agent ?? "?"}
                    <button onclick={() => revoke(u, s.token_sha256)}>Revoke</button>
                  </li>
                {/each}
              </ul>
            {/if}
          </td>
        </tr>
      {/if}
    {/each}
  </tbody>
</table>
