<script lang="ts">
  import type { AdminAuditPageData } from "../../page_data/AdminAuditPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import AdminNav from "../../lib/AdminNav.svelte";

  type Entry = AdminAuditPageData["entries"][number];
  const pageData = loadPageData<AdminAuditPageData>();

  let entries = $state<Entry[]>(pageData.entries);
  let username = $state(pageData.filter_username ?? "");
  let operation = $state(pageData.filter_operation ?? "");
  let loading = $state(false);
  let error = $state("");

  // Populated from the data itself (distinct + sorted), so it stays truthful
  // even for operations no current release writes.
  const operations = pageData.operations;

  // "reset-password" → "Reset password".
  function humanize(op: string): string {
    const words = op.replaceAll("-", " ");
    return words.charAt(0).toUpperCase() + words.slice(1);
  }

  // Badge tone per operation family — destructive red, additive green,
  // everything else neutral (mirrors the login-attempts result badges).
  const DESTRUCTIVE = new Set([
    "delete",
    "disable",
    "revoke-session",
    "revoke-capability",
    "logout-everywhere",
  ]);
  const ADDITIVE = new Set(["create", "enable", "unlock", "grant-capability"]);
  function badgeClass(op: string): string {
    if (DESTRUCTIVE.has(op)) return "badge fail";
    if (ADDITIVE.has(op)) return "badge ok";
    return "badge neutral";
  }

  // Actor/target cells: resolved username when the account still exists, else
  // the raw id ("root" and "cli:…" are meaningful as-is; a deleted target
  // falls back to its id, with the username often recoverable from detail).
  function principal(name: string | null | undefined, id: string | null | undefined): string {
    return name || id || "—";
  }

  // The JSON detail rendered as key: value chips; unparseable → raw text.
  function detailChips(detail: string | null | undefined): [string, string][] | null {
    if (!detail) return null;
    try {
      const parsed = JSON.parse(detail);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return null;
      }
      return Object.entries(parsed).map(([k, v]) => [k, String(v)]);
    } catch {
      return null;
    }
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
    const { ok, data } = await postJSON<{ ok: boolean; error?: string; entries?: Entry[] }>(
      "/-/admin/api/audit",
      { username: username.trim(), operation },
    );
    loading = false;
    if (!ok || !data.ok) {
      error = data.error || "Could not load the audit trail";
      return;
    }
    entries = data.entries ?? [];
  }

  function clear() {
    username = "";
    operation = "";
    apply();
  }

  const hasFilter = $derived(username.trim() !== "" || operation !== "");
</script>

<div class="page">
  <header class="bar">
    <h1>Audit trail</h1>
  </header>
  <AdminNav current="audit" />

  <p class="intro">
    Every admin action — who created, disabled, reset, granted, and deleted
    what — most recent first. Filter by the exact target username or by
    operation.
  </p>

  <form class="filters" onsubmit={apply}>
    <label class="field">
      <span>Target username</span>
      <input class="input" bind:value={username} placeholder="Any account" />
    </label>
    <label class="field">
      <span>Operation</span>
      <select class="input" bind:value={operation} onchange={apply}>
        <option value="">All operations</option>
        {#each operations as op (op)}
          <option value={op}>{humanize(op)}</option>
        {/each}
      </select>
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
          <th>Operation</th>
          <th>Actor</th>
          <th>Target</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {#each entries as entry (entry.id)}
          {@const chips = detailChips(entry.detail)}
          <tr>
            <td class="time">{fmtDate(entry.timestamp)}</td>
            <td><span class={badgeClass(entry.operation)}>{humanize(entry.operation)}</span></td>
            <td class="uname">{principal(entry.actor_username, entry.actor_id)}</td>
            <td class="uname">{principal(entry.target_username, entry.target_id)}</td>
            <td class="detail">
              {#if chips}
                {#each chips as [key, value] (key)}
                  <span class="chip"><span class="chip-key">{key}:</span> {value}</span>
                {/each}
              {:else}
                {entry.detail ?? "—"}
              {/if}
            </td>
          </tr>
        {/each}
        {#if entries.length === 0}
          <tr><td colspan="5" class="empty">No audit entries match these filters.</td></tr>
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
  .detail {
    color: var(--muted);
    max-width: 26rem;
    white-space: normal;
  }
  .empty {
    text-align: center;
    color: var(--muted);
    padding: 1.5rem;
  }

  /* Operation badges — additive green, destructive red, neutral otherwise
   * (same palette as the login-attempts result badges). */
  .badge.ok {
    color: var(--ok);
  }
  .badge.fail {
    color: var(--danger);
  }
  .badge.neutral {
    color: var(--muted);
  }

  /* Detail key:value chips */
  .chip {
    display: inline-block;
    background: var(--acc-l);
    border-radius: 4px;
    padding: 0.1rem 0.45rem;
    margin: 0.1rem 0.25rem 0.1rem 0;
    font-size: 0.8rem;
    color: var(--ink);
  }
  .chip-key {
    color: var(--muted);
  }
</style>
