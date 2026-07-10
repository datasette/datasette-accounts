<script lang="ts">
  import type { CapabilitiesPageData } from "../../page_data/CapabilitiesPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import AdminNav from "../../lib/AdminNav.svelte";

  type Action = CapabilitiesPageData["actions"][number];
  type Grant = Action["grants"][number];
  type Group = CapabilitiesPageData["groups"][number];

  const pageData = loadPageData<CapabilitiesPageData>();

  let actions = $state<Action[]>(pageData.actions);
  const groups: Group[] = pageData.groups;
  const hasAcl: boolean = pageData.has_acl;
  let error = $state("");

  // Accounts for the actor picker (loaded from the existing admin list API).
  let accounts = $state<{ id: string; username: string }[]>([]);

  // One inline add-grant row open at a time, keyed by action name.
  let addOpen = $state<string | null>(null);
  let addType = $state("actor");
  let addActor = $state("");
  let addGroup = $state<number | "">("");

  $effect(() => {
    postJSON<{ users: { id: string; username: string }[] }>(
      "/-/admin/api/list",
      {},
    ).then(({ data }) => {
      accounts = (data.users || []).map((u) => ({ id: u.id, username: u.username }));
    });
  });

  const PUBLIC_LABELS: Record<string, string> = {
    everyone: "Everyone (public)",
    authenticated: "Any signed-in user",
    anonymous: "Anonymous visitors",
  };

  function principalOptionLabel(type: string): string {
    if (type === "actor") return "A specific account";
    if (type === "group") return "A group";
    return PUBLIC_LABELS[type] ?? type;
  }

  function grantLabel(g: Grant): string {
    if (g.principal_type === "actor")
      return "@" + (g.actor_username || g.actor_id || "unknown");
    if (g.principal_type === "group")
      return "Group: " + (g.group_name || "#" + g.group_id);
    return PUBLIC_LABELS[g.principal_type] ?? g.principal_type;
  }

  function grantKind(g: Grant): string {
    if (g.principal_type === "actor") return "account";
    if (g.principal_type === "group") return "group";
    return "public";
  }

  async function refresh() {
    const { data } = await postJSON<{ actions: Action[] }>(
      "/-/admin/api/capabilities/list",
      {},
    );
    if (data.actions) actions = data.actions;
  }

  function openAdd(a: Action) {
    error = "";
    addOpen = a.name;
    addType = a.offerable_principals[0] ?? "actor";
    addActor = accounts[0]?.id ?? "";
    addGroup = groups[0]?.id ?? "";
  }

  function cancelAdd() {
    addOpen = null;
  }

  async function submitAdd(a: Action) {
    error = "";
    const body: Record<string, unknown> = {
      action: a.name,
      principal_type: addType,
    };
    if (addType === "actor") {
      if (!addActor) {
        error = "Pick an account.";
        return;
      }
      body.actor_id = addActor;
    } else if (addType === "group") {
      if (addGroup === "") {
        error = "Pick a group.";
        return;
      }
      body.group_id = addGroup;
    }
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/admin/api/capabilities/grant",
      body,
    );
    if (!ok || !data.ok) {
      error = data.error || "Could not add grant.";
      return;
    }
    addOpen = null;
    await refresh();
  }

  async function revoke(g: Grant) {
    error = "";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/admin/api/capabilities/revoke",
      { id: g.id },
    );
    if (!ok || !data.ok) {
      error = data.error || "Could not revoke grant.";
      return;
    }
    await refresh();
  }
</script>

<div class="page">
  <header class="bar">
    <h1>Capabilities</h1>
  </header>
  <AdminNav current="capabilities" />

  <p class="page-intro">
    Grant instance-wide capabilities to accounts, groups, or everyone. These are
    global actions (like “create a paper”) that aren’t tied to one document.
    {#if hasAcl}
      Per-document sharing and group membership live in
      <a href="/-/acl/groups">Groups &amp; sharing</a>.
    {/if}
  </p>

  {#if error}<p class="msg msg-error">{error}</p>{/if}

  {#if actions.length === 0}
    <div class="card empty">
      <p>No grantable capabilities.</p>
      <p class="muted">
        Install a plugin that registers global actions, or set
        <code>grantable_actions</code> in this plugin’s configuration.
      </p>
    </div>
  {/if}

  <div class="stack">
    {#each actions as a (a.name)}
      <section class="card action">
        <div class="ahead">
          <div>
            <h2>{a.description || a.name}</h2>
            <code class="aname">{a.name}</code>
            {#if a.also_requires}
              <span class="requires" title="Datasette also requires this action">
                also requires <code>{a.also_requires}</code>
              </span>
            {/if}
          </div>
          <button class="btn btn-sm" onclick={() => openAdd(a)}>+ Grant</button>
        </div>

        {#if a.grants.length === 0 && a.config_grants.length === 0}
          <p class="none">No one has this capability yet.</p>
        {/if}

        {#if a.grants.length > 0}
          <ul class="grants">
            {#each a.grants as g (g.id)}
              <li class="grant {grantKind(g)}">
                <span class="label">{grantLabel(g)}</span>
                <button
                  class="chip-x"
                  aria-label="Revoke {grantLabel(g)}"
                  title="Revoke"
                  onclick={() => revoke(g)}>✕</button
                >
              </li>
            {/each}
          </ul>
        {/if}

        {#each a.config_grants as cg}
          <div class="config">
            <span class="config-tag">from datasette.yaml · read-only</span>
            <pre>{cg.allow_json}</pre>
          </div>
        {/each}

        {#if addOpen === a.name}
          <div class="addrow">
            <select bind:value={addType} aria-label="Principal type">
              {#each a.offerable_principals as p}
                <option value={p}>{principalOptionLabel(p)}</option>
              {/each}
            </select>
            {#if addType === "actor"}
              <select bind:value={addActor} aria-label="Account">
                {#each accounts as u}
                  <option value={u.id}>@{u.username}</option>
                {/each}
              </select>
            {:else if addType === "group"}
              <select bind:value={addGroup} aria-label="Group">
                {#each groups as gr}
                  <option value={gr.id}>{gr.name}</option>
                {/each}
              </select>
            {/if}
            <button class="btn-primary btn-sm" onclick={() => submitAdd(a)}>Grant</button>
            <button class="btn-sm" onclick={cancelAdd}>Cancel</button>
          </div>
        {/if}
      </section>
    {/each}
  </div>
</div>

<style>
  .bar h1 {
    margin: 0 0 0.75rem;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
  }
  .action {
    padding: 1rem 1.1rem;
  }
  .ahead {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
  }
  .ahead h2 {
    margin: 0;
    font-size: 1rem;
  }
  .aname {
    font-size: 0.78rem;
    color: var(--muted);
  }
  .requires {
    font-size: 0.78rem;
    color: var(--muted);
    margin-left: 0.5rem;
  }
  .none {
    color: var(--muted);
    font-size: 0.88rem;
    margin: 0.75rem 0 0;
  }
  .grants {
    list-style: none;
    margin: 0.75rem 0 0;
    padding: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }
  .grant {
    display: inline-flex;
    align-items: center;
    gap: 0.15rem;
    padding: 0.1rem 0.15rem 0.1rem 0.5rem;
    border-radius: 6px;
    font-size: 0.78rem;
    line-height: 1.5;
    border: 1px solid var(--border);
    background: var(--surface);
  }
  /* Per-kind tint: a faint background wash + matching border. */
  .grant.public {
    border-color: color-mix(in srgb, var(--acc) 35%, var(--border));
    background: color-mix(in srgb, var(--acc) 8%, var(--surface));
  }
  .grant.public .label {
    color: var(--acc-d, var(--acc));
  }
  .grant.group {
    border-color: color-mix(in srgb, var(--mauve) 35%, var(--border));
    background: color-mix(in srgb, var(--mauve) 8%, var(--surface));
  }
  .grant.group .label {
    color: var(--mauve);
  }
  .grant .label {
    font-weight: 500;
  }
  /* .chip-x (the compact ✕) is styled globally in theme.css so it beats the
     base `#app-root button` style — a scoped rule here can't win on specificity. */
  .config {
    margin-top: 0.85rem;
  }
  .config-tag {
    display: inline-block;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }
  .config pre {
    margin: 0;
    padding: 0.6rem 0.75rem;
    background: var(--hover);
    border: 1px dashed var(--border);
    border-radius: 8px;
    font-size: 0.8rem;
    overflow-x: auto;
  }
  .addrow {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.95rem;
    padding-top: 0.85rem;
    border-top: 1px solid var(--border);
  }
  .addrow select {
    padding: 0.35rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg);
    color: var(--ink);
    font-size: 0.85rem;
  }
  .empty {
    padding: 1.5rem;
    text-align: center;
  }
  .empty .muted {
    color: var(--muted);
    font-size: 0.88rem;
  }
</style>
