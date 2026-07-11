<script lang="ts">
  import type { ConfigPageData } from "../../page_data/ConfigPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import AdminNav from "../../lib/AdminNav.svelte";

  type Slot = ConfigPageData["slots"][number];
  type Provider = NonNullable<ConfigPageData["providers"]>[number];
  const pageData = loadPageData<ConfigPageData>();

  let error = $state("");

  // --- Sign-in providers (design §9). Enabled + signups are runtime settings;
  // both toggles flip optimistically and roll back if the server refuses (e.g.
  // the last-provider guard). The write takes effect on the next request.
  let providers = $state<Provider[]>(pageData.providers ?? []);
  let providerError = $state("");

  const SIGNUPS = [
    { value: "off", label: "off" },
    { value: "approval", label: "require approval" },
    { value: "auto", label: "auto-activate" },
  ];

  async function toggleProvider(p: Provider) {
    const prev = p.enabled;
    p.enabled = !prev; // optimistic
    providerError = "";
    const { ok, data } = await postJSON<{
      ok: boolean;
      enabled?: boolean;
      error?: string;
    }>("/-/admin/api/set-provider", { key: p.key, enabled: p.enabled });
    if (!ok || !data.ok) {
      p.enabled = prev; // rollback
      // Surface the last-provider 400 (and any other refusal) verbatim.
      providerError = data.error || "Could not update provider.";
    } else if (typeof data.enabled === "boolean") {
      p.enabled = data.enabled;
    }
  }

  async function changeSignups(p: Provider, value: string) {
    const prev = p.signups;
    p.signups = value; // optimistic
    providerError = "";
    const { ok, data } = await postJSON<{
      ok: boolean;
      signups?: string;
      error?: string;
    }>("/-/admin/api/set-provider", { key: p.key, signups: value });
    if (!ok || !data.ok) {
      p.signups = prev; // rollback
      providerError = data.error || "Could not update sign-ups.";
    } else if (typeof data.signups === "string") {
      p.signups = data.signups;
    }
  }

  // --- Site messages. Per-slot editing state: `draft` is the textarea value,
  // `saved` is the last persisted body used to compute the dirty flag +
  // enable the Save button.
  type Edit = Slot & {
    draft: string;
    saved: string;
    busy: boolean;
    note: string;
    error: string;
  };
  let slots = $state<Edit[]>(
    pageData.slots.map((s) => ({
      ...s,
      draft: s.body ?? "",
      saved: s.body ?? "",
      busy: false,
      note: "",
      error: "",
    })),
  );

  async function save(slot: Edit) {
    slot.error = "";
    slot.note = "";
    slot.busy = true;
    const { ok, data } = await postJSON<{
      ok: boolean;
      error?: string;
      body?: string;
    }>("/-/admin/api/messages/set", { key: slot.key, body: slot.draft });
    slot.busy = false;
    if (!ok || !data.ok) {
      slot.error = data.error || "Could not save message";
      return;
    }
    const body = data.body ?? "";
    slot.saved = body;
    slot.draft = body;
    slot.note = body ? "Saved" : "Cleared";
  }

  function reset(slot: Edit) {
    slot.draft = slot.saved;
    slot.note = "";
    slot.error = "";
  }
</script>

<div class="page">
  <header class="bar">
    <h1>Configuration</h1>
  </header>
  <AdminNav current="config" />

  {#if error}<p class="msg msg-error">{error}</p>{/if}

  <section class="section" aria-labelledby="providers-heading">
    <div class="section-head">
      <h2 id="providers-heading">Sign-in providers</h2>
      <span class="section-sub">runtime settings · audited</span>
    </div>
    <p class="page-intro">
      One row per installed provider. Turning <b>New sign-ups</b> to
      <b>require approval</b> for <code>password</code> opens
      <code>/-/register</code>; new requests wait on the Accounts page for an
      admin's approval. <b>auto-activate</b> signs new people straight in — for trusted
      identity providers only.
    </p>
    {#if providerError}<p class="msg msg-error">{providerError}</p>{/if}
    <div class="card table-wrap">
      <table>
        <thead>
          <tr>
            <th>Provider</th>
            <th>Source</th>
            <th>Enabled</th>
            <th>New sign-ups</th>
            <th>Linked</th>
          </tr>
        </thead>
        <tbody>
          {#each providers as p (p.key)}
            <tr>
              <td>
                <span class="pname">{p.label}</span>
                <code class="chip-key">{p.key}</code>
                {#if p.builtin}<span class="chip">built-in</span>{/if}
              </td>
              <td class="muted src">{p.source}</td>
              <td>
                <button
                  class="switch"
                  class:on={p.enabled}
                  role="switch"
                  aria-checked={p.enabled}
                  aria-label="Enable {p.label}"
                  onclick={() => toggleProvider(p)}
                >
                  <span class="knob" aria-hidden="true"></span>
                  <span class="state">{p.enabled ? "On" : "Off"}</span>
                </button>
              </td>
              <td>
                <div class="signups">
                  <select
                    value={p.signups}
                    aria-label="New sign-ups for {p.label}"
                    onchange={(e) => changeSignups(p, e.currentTarget.value)}
                  >
                    {#each SIGNUPS as s (s.value)}
                      <option value={s.value}>{s.label}</option>
                    {/each}
                  </select>
                  {#if p.signups === "auto"}
                    <span class="chip warn">trusted IdP only</span>
                  {/if}
                </div>
              </td>
              <td class="muted">
                {#if p.builtin}
                  <span class="never">—</span>
                {:else}
                  {p.linked_count} linked
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="break-glass">
      Locked out? An operator can always run
      <code>datasette accounts enable-provider password</code> on the server.
    </p>
  </section>

  <section class="section" aria-labelledby="messages-heading">
    <h2 id="messages-heading">Messages</h2>
    <p class="page-intro">
      Optional notes shown to people using this Datasette. Leave a message blank
      to hide it. Basic HTML is allowed — e.g.
      <code>&lt;a href="mailto:help@example.com"&gt;email us&lt;/a&gt;</code>.
    </p>
    <div class="slots">
      {#each slots as slot (slot.key)}
        <section class="card">
          <div class="head">
            <h3>{slot.label}</h3>
            {#if !slot.draft.trim()}<span class="badge-unset">Not set</span
              >{/if}
          </div>
          <p class="desc">{slot.description}</p>
          {#if slot.error}<p class="msg msg-error">{slot.error}</p>{/if}
          <textarea
            bind:value={slot.draft}
            rows="3"
            placeholder="No message"
            aria-label={slot.label}
          ></textarea>
          <div class="foot">
            <div class="status" aria-live="polite">
              {#if slot.note}<span class="note">{slot.note}</span>{/if}
            </div>
            {#if slot.draft !== slot.saved}
              <button
                class="btn-sm"
                onclick={() => reset(slot)}
                disabled={slot.busy}>Reset</button
              >
            {/if}
            <button
              class="btn-primary btn-sm"
              onclick={() => save(slot)}
              disabled={slot.busy || slot.draft === slot.saved}
            >
              {slot.busy ? "Saving…" : "Save"}
            </button>
          </div>
        </section>
      {/each}
    </div>
  </section>
</div>

<style>
  .bar {
    margin-bottom: 1rem;
  }
  .bar h1 {
    margin: 0;
  }
  .section {
    margin-bottom: 2rem;
  }
  .section h2 {
    font-size: 1.15rem;
    margin: 0 0 0.6rem;
  }
  .section-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 1rem;
  }
  .section-head h2 {
    margin: 0;
  }
  .section-sub {
    color: var(--muted);
    font-size: 0.8rem;
  }

  /* Sign-in providers table */
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
  .pname {
    font-weight: 600;
  }
  .src {
    font-size: 0.85rem;
  }
  .muted {
    color: var(--muted);
  }
  .never {
    color: var(--muted);
  }
  .chip-key {
    font-size: 0.78rem;
    background: var(--hover);
    padding: 0.05rem 0.4rem;
    border-radius: 5px;
    margin: 0 0.25rem;
  }
  .chip {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 0.05rem 0.5rem;
    border-radius: 999px;
    background: var(--hover);
    color: var(--muted);
  }
  .chip.warn {
    background: #fdece1;
    color: var(--warn);
  }
  .signups {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  select {
    font: inherit;
    font-size: 0.85rem;
    padding: 0.25rem 0.4rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface);
    color: var(--ink);
  }
  .break-glass {
    margin: 0.9rem 0 0;
    color: var(--muted);
    font-size: 0.82rem;
  }
  .break-glass code {
    font-size: 0.78rem;
  }
  .switch {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.25rem 0.7rem 0.25rem 0.3rem;
    background: transparent;
    cursor: pointer;
    flex-shrink: 0;
  }
  .switch:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .switch .knob {
    position: relative;
    width: 1.7rem;
    height: 0.95rem;
    border-radius: 999px;
    background: var(--border);
    transition: background 0.15s ease;
  }
  .switch .knob::after {
    content: "";
    position: absolute;
    top: 1px;
    left: 1px;
    width: calc(0.95rem - 2px);
    height: calc(0.95rem - 2px);
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
    transition: transform 0.15s ease;
  }
  .switch.on .knob {
    background: var(--ok, #16a34a);
  }
  .switch.on .knob::after {
    transform: translateX(0.75rem);
  }
  .switch .state {
    font-size: 0.8rem;
    font-weight: 600;
  }

  .slots {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.25rem;
  }
  .head h3 {
    margin: 0;
    font-size: 1.05rem;
  }
  .badge-unset {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.05rem 0.5rem;
  }
  .desc {
    color: var(--muted);
    font-size: 0.88rem;
    margin: 0 0 0.75rem;
    max-width: 42rem;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
    font: inherit;
    padding: 0.55rem 0.7rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    resize: vertical;
  }
  .foot {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }
  .status {
    flex: 1;
    font-size: 0.85rem;
  }
  .note {
    color: var(--acc);
    font-weight: 600;
  }
</style>
