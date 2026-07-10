<script lang="ts">
  import type { ConfigPageData } from "../../page_data/ConfigPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import AdminNav from "../../lib/AdminNav.svelte";

  type Slot = ConfigPageData["slots"][number];
  const pageData = loadPageData<ConfigPageData>();

  let error = $state("");

  // --- Self-registration (see plans/self-registration): optimistic flip
  // with rollback on error, so the switch state always chases the server's.
  let regEnabled = $state(Boolean(pageData.registration_enabled));
  let regBusy = $state(false);

  async function toggleRegistration() {
    const next = !regEnabled;
    regEnabled = next; // optimistic
    regBusy = true;
    error = "";
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/admin/api/set-registration",
      { enabled: next },
    );
    regBusy = false;
    if (!ok || !data.ok) {
      regEnabled = !next; // rollback
      error = data.error || "Could not update self-registration";
    }
  }

  // --- Site messages. Per-slot editing state: `draft` is the textarea value,
  // `saved` is the last persisted body used to compute the dirty flag +
  // enable the Save button.
  type Edit = Slot & { draft: string; saved: string; busy: boolean; note: string; error: string };
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
    const { ok, data } = await postJSON<{ ok: boolean; error?: string; body?: string }>(
      "/-/admin/api/messages/set",
      { key: slot.key, body: slot.draft },
    );
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

  <section class="section" aria-labelledby="reg-heading">
    <h2 id="reg-heading">Self-registration</h2>
    <div class="card reg-card">
      <div class="reg-copy">
        <span class="reg-label" id="reg-label">Allow anyone to request an account</span>
        <p class="reg-note">
          When on, visitors can request an account at <code>/-/register</code>.
          New requests wait on the Accounts page for an admin's approval.
        </p>
      </div>
      <button
        class="switch"
        class:on={regEnabled}
        role="switch"
        aria-checked={regEnabled}
        aria-labelledby="reg-label"
        disabled={regBusy}
        onclick={toggleRegistration}
      >
        <span class="knob" aria-hidden="true"></span>
        <span class="state">{regEnabled ? "On" : "Off"}</span>
      </button>
    </div>
  </section>

  <section class="section" aria-labelledby="messages-heading">
    <h2 id="messages-heading">Messages</h2>
    <p class="page-intro">
      Optional notes shown to people using this Datasette. Leave a message blank to
      hide it. Basic HTML is allowed — e.g.
      <code>&lt;a href="mailto:help@example.com"&gt;email us&lt;/a&gt;</code>.
    </p>
    <div class="slots">
      {#each slots as slot (slot.key)}
        <section class="card">
          <div class="head">
            <h3>{slot.label}</h3>
            {#if !slot.draft.trim()}<span class="badge-unset">Not set</span>{/if}
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
              <button class="btn-sm" onclick={() => reset(slot)} disabled={slot.busy}>Reset</button>
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

  /* Self-registration switch — an explicit On/Off control with the state
     spelled out. */
  .reg-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    padding: 1rem 1.25rem;
  }
  .reg-label {
    font-weight: 600;
    font-size: 0.95rem;
  }
  .reg-note {
    margin: 0.25rem 0 0;
    color: var(--muted);
    font-size: 0.85rem;
    max-width: 36rem;
  }
  .reg-note code {
    font-size: 0.8rem;
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
