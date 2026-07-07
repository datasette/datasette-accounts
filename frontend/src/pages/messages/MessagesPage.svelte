<script lang="ts">
  import type { MessagesPageData } from "../../page_data/MessagesPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";
  import AdminNav from "../../lib/AdminNav.svelte";

  type Slot = MessagesPageData["slots"][number];
  const pageData = loadPageData<MessagesPageData>();

  // Per-slot editing state: `draft` is the textarea value, `saved` is the last
  // persisted body used to compute the dirty flag + enable the Save button.
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
    <h1>Messages</h1>
  </header>
  <AdminNav current="messages" />

  <p class="intro">
    Optional notes shown to people using this Datasette. Leave a message blank to
    hide it. Basic HTML is allowed — e.g.
    <code>&lt;a href="mailto:help@example.com"&gt;email us&lt;/a&gt;</code>.
  </p>

  <div class="slots">
    {#each slots as slot (slot.key)}
      <section class="card">
        <div class="head">
          <h2>{slot.label}</h2>
          {#if !slot.draft.trim()}<span class="badge">Not set</span>{/if}
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
    max-width: 40rem;
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
  .head h2 {
    margin: 0;
    font-size: 1.05rem;
  }
  .badge {
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
