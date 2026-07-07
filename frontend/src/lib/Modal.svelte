<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    open = $bindable(false),
    title = "",
    children,
    footer,
    onclose,
  }: {
    open?: boolean;
    title?: string;
    children?: Snippet;
    footer?: Snippet;
    onclose?: () => void;
  } = $props();

  let dialog = $state<HTMLDialogElement>();

  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    else if (!open && dialog.open) dialog.close();
  });

  function handleClose() {
    open = false;
    onclose?.();
  }
</script>

<dialog bind:this={dialog} class="acc-dialog" onclose={handleClose}>
  <div class="head">
    <h2>{title}</h2>
    <button type="button" class="btn-ghost btn-sm x" onclick={() => (open = false)} aria-label="Close"
      >✕</button
    >
  </div>
  <div class="body">
    {@render children?.()}
  </div>
  {#if footer}
    <div class="foot">
      {@render footer()}
    </div>
  {/if}
</dialog>

<style>
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border);
  }
  .head h2 {
    margin: 0;
    font-size: 1.05rem;
  }
  .x {
    color: var(--muted);
    line-height: 1;
  }
  .body {
    padding: 1.25rem;
  }
  .foot {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
    padding: 0.9rem 1.25rem;
    border-top: 1px solid var(--border);
    background: var(--bg);
    border-radius: 0 0 12px 12px;
  }
</style>
