<script lang="ts">
  // Shows a one-time set-password URL once, with a copy affordance. The raw
  // token is never stored server-side (only its hash), so this is the only
  // chance to capture the link — same treatment as the generated password.
  let { url }: { url: string } = $props();

  const CLIPBOARD =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M10 1.5a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5zm-5 0A1.5 1.5 0 0 1 6.5 0h3A1.5 1.5 0 0 1 11 1.5v1A1.5 1.5 0 0 1 9.5 4h-3A1.5 1.5 0 0 1 5 2.5zm-2 0h1v1A2.5 2.5 0 0 0 6.5 5h3A2.5 2.5 0 0 0 12 2.5v-1h1a2 2 0 0 1 2 2V14a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3.5a2 2 0 0 1 2-2"/></svg>';
  const CHECK =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0"/></svg>';

  let copied = $state(false);
  let urlVal = $state<HTMLElement>();

  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // Clipboard API unavailable (insecure context / denied) — select the
      // text so the admin can copy manually.
      if (urlVal) {
        const range = document.createRange();
        range.selectNodeContents(urlVal);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
    }
    copied = true;
  }
</script>

<div class="reveal">
  <p class="warn">
    This link is shown <strong>only once</strong> and works once. Copy it now and send it to the
    user securely — it cannot be retrieved later.
  </p>
  <div class="crow">
    <span class="clabel">Link</span>
    <code class="cval mono" bind:this={urlVal}>{url}</code>
    <button type="button" class="icon-btn" aria-label="Copy link" onclick={copy}
      >{@html copied ? CHECK : CLIPBOARD}</button
    >
  </div>
</div>

<style>
  .warn {
    margin: 0 0 1rem;
    padding: 0.6rem 0.75rem;
    border-radius: 6px;
    background: var(--acc-l);
    color: var(--acc-d);
    font-size: 0.85rem;
  }
  .crow {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.4rem 0.3rem 0.4rem 0.6rem;
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .clabel {
    flex: 0 0 3rem;
    font-weight: 600;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .cval {
    flex: 1 1 auto;
    word-break: break-all;
    font-size: 0.85rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    letter-spacing: 0.02em;
  }
</style>
