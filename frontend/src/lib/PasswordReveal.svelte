<script lang="ts">
  // Shows a server-generated password once, with copy affordances. The plaintext
  // is never stored server-side, so this is the only chance to capture it — hence
  // the "won't be shown again" warning and the ready-to-paste message block.
  let { username, password }: { username?: string; password: string } = $props();

  const CLIPBOARD =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M10 1.5a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5zm-5 0A1.5 1.5 0 0 1 6.5 0h3A1.5 1.5 0 0 1 11 1.5v1A1.5 1.5 0 0 1 9.5 4h-3A1.5 1.5 0 0 1 5 2.5zm-2 0h1v1A2.5 2.5 0 0 0 6.5 5h3A2.5 2.5 0 0 0 12 2.5v-1h1a2 2 0 0 1 2 2V14a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3.5a2 2 0 0 1 2-2"/></svg>';
  const CHECK =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0"/></svg>';

  // Ready-to-send block for a Slack DM / email to the user: a short preamble
  // with the login URL, then the credentials. Both create and reset force a
  // password change, so the prompt-to-change note is always accurate here.
  const loginUrl = `${window.location.origin}/-/login`;
  const creds = $derived(
    username ? `Username: ${username}\nPassword: ${password}` : `Password: ${password}`,
  );
  const message = $derived(
    `Log in to Datasette at ${loginUrl} with the following credentials. ` +
      `You'll be prompted to change your password on first sign-in.\n\n${creds}`,
  );
  const messageRows = $derived(message.split("\n").length);

  // Which item was last copied, so we can swap that one button to a check.
  let copied = $state<"" | "username" | "password" | "message">("");

  async function copy(text: string, which: typeof copied, fallback?: HTMLElement) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API unavailable (insecure context / denied) — select the
      // source text so the admin can copy manually.
      if (fallback instanceof HTMLInputElement || fallback instanceof HTMLTextAreaElement) {
        fallback.select();
      } else if (fallback) {
        const range = document.createRange();
        range.selectNodeContents(fallback);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
    }
    copied = which;
  }

  let userVal = $state<HTMLElement>();
  let pwVal = $state<HTMLElement>();
  let msgField = $state<HTMLTextAreaElement>();
</script>

<div class="reveal">
  <p class="warn">
    This password is shown <strong>only once</strong>. Copy it now and share it securely —
    it cannot be retrieved later.
  </p>

  <div class="creds">
    {#if username}
      <div class="crow">
        <span class="clabel">Username</span>
        <code class="cval mono" bind:this={userVal}>{username}</code>
        <button
          type="button"
          class="icon-btn"
          aria-label="Copy username"
          onclick={() => copy(username, "username", userVal)}>{@html copied === "username" ? CHECK : CLIPBOARD}</button
        >
      </div>
    {/if}
    <div class="crow">
      <span class="clabel">Password</span>
      <code class="cval mono" bind:this={pwVal}>{password}</code>
      <button
        type="button"
        class="icon-btn"
        aria-label="Copy password"
        onclick={() => copy(password, "password", pwVal)}>{@html copied === "password" ? CHECK : CLIPBOARD}</button
      >
    </div>
  </div>

  <label class="field">
    <span>Message to send</span>
    <textarea
      class="input mono msg"
      readonly
      rows={messageRows}
      value={message}
      bind:this={msgField}
      onfocus={() => msgField?.select()}
    ></textarea>
  </label>
  <button type="button" class="btn-sm" onclick={() => copy(message, "message", msgField)}>
    {copied === "message" ? "Copied ✓" : "Copy message"}
  </button>
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
  .creds {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin-bottom: 1.25rem;
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
    flex: 0 0 4.5rem;
    font-weight: 600;
    font-size: 0.8rem;
    color: var(--muted);
  }
  .cval {
    flex: 1 1 auto;
    word-break: break-all;
    font-size: 0.95rem;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    letter-spacing: 0.02em;
  }
  .msg {
    resize: none;
    line-height: 1.5;
  }
</style>
