<script lang="ts">
  import type { RegisterPageData } from "../../page_data/RegisterPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<RegisterPageData>();

  let username = $state("");
  let password = $state("");
  let confirmPassword = $state("");
  let error = $state("");
  let busy = $state(false);
  let submitted = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    error = "";
    if (password !== confirmPassword) {
      error = "Passwords do not match";
      return;
    }
    busy = true;
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/register/api/submit",
      { username, password },
    );
    busy = false;
    if (ok && data.ok) {
      submitted = true;
    } else {
      error = data.error || "Registration failed";
    }
  }
</script>

<div class="page narrow">
  <h1>Request an account</h1>
  {#if submitted}
    <div class="card">
      <p class="msg msg-ok">
        Your request was received — you'll be able to sign in once an
        administrator approves it.
      </p>
    </div>
  {:else}
    <form class="card" onsubmit={submit}>
      {#if error}<p class="msg msg-error">{error}</p>{/if}
      <label class="field">
        <span>Username</span>
        <input
          id="username"
          name="username"
          type="text"
          bind:value={username}
          autocomplete="username"
          autocapitalize="none"
          autocorrect="off"
          spellcheck="false"
          minlength="3"
          maxlength="64"
          required
        />
        <span class="hint">
          3-64 characters: letters, numbers, ".", "_", "-", starting with a
          letter or number.
        </span>
      </label>
      <label class="field">
        <span>Password</span>
        <input
          id="new-password"
          name="password"
          type="password"
          bind:value={password}
          autocomplete="new-password"
          required
        />
      </label>
      <label class="field">
        <span>Confirm password</span>
        <input
          id="confirm-password"
          name="confirm-password"
          type="password"
          bind:value={confirmPassword}
          autocomplete="new-password"
          required
        />
      </label>
      <button type="submit" class="btn-primary block" disabled={busy}>
        {busy ? "Submitting…" : "Request an account"}
      </button>
    </form>
  {/if}
  {#if pageData.help?.trim()}
    <!-- Admin-authored HTML (trusted; only admins can set it). -->
    <p class="help">{@html pageData.help}</p>
  {/if}
</div>

<style>
  .block {
    width: 100%;
    justify-content: center;
    padding-top: 0.6rem;
    padding-bottom: 0.6rem;
  }
  .hint {
    color: var(--muted);
    font-size: 0.8rem;
  }
  .help {
    margin: 1rem 0 0;
    padding: 0.75rem 1rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--card, transparent);
    color: var(--muted);
    font-size: 0.88rem;
    line-height: 1.5;
  }
</style>
