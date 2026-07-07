<script lang="ts">
  import type { LoginPageData } from "../../page_data/LoginPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<LoginPageData>();

  let username = $state("");
  let password = $state("");
  let error = $state("");
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = "";
    const { ok, data } = await postJSON<{
      ok: boolean;
      redirect?: string;
      error?: string;
    }>("/-/login/api/authenticate", {
      username,
      password,
      next: pageData.next,
    });
    busy = false;
    if (ok && data.ok) {
      window.location.href = data.redirect || "/";
    } else {
      error = data.error || "Login failed";
    }
  }
</script>

<div class="page narrow">
  <h1>Log in</h1>
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
        required
      />
    </label>
    <label class="field">
      <span>Password</span>
      <input
        id="current-password"
        name="password"
        type="password"
        bind:value={password}
        autocomplete="current-password"
        required
      />
    </label>
    <button type="submit" class="btn-primary block" disabled={busy}>
      {busy ? "Signing in…" : "Log in"}
    </button>
  </form>
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
