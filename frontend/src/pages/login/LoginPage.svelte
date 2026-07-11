<script lang="ts">
  import type { LoginPageData } from "../../page_data/LoginPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<LoginPageData>();
  const providers = pageData.providers ?? [];
  const passwordEnabled = pageData.password_enabled !== false;

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
  <div class="card">
    {#if passwordEnabled}
      <!-- The password form renders only while the built-in `password`
           provider is enabled (design §9); an SSO-only instance shows the
           provider buttons alone. -->
      <form onsubmit={submit}>
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
    {/if}

    {#if providers.length > 0}
      <!-- Divider only when both the form and the buttons are present. -->
      {#if passwordEnabled}<div class="divider"><span>or</span></div>{/if}
      <!-- Redirect-based flow: a full-page navigation, never a fetch. The
           validated `next` is already baked into start_url. -->
      {#each providers as p (p.key)}
        <a class="provider-btn" href={p.start_url}>Continue with {p.label}</a>
      {/each}
    {/if}
  </div>

  {#if passwordEnabled && pageData.allow_register}
    <!-- Only while the admin-controlled self-registration toggle is on (and
         password sign-ins are possible at all). -->
    <p class="register-link">
      No account? <a href="/-/register">Request an account</a>
    </p>
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
  /* "or" rule between the password form and the provider buttons. */
  .divider {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 1.2rem 0 0.9rem;
    color: var(--muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .divider::before,
  .divider::after {
    content: "";
    flex: 1;
    border-top: 1px solid var(--border);
  }
  /* Fixed-style provider button — no per-provider colour/icon in v1 (D10). */
  .provider-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    box-sizing: border-box;
    margin-top: 0.6rem;
    padding: 0.6rem 0.9rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--card, transparent);
    color: var(--ink);
    font-weight: 600;
    text-decoration: none;
  }
  .provider-btn:hover {
    border-color: var(--acc);
    color: var(--acc-d);
  }
  .register-link {
    margin: 0.9rem 0 0;
    text-align: center;
    font-size: 0.88rem;
    color: var(--muted);
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
