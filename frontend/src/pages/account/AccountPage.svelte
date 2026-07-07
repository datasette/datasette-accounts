<script lang="ts">
  import type { AccountPageData } from "../../page_data/AccountPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<AccountPageData>();

  let current = $state("");
  let next = $state("");
  let message = $state("");
  let error = $state("");
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    error = "";
    message = "";
    const body: Record<string, unknown> = { new_password: next };
    // First-login forced change doesn't ask for the current password again.
    if (!pageData.must_change_password) body.current_password = current;
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/account/api/change-password",
      body,
    );
    busy = false;
    if (ok && data.ok) {
      message = "Password changed.";
      setTimeout(() => (window.location.href = "/"), 800);
    } else {
      error = data.error || "Failed";
    }
  }
</script>

<div class="page narrow">
  <h1>Your account</h1>
  <p class="who">Signed in as <strong class="me">{pageData.username}</strong></p>

  {#if pageData.must_change_password}
    <p class="msg msg-error">Set a new password before continuing.</p>
  {/if}

  <form class="card" onsubmit={submit}>
    <h2>Change password</h2>
    {#if message}<p class="msg msg-ok">{message}</p>{/if}
    {#if error}<p class="msg msg-error">{error}</p>{/if}
    <!-- Hidden username so password managers (1Password, Chrome, …) associate the
         new password with this account and offer to update the saved entry. -->
    <input
      class="pw-username"
      type="text"
      name="username"
      autocomplete="username"
      value={pageData.username}
      readonly
      tabindex="-1"
      aria-hidden="true"
    />
    {#if !pageData.must_change_password}
      <label class="field">
        <span>Current password</span>
        <input
          id="current-password"
          name="current-password"
          type="password"
          bind:value={current}
          autocomplete="current-password"
          required
        />
      </label>
    {/if}
    <label class="field">
      <span>New password</span>
      <input
        id="new-password"
        name="new-password"
        type="password"
        bind:value={next}
        autocomplete="new-password"
        required
      />
    </label>
    <button type="submit" class="btn-primary" disabled={busy}>
      {busy ? "Saving…" : "Change password"}
    </button>
  </form>
</div>

<style>
  .who {
    margin: 0 0 1.25rem;
    color: var(--muted);
  }
  .me {
    color: var(--acc-d);
  }
  h2 {
    margin: 0 0 1rem;
    font-size: 1.05rem;
  }
  /* Present in the DOM for password managers, but not shown or focusable.
     `display:none` is avoided because some managers skip such fields. */
  .pw-username {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    border: 0;
  }
</style>
