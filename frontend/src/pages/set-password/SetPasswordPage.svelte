<script lang="ts">
  import type { SetPasswordPageData } from "../../page_data/SetPasswordPageData.types.ts";
  import { loadPageData } from "../../page_data/load.ts";
  import { postJSON } from "../../lib/api.ts";

  const pageData = loadPageData<SetPasswordPageData>();

  let password = $state("");
  let confirm = $state("");
  let error = $state("");
  let busy = $state(false);

  const heading =
    pageData.purpose === "reset"
      ? "Reset your password"
      : `Choose a password for ${pageData.username}`;

  async function submit(e: Event) {
    e.preventDefault();
    if (password !== confirm) {
      error = "Passwords don't match";
      return;
    }
    busy = true;
    error = "";
    const { ok, data } = await postJSON<{
      ok: boolean;
      redirect?: string;
      error?: string;
    }>("/-/set-password/api/complete", {
      token: pageData.token,
      new_password: password,
    });
    busy = false;
    if (ok && data.ok) {
      window.location.href = data.redirect || "/";
    } else {
      error = data.error || "Something went wrong";
    }
  }
</script>

<div class="page narrow">
  {#if pageData.valid}
    <h1>{heading}</h1>
    <form class="card" onsubmit={submit}>
      {#if error}<p class="msg msg-error">{error}</p>{/if}
      <!-- Hidden username so password managers associate the new password
           with this account. -->
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
      <label class="field">
        <span>New password</span>
        <input
          id="new-password"
          name="new-password"
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
          bind:value={confirm}
          autocomplete="new-password"
          required
        />
      </label>
      <button type="submit" class="btn-primary block" disabled={busy}>
        {busy ? "Saving…" : "Set password"}
      </button>
    </form>
  {:else}
    <h1>Link invalid</h1>
    <p class="card msg-invalid">
      This link is invalid or has expired.
      <a href="/-/login">Go to the login page</a>.
    </p>
  {/if}
</div>

<style>
  .block {
    width: 100%;
    justify-content: center;
    padding-top: 0.6rem;
    padding-bottom: 0.6rem;
  }
  .msg-invalid {
    color: var(--muted);
    line-height: 1.5;
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
