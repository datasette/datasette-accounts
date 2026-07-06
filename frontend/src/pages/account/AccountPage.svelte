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
    const { ok, data } = await postJSON<{ ok: boolean; error?: string }>(
      "/-/account/api/change-password",
      { current_password: current, new_password: next },
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

<h1>Your account</h1>
<p>Signed in as <strong>{pageData.username}</strong>.</p>
{#if pageData.must_change_password}
  <p class="error">You must change your password before continuing.</p>
{/if}
<form onsubmit={submit}>
  <label>Current password
    <input type="password" bind:value={current} required />
  </label>
  <label>New password
    <input type="password" bind:value={next} required />
  </label>
  <p><button type="submit" disabled={busy}>Change password</button></p>
  {#if message}<p class="ok">{message}</p>{/if}
  {#if error}<p class="error">{error}</p>{/if}
</form>
