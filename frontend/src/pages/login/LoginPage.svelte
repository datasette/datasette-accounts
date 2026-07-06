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

<h1>Log in</h1>
<form onsubmit={submit}>
  <label>Username
    <input bind:value={username} autocomplete="username" required />
  </label>
  <label>Password
    <input type="password" bind:value={password} autocomplete="current-password" required />
  </label>
  <p><button type="submit" disabled={busy}>Log in</button></p>
  {#if error}<p class="error">{error}</p>{/if}
</form>
