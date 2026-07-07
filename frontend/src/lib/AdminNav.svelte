<script lang="ts">
  // Shared tab strip across the admin pages (Accounts / Capabilities / Messages).
  let { current }: { current: "accounts" | "capabilities" | "messages" } = $props();
</script>

<nav class="tabs" aria-label="Admin sections">
  <a href="/-/admin/users" class:active={current === "accounts"} aria-current={current === "accounts" ? "page" : undefined}>Accounts</a>
  <a href="/-/admin/capabilities" class:active={current === "capabilities"} aria-current={current === "capabilities" ? "page" : undefined}>Capabilities</a>
  <a href="/-/admin/messages" class:active={current === "messages"} aria-current={current === "messages" ? "page" : undefined}>Messages</a>
</nav>

<style>
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 1.25rem;
    border-bottom: 1px solid var(--border);
  }
  .tabs a {
    padding: 0.5rem 0.9rem;
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--muted);
    text-decoration: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tabs a:hover {
    color: var(--ink);
  }
  .tabs a.active {
    color: var(--acc);
    border-bottom-color: var(--acc);
  }
</style>
