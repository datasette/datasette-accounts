// Programmatic doc screenshots of datasette-accounts → docs/screenshots/*.png.
//
// SELF-CONTAINED: boots its own throwaway datasette on a fixed port with a fresh
// internal DB, lets frontend/scripts/shot-plugins/seed.py seed deterministic demo
// accounts, drives Playwright, then tears the server down. One command,
// reproducible — so the committed PNGs only change when the UI actually changes
// (clean git diffs).
//
// Output is committed; the README embeds these, so re-run + commit when the UI
// look changes:  `just shots`  (or a subset, e.g. `just shots login admin`).
//
// Unlike the other plugins in this family, datasette-accounts owns its auth: it
// uses its own DB-backed `ds_accounts_session` cookie, NOT the core `ds_actor`
// cookie. So there is nothing to sign — instead we seed accounts (seed.py) and
// log in through the real login form to obtain an authenticated context.
//
// Based on the datasette-plugin-screenshots skill; the server-lifecycle and
// stability boilerplate is standard, the login helper + shot map are per-plugin.
import { chromium } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdir, rm } from "node:fs/promises";
import { spawn, execFileSync } from "node:child_process";

// A free high port unique to this plugin (others: paper 8486, sheets 8487,
// town 8489, skill-template 8490).
const PORT = Number(process.env.SHOTS_PORT || 8491);
const BASE = `http://localhost:${PORT}`;
// Every seeded demo account shares this password (see seed.py:DEMO_PASSWORD).
const DEMO_PASSWORD = "demo-password";
// Throwaway signing secret for the datasette instance. NOT a real secret.
const SECRET = "screenshots-secret-not-for-prod";
const INTERNAL_DB = "/tmp/datasette-accounts-shots-internal.db";

const HERE = dirname(fileURLToPath(import.meta.url));
const PLUGINS_DIR = resolve(HERE, "shot-plugins");
const OUT = resolve(HERE, "../../docs/screenshots");
const out = (n) => resolve(OUT, `${n}.png`);

const VIEWPORT = { width: 1000, height: 820 };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
async function reachable() {
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 500);
    const r = await fetch(`${BASE}/-/login`, {
      redirect: "manual",
      signal: ac.signal,
    });
    clearTimeout(t);
    return r.status < 500;
  } catch {
    return false;
  }
}

async function startServer() {
  await rm(INTERNAL_DB, { force: true });
  if (await reachable()) {
    throw new Error(
      `something is already serving on ${BASE}. Stop it (or set SHOTS_PORT) and retry.`,
    );
  }
  // `detached: true` puts datasette in its own process group. datasette is a
  // grandchild of `uv run`, so we kill the whole group in stopServer.
  const child = spawn(
    "uv",
    [
      "run",
      "datasette",
      "--internal",
      INTERNAL_DB,
      "--secret",
      SECRET,
      // Throwaway plugin: seeds deterministic demo accounts + one session.
      "--plugins-dir",
      PLUGINS_DIR,
      "-p",
      String(PORT),
    ],
    {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
      env: { ...process.env },
    },
  );
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));

  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `datasette exited early (code ${child.exitCode}):\n${log}`,
      );
    }
    if (await reachable()) return child;
    await sleep(250);
  }
  stopServer(child);
  throw new Error(`datasette never came up on ${BASE}:\n${log}`);
}

// Kill the server's whole process group (datasette is uv's child). Idempotent.
function stopServer(child) {
  if (!child || child.exitCode !== null) return;
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      // already gone
    }
  }
}

// ---------------------------------------------------------------------------
// Per-page stabilization: kill carets / transitions and hide dev-only widgets so
// a re-run with no UI change produces no binary diff.
const STABILITY_CSS = `*, *::before, *::after {
  caret-color: transparent !important;
  transition: none !important;
  animation: none !important;
}
#datasette-debug-bar { display: none !important; }`;

async function freezeVolatile(page) {
  await page.evaluate(() => {
    document.getElementById("datasette-debug-bar")?.remove();
  });
}

// Screenshot from the top down to the bottom of the page footer, dropping the
// empty viewport space a short page otherwise leaves below it.
async function shotClipped(page, file, pad = 12) {
  const bottom = await page.evaluate(() => {
    const f = document.querySelector(".ft") || document.querySelector("footer");
    return f
      ? Math.ceil(f.getBoundingClientRect().bottom)
      : document.body.scrollHeight;
  });
  const vp = page.viewportSize() || VIEWPORT;
  await page.screenshot({
    path: file,
    clip: {
      x: 0,
      y: 0,
      width: vp.width,
      height: Math.min(vp.height, bottom + pad),
    },
  });
}

async function makeContext(browser, viewport = VIEWPORT) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: 2 });
  await ctx.addInitScript((css) => {
    const inject = () => {
      if (document.getElementById("__shots_stability")) return;
      const s = document.createElement("style");
      s.id = "__shots_stability";
      s.textContent = css;
      (document.head || document.documentElement).appendChild(s);
    };
    inject();
    document.addEventListener("DOMContentLoaded", inject);
  }, STABILITY_CSS);
  return ctx;
}

// Log in through the real form and land on `nextPath`. Returns { ctx, page }.
async function loginContext(browser, username, nextPath, viewport = VIEWPORT) {
  const ctx = await makeContext(browser, viewport);
  const page = await ctx.newPage();
  await page.goto(`${BASE}/-/login?next=${encodeURIComponent(nextPath)}`);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(DEMO_PASSWORD);
  await Promise.all([
    page.waitForURL((u) => !u.pathname.startsWith("/-/login"), {
      timeout: 15_000,
    }),
    page.getByRole("button", { name: "Log in" }).click(),
  ]);
  return { ctx, page };
}

// ---------------------------------------------------------------------------
// The per-plugin shot map. Each entry opens a context, reaches a real readiness
// selector (never a bare sleep for load), then screenshots.
function buildShots(browser) {
  return {
    // The login form (unauthenticated).
    login: async () => {
      const ctx = await makeContext(browser);
      const page = await ctx.newPage();
      await page.goto(`${BASE}/-/login`);
      await page
        .getByRole("heading", { name: "Log in" })
        .waitFor({ timeout: 15_000 });
      await page.getByLabel("Username").waitFor();
      // The admin-authored login help/contact note (seeded in seed.py).
      await page.getByText("Trouble signing in?").waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("login"));
      await ctx.close();
    },

    // The signed-out homepage banner (top_homepage hook) prompting sign-in.
    "homepage-message": async () => {
      const ctx = await makeContext(browser);
      const page = await ctx.newPage();
      await page.goto(`${BASE}/`);
      await page
        .getByText("Sign in to browse the internal datasets")
        .waitFor({ timeout: 15_000 });
      await freezeVolatile(page);
      await shotClipped(page, out("homepage-message"));
      await ctx.close();
    },

    // The admin accounts table (logged in as the seeded admin).
    admin: async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/users",
      );
      await page
        .getByRole("heading", { name: "Accounts" })
        .waitFor({ timeout: 15_000 });
      await page.getByRole("cell", { name: "dave", exact: true }).waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("admin"));
      await ctx.close();
    },

    // The admin table with a row's overflow (kebab) menu open.
    "admin-menu": async () => {
      // Taller viewport: the open menu (now ~9 items) extends past the footer
      // and would otherwise be clipped at the standard height.
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/users",
        { width: 1000, height: 1040 },
      );
      await page.getByRole("cell", { name: "alice", exact: true }).waitFor({
        timeout: 15_000,
      });
      await page
        .getByRole("row", { name: /alice/ })
        .getByRole("button", { name: "Actions for alice" })
        .click();
      await page
        .getByRole("menuitem", { name: "History" })
        .waitFor({ timeout: 15_000 });
      await freezeVolatile(page);
      await shotClipped(page, out("admin-menu"), 90);
      await ctx.close();
    },

    // The active-sessions modal for a user (opened from the kebab menu).
    // Captured full-frame (not footer-clipped) so the viewport-centred modal
    // is shown centred rather than cut off at the bottom.
    "admin-sessions": async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/users",
        {
          width: 1000,
          height: 680,
        },
      );
      await page.getByRole("cell", { name: "alice", exact: true }).waitFor({
        timeout: 15_000,
      });
      await page
        .getByRole("row", { name: /alice/ })
        .getByRole("button", { name: "Actions for alice" })
        .click();
      await page.getByRole("menuitem", { name: "Active sessions" }).click();
      await page.getByText("203.0.113.24").waitFor({ timeout: 15_000 });
      await freezeVolatile(page);
      await page.screenshot({ path: out("admin-sessions") });
      await ctx.close();
    },

    // The Capabilities admin page: global-action grants to accounts, groups
    // and audiences (seeded against the installed datasette-paper plugin).
    capabilities: async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/capabilities",
      );
      await page
        .getByRole("heading", { name: "Capabilities" })
        .waitFor({ timeout: 15_000 });
      // Wait for the seeded grants to render (the paper-create card).
      await page
        .getByText("Can create new papers")
        .waitFor({ timeout: 15_000 });
      await page.getByText("@alice").waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("capabilities"));
      await ctx.close();
    },

    // The Capabilities page with a grant being added (principal picker open).
    "capabilities-add": async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/capabilities",
      );
      await page
        .getByText("Can create new papers")
        .waitFor({ timeout: 15_000 });
      // Open the add-grant row on the first action card.
      await page.getByRole("button", { name: "+ Grant" }).first().click();
      await page.getByLabel("Principal type").waitFor({ timeout: 15_000 });
      await freezeVolatile(page);
      await shotClipped(page, out("capabilities-add"));
      await ctx.close();
    },

    // The Configuration admin page: the self-registration toggle + the
    // admin-editable site messages (homepage sign-in prompt + login
    // help/contact), seeded with demo copy.
    config: async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/config",
      );
      await page
        .getByRole("heading", { name: "Configuration" })
        .waitFor({ timeout: 15_000 });
      await page
        .getByRole("heading", { name: "Self-registration" })
        .waitFor();
      await page
        .getByRole("heading", { name: "Homepage sign-in prompt" })
        .waitFor();
      await page
        .getByRole("heading", { name: "Login help / contact" })
        .waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("config"));
      await ctx.close();
    },

    // The Login attempts admin audit page: every sign-in attempt with its
    // result + reason, filterable by username/IP (seeded demo rows).
    "login-attempts": async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/login-attempts",
      );
      await page
        .getByRole("heading", { name: "Login attempts" })
        .waitFor({ timeout: 15_000 });
      // Wait for the seeded rows (the attacker IP) to render.
      await page.getByText("45.148.10.62").first().waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("login-attempts"));
      await ctx.close();
    },

    // The Admin history page: every admin mutation with its actor,
    // target, and detail chips, filterable by target username/operation
    // (seeded demo rows, including a CLI actor and a deleted target).
    audit: async () => {
      const { ctx, page } = await loginContext(
        browser,
        "admin",
        "/-/admin/audit",
      );
      await page
        .getByRole("heading", { name: "Admin history" })
        .waitFor({ timeout: 15_000 });
      // Wait for the seeded rows (the CLI actor) to render.
      await page.getByText("cli:ops").first().waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("audit"));
      await ctx.close();
    },

    // A regular user's own account page (Password tab, change-password form).
    account: async () => {
      const { ctx, page } = await loginContext(browser, "alice", "/-/account");
      await page.getByRole("heading", { name: "Your account" }).waitFor({
        timeout: 15_000,
      });
      await page.getByText("Signed in as").waitFor();
      await freezeVolatile(page);
      await shotClipped(page, out("account"));
      await ctx.close();
    },

    // The account page's Sessions tab (hash-routed): the user's own sessions
    // with per-session revoke + log-out-others.
    "account-sessions": async () => {
      const { ctx, page } = await loginContext(
        browser,
        "alice",
        "/-/account#sessions",
      );
      await page.getByText("This device").waitFor({ timeout: 15_000 });
      await freezeVolatile(page);
      await shotClipped(page, out("account-sessions"));
      await ctx.close();
    },
  };
}

// ---------------------------------------------------------------------------
async function main() {
  const requested = new Set(process.argv.slice(2));

  await mkdir(OUT, { recursive: true });
  console.log(`booting datasette on ${BASE} …`);
  const server = await startServer();
  const onSignal = () => {
    stopServer(server);
    process.exit(130);
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  const browser = await chromium.launch();
  try {
    const shotsByName = buildShots(browser);
    const names = Object.keys(shotsByName);
    const unknown = [...requested].filter((n) => !names.includes(n));
    if (unknown.length) {
      throw new Error(
        `unknown shot(s): ${unknown.join(", ")} (have: ${names.join(", ")})`,
      );
    }
    const todo = requested.size ? names.filter((n) => requested.has(n)) : names;

    for (const name of todo) {
      await shotsByName[name]();
      console.log(`✓ ${name} → ${out(name)}`);
    }
  } finally {
    await browser.close();
    stopServer(server);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
