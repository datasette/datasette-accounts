import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { compileAll, compileSchema } from "./scripts/gen-page-types.mjs";

const DEV_PORT = 5180;

export default defineConfig({
  server: {
    port: DEV_PORT,
    strictPort: true,
    cors: true,
    hmr: { host: "localhost", port: DEV_PORT, protocol: "ws" },
  },
  plugins: [
    svelte(),
    {
      name: "page-data-types",
      async buildStart() {
        await compileAll();
      },
      async handleHotUpdate({ file, server }) {
        if (!file.endsWith("_schema.json")) return;
        await compileSchema(file);
        const outFile = file.replace("_schema.json", ".types.ts");
        const mod = server.moduleGraph.getModuleById(outFile);
        if (mod) {
          server.moduleGraph.invalidateModule(mod);
          return [mod];
        }
      },
    },
  ],
  build: {
    manifest: "manifest.json",
    outDir: "../datasette_accounts",
    assetsDir: "static/gen",
    emptyOutDir: false,
    rollupOptions: {
      input: {
        login: "src/pages/login/index.ts",
        register: "src/pages/register/index.ts",
        admin: "src/pages/admin/index.ts",
        account: "src/pages/account/index.ts",
        capabilities: "src/pages/capabilities/index.ts",
        messages: "src/pages/messages/index.ts",
        "login-attempts": "src/pages/login-attempts/index.ts",
        "set-password": "src/pages/set-password/index.ts",
        audit: "src/pages/audit/index.ts",
      },
    },
  },
});
