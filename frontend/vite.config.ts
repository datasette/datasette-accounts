import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { readFileSync, writeFileSync } from "fs";
import { compile } from "json-schema-to-typescript";
import { glob } from "glob";

const DEV_PORT = 5180;

async function compileSchema(file: string) {
  const schema = JSON.parse(readFileSync(file, "utf-8"));
  const ts = await compile(schema, "");
  writeFileSync(file.replace("_schema.json", ".types.ts"), ts);
}

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
        for (const file of glob.sync("src/page_data/*_schema.json")) {
          await compileSchema(file);
        }
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
        admin: "src/pages/admin/index.ts",
        account: "src/pages/account/index.ts",
        capabilities: "src/pages/capabilities/index.ts",
        messages: "src/pages/messages/index.ts",
      },
    },
  },
});
