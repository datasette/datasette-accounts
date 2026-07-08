// Compile page-data JSON Schemas (written by scripts/typegen-pagedata.py) into
// TypeScript declarations. Used both by the Vite `page-data-types` plugin and
// standalone (`npm run gen-types`) so `svelte-check` has the .types.ts files
// without a full build (e.g. in the frontend CI job).
import { readFileSync, writeFileSync } from "fs";
import { compile } from "json-schema-to-typescript";
import { glob } from "glob";

export async function compileSchema(file) {
  const schema = JSON.parse(readFileSync(file, "utf-8"));
  const ts = await compile(schema, "");
  writeFileSync(file.replace("_schema.json", ".types.ts"), ts);
}

export async function compileAll() {
  for (const file of glob.sync("src/page_data/*_schema.json")) {
    await compileSchema(file);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await compileAll();
}
