import { build } from "esbuild";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const outdir = resolve(__dirname, "dist");
const outfile = resolve(outdir, "worker.js");

await mkdir(outdir, { recursive: true });
await build({
  entryPoints: [resolve(__dirname, "src/worker.js")],
  outfile,
  bundle: true,
  format: "esm",
  target: "es2022",
  platform: "neutral",
  minify: true,
  legalComments: "none",
  charset: "ascii",
});

console.log(`Built ${outfile}`);
