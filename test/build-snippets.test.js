import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { readFile, stat, writeFile } from "node:fs/promises";
import { runBuild, distDir } from "../lib/build-lock.js";

const HARD_LIMIT = 32 * 1024;
const splitSnippets = [
  { file: "pow_config_snippet.js", token: "__COMPILED_CONFIG__" },
  { file: "pow_core1_snippet.js", token: "__HTML_TEMPLATE__" },
  { file: "pow_core2_snippet.js", token: "__HTML_TEMPLATE__" },
];

const powConfigSnippet = join(distDir, splitSnippets[0].file);
const powCore1Snippet = join(distDir, splitSnippets[1].file);
const powCore2Snippet = join(distDir, splitSnippets[2].file);
const legacyPowSnippet = join(distDir, "pow_snippet.js");

test("build emits pow-config and split core snippets", async () => {
  await runBuild({ cleanDist: true });

  const snippetStats = await Promise.all(
    splitSnippets.map(async ({ file }) => ({
      file,
      info: await stat(join(distDir, file)),
    }))
  );
  for (const { file, info } of snippetStats) {
    assert.ok(info.size > 0, `${file} is empty`);
    assert.ok(info.size <= HARD_LIMIT, `${file} exceeds 32KiB hard limit (${info.size}B)`);
  }

  await writeFile(legacyPowSnippet, "// stale artifact\n", "utf8");
  await runBuild();
  await assert.rejects(
    stat(legacyPowSnippet),
    { code: "ENOENT" },
    "legacy pow_snippet.js should be absent after build"
  );

  const snippetSources = await Promise.all(
    splitSnippets.map(async ({ file, token }) => ({
      file,
      token,
      source: await readFile(join(distDir, file), "utf8"),
    }))
  );
  for (const { file, token, source } of snippetSources) {
    assert.ok(!source.includes("__COMPILED_CONFIG__"), `${file} still contains config placeholder`);
    assert.ok(!source.includes(token), `${file} still contains inline placeholder ${token}`);
  }
});
