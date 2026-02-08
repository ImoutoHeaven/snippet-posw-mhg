import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { readFile, stat } from "node:fs/promises";
import { runBuild, distDir } from "../lib/build-lock.js";

const powConfigSnippet = join(distDir, "pow_config_snippet.js");
const powSnippet = join(distDir, "pow_snippet.js");

test("build emits pow-config and pow snippets", async () => {
  await runBuild({ cleanDist: true });

  const [configStat, powStat] = await Promise.all([
    stat(powConfigSnippet),
    stat(powSnippet),
  ]);
  const limit = 32 * 1024;
  assert.ok(configStat.size <= limit, "pow_config_snippet.js exceeds 32KB");
  assert.ok(powStat.size <= limit, "pow_snippet.js exceeds 32KB");

  const [configSource, powSource] = await Promise.all([
    readFile(powConfigSnippet, "utf8"),
    readFile(powSnippet, "utf8"),
  ]);
  assert.ok(!configSource.includes("__COMPILED_CONFIG__"));
  assert.ok(!powSource.includes("__COMPILED_CONFIG__"));
  assert.ok(!powSource.includes("__HTML_TEMPLATE__"));
});
