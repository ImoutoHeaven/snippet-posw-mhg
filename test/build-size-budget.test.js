import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { stat } from "node:fs/promises";
import { runBuild, repoRoot } from "../lib/build-lock.js";

const powSnippet = join(repoRoot, "dist", "pow_snippet.js");
const powConfigSnippet = join(repoRoot, "dist", "pow_config_snippet.js");
const SNIPPET_BUDGET = 32 * 1024;

test("both snippets stay within 32KiB budget", async () => {
  await runBuild();
  const [powInfo, powConfigInfo] = await Promise.all([
    stat(powSnippet),
    stat(powConfigSnippet),
  ]);

  assert.ok(
    powInfo.size <= SNIPPET_BUDGET,
    `dist/pow_snippet.js size ${powInfo.size} exceeds budget ${SNIPPET_BUDGET}`
  );
  assert.ok(
    powConfigInfo.size <= SNIPPET_BUDGET,
    `dist/pow_config_snippet.js size ${powConfigInfo.size} exceeds budget ${SNIPPET_BUDGET}`
  );
});
