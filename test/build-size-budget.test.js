import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { stat } from "node:fs/promises";
import { runBuild, distDir } from "../lib/build-lock.js";

const powConfigSnippet = join(distDir, "pow_config_snippet.js");
const powCore1Snippet = join(distDir, "pow_core1_snippet.js");
const powCore2Snippet = join(distDir, "pow_core2_snippet.js");
const HARD_LIMIT = 32 * 1024;
const snippets = [
  { name: "pow_config_snippet.js", path: powConfigSnippet },
  { name: "pow_core1_snippet.js", path: powCore1Snippet },
  { name: "pow_core2_snippet.js", path: powCore2Snippet },
];

const findTelemetryLine = (stdout, snippetName) =>
  stdout
    .split(/\r?\n/u)
    .find((line) => line.includes("Built snippet:") && line.includes(snippetName));

test("split snippets enforce 32KiB hard-limit telemetry only", async () => {
  const buildResult = await runBuild({ cleanDist: true });
  const snippetInfos = await Promise.all(
    snippets.map(async ({ name, path }) => ({
      name,
      size: (await stat(path)).size,
      line: findTelemetryLine(buildResult.stdout, name),
    }))
  );

  for (const { name, size, line } of snippetInfos) {
    assert.ok(size <= HARD_LIMIT, `${name} size ${size} exceeds 32KiB hard limit ${HARD_LIMIT}`);
    assert.ok(line, `build output missing ${name} telemetry line`);
    assert.match(line, /hard32KiB=/);
    assert.match(line, new RegExp(`hard32KiB=${size <= HARD_LIMIT ? "OK" : "OVER"}\\b`, "u"));
    assert.doesNotMatch(line, /best-effort23KiB=/);
  }

  assert.match(buildResult.stdout, /pow_config_snippet\.js/);
  assert.match(buildResult.stdout, /pow_core1_snippet\.js/);
  assert.match(buildResult.stdout, /pow_core2_snippet\.js/);
  assert.match(buildResult.stdout, /32KiB hard limit/);
  assert.doesNotMatch(buildResult.stdout, /23KiB/);
  assert.doesNotMatch(buildResult.stdout, /best-effort/);
});
