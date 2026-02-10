import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { stat } from "node:fs/promises";
import { runBuild, repoRoot } from "../lib/build-lock.js";

const powConfigSnippet = join(repoRoot, "dist", "pow_config_snippet.js");
const powCore1Snippet = join(repoRoot, "dist", "pow_core1_snippet.js");
const powCore2Snippet = join(repoRoot, "dist", "pow_core2_snippet.js");
const HARD_LIMIT = 32 * 1024;
const CORE_TARGET = 23 * 1024;

const findTelemetryLine = (stdout, snippetName) =>
  stdout
    .split(/\r?\n/u)
    .find((line) => line.includes("Built snippet:") && line.includes(snippetName));

test("split snippets enforce 32KiB and report 23KiB telemetry", async () => {
  const buildResult = await runBuild();
  const [powConfigInfo, core1Info, core2Info] = await Promise.all([
    stat(powConfigSnippet),
    stat(powCore1Snippet),
    stat(powCore2Snippet),
  ]);

  assert.ok(
    powConfigInfo.size <= HARD_LIMIT,
    `dist/pow_config_snippet.js size ${powConfigInfo.size} exceeds 32KiB hard limit ${HARD_LIMIT}`
  );
  assert.ok(
    core1Info.size <= HARD_LIMIT,
    `dist/pow_core1_snippet.js size ${core1Info.size} exceeds 32KiB hard limit ${HARD_LIMIT}`
  );
  assert.ok(
    core2Info.size <= HARD_LIMIT,
    `dist/pow_core2_snippet.js size ${core2Info.size} exceeds 32KiB hard limit ${HARD_LIMIT}`
  );

  const core1Line = findTelemetryLine(buildResult.stdout, "pow_core1_snippet.js");
  const core2Line = findTelemetryLine(buildResult.stdout, "pow_core2_snippet.js");
  assert.ok(core1Line, "build output missing pow_core1_snippet.js telemetry line");
  assert.ok(core2Line, "build output missing pow_core2_snippet.js telemetry line");

  const expectedCore1Hard = core1Info.size <= HARD_LIMIT ? "OK" : "OVER";
  const expectedCore1BestEffort = core1Info.size <= CORE_TARGET ? "OK" : "MISS";
  const expectedCore2Hard = core2Info.size <= HARD_LIMIT ? "OK" : "OVER";
  const expectedCore2BestEffort = core2Info.size <= CORE_TARGET ? "OK" : "MISS";

  assert.match(core1Line, /hard32KiB=/);
  assert.match(core1Line, /best-effort23KiB=/);
  assert.match(core1Line, new RegExp(`hard32KiB=${expectedCore1Hard}\\b`, "u"));
  assert.match(core1Line, new RegExp(`best-effort23KiB=${expectedCore1BestEffort}\\b`, "u"));

  assert.match(core2Line, /hard32KiB=/);
  assert.match(core2Line, /best-effort23KiB=/);
  assert.match(core2Line, new RegExp(`hard32KiB=${expectedCore2Hard}\\b`, "u"));
  assert.match(core2Line, new RegExp(`best-effort23KiB=${expectedCore2BestEffort}\\b`, "u"));

  assert.match(buildResult.stdout, /pow_core1_snippet\.js/);
  assert.match(buildResult.stdout, /pow_core2_snippet\.js/);
  assert.match(buildResult.stdout, /23KiB best-effort/);
});
