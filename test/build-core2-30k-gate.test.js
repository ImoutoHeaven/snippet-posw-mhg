import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { stat } from "node:fs/promises";
import { runBuild, distDir } from "../lib/build-lock.js";

const CORE2_30K_LIMIT = 30 * 1024;
const core2SnippetPath = join(distDir, "pow_core2_snippet.js");

const ensureCore2Artifact = async () => {
  try {
    return await stat(core2SnippetPath);
  } catch (error) {
    if (!error || error.code !== "ENOENT") throw error;
    await runBuild({ cleanDist: false });
    return stat(core2SnippetPath);
  }
};

const gatedTest = process.env.ENFORCE_CORE2_30K === "1" ? test : test.skip;

gatedTest("pow_core2_snippet.js stays within 30KiB gate", async () => {
  const artifact = await ensureCore2Artifact();
  assert.ok(
    artifact.size <= CORE2_30K_LIMIT,
    `pow_core2_snippet.js size ${artifact.size} exceeds 30KiB gate ${CORE2_30K_LIMIT}`
  );
});
