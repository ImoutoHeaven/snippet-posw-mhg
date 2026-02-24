import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const CLIENT_ARTIFACTS = ["glue.js", "esm/esm.js", "esm/mhg-worker.js"];

test("client artifacts stay self-contained and avoid server module imports", async () => {
  for (const relPath of CLIENT_ARTIFACTS) {
    const source = await readFile(join(repoRoot, relPath), "utf8");
    assert.equal(
      source.includes("../lib/"),
      false,
      `${relPath} must not reference ../lib server modules`
    );
    assert.doesNotMatch(
      source,
      /^\s*import\s.+$/mu,
      `${relPath} must remain self-contained without static imports`
    );
  }
});
