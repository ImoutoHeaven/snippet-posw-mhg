import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

test("readme documents verify-only Equihash protocol", async () => {
  const md = await readFile(join(repoRoot, "README.md"), "utf8");
  const legacyEndpoints = ["commit", "challenge", "open", "cap"].map((suffix) => `/__pow/${suffix}`);

  assert.equal(md.includes("${POW_API_PREFIX}/verify"), true);
  assert.equal(md.includes("POST /__pow/verify"), true);
  assert.match(md, /default:\s*`POST \/__pow\/verify`/u);
  for (const endpoint of legacyEndpoints) {
    assert.equal(md.includes(endpoint), false);
  }
});
