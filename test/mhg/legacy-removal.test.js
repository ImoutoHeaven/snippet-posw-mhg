import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";

test("legacy pow chain symbols removed", async () => {
  const businessGateSource = await readFile("lib/pow/business-gate.js", "utf8");
  const configSource = await readFile("pow-config.js", "utf8");
  const readmeSource = await readFile("README.md", "utf8");

  assert.equal(businessGateSource.includes("POW_SPINE_K"), false);
  assert.equal(businessGateSource.includes("MERKLE_LEAF_PREFIX"), false);
  assert.equal(businessGateSource.includes("MERKLE_NODE_PREFIX"), false);
  assert.equal(businessGateSource.includes("hashMerkleLeaf"), false);
  assert.equal(businessGateSource.includes("hashMerkleNode"), false);
  assert.equal(businessGateSource.includes("computeMerkleDepth"), false);
  assert.equal(businessGateSource.includes("verifyMerkleProof"), false);
  assert.equal(configSource.includes("POW_SPINE_K"), false);
  assert.equal(configSource.includes("POW_FORCE_EDGE_1"), false);
  assert.equal(configSource.includes("POW_FORCE_EDGE_LAST"), false);
  assert.equal(configSource.includes("SPINE_SEED_MIN_LEN"), false);
  assert.equal(configSource.includes("SPINE_SEED_MAX_LEN"), false);
  assert.equal(configSource.includes("spineSeed"), false);
  assert.equal(configSource.includes("POW_SEGMENT_LEN"), true);
  assert.equal(configSource.includes("POW_HASHCASH_BITS"), true);
  assert.equal(readmeSource.includes("POW_SPINE_K"), false);
  assert.equal(readmeSource.includes("POW_FORCE_EDGE_1"), false);
  assert.equal(readmeSource.includes("POW_FORCE_EDGE_LAST"), false);
  assert.equal(readmeSource.includes('digest = SHA256("hashcash|v4|"'), true);
  assert.equal(readmeSource.includes("__Host-pow_commit` (v4)"), false);
  assert.equal(readmeSource.includes("POW_PAGE_BYTES"), true);
  assert.equal(readmeSource.includes("POW_MIX_ROUNDS"), true);
  assert.equal(readmeSource.includes("MHG1-P2|v4"), true);
  assert.equal(readmeSource.includes("mhg|graph|v4|"), true);
  assert.equal(readmeSource.includes("staticParentsOf"), true);
  assert.equal(readmeSource.includes("deriveDynamicParent2"), true);
  assert.equal(readmeSource.includes("parentsOf"), false);
  assert.equal(readmeSource.includes("prevPage"), false);
});

const collectCodeFiles = async (dir) => {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name === ".git") {
      continue;
    }
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (fullPath.includes(`${join("docs", "plans")}`)) continue;
      files.push(...(await collectCodeFiles(fullPath)));
      continue;
    }
    const ext = extname(entry.name);
    if ([".js", ".mjs", ".md", ".json"].includes(ext)) {
      files.push(fullPath);
    }
  }
  return files;
};

test("repository code does not reference monolith pow.js", async () => {
  const files = await collectCodeFiles(".");
  const offenders = [];
  const monolithPathRefPattern = /['"`](?:(?:\.\.?)\/)*pow\.js['"`]/u;
  for (const filePath of files) {
    if (filePath.endsWith("test/mhg/legacy-removal.test.js")) continue;
    const source = await readFile(filePath, "utf8");
    if (monolithPathRefPattern.test(source)) offenders.push(filePath);
  }
  assert.deepEqual(offenders, []);
});
