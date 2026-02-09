import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("legacy pow chain symbols removed", async () => {
  const powSource = await readFile("pow.js", "utf8");
  const configSource = await readFile("pow-config.js", "utf8");

  assert.equal(powSource.includes("POW_SPINE_K"), false);
  assert.equal(powSource.includes("MERKLE_LEAF_PREFIX"), false);
  assert.equal(powSource.includes("MERKLE_NODE_PREFIX"), false);
  assert.equal(powSource.includes("hashMerkleLeaf"), false);
  assert.equal(powSource.includes("hashMerkleNode"), false);
  assert.equal(powSource.includes("computeMerkleDepth"), false);
  assert.equal(powSource.includes("verifyMerkleProof"), false);
  assert.equal(configSource.includes("POW_SPINE_K"), false);
  assert.equal(configSource.includes("POW_FORCE_EDGE_1"), false);
  assert.equal(configSource.includes("POW_FORCE_EDGE_LAST"), false);
  assert.equal(configSource.includes("SPINE_SEED_MIN_LEN"), false);
  assert.equal(configSource.includes("SPINE_SEED_MAX_LEN"), false);
  assert.equal(configSource.includes("spineSeed"), false);
  assert.equal(configSource.includes("POW_SEGMENT_LEN"), true);
  assert.equal(configSource.includes("POW_HASHCASH_BITS"), true);
});
