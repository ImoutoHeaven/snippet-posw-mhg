import test from "node:test";
import assert from "node:assert/strict";

test("protocol constants are fixed and not configurable", async () => {
  const c = await import("../../lib/mhg/constants.js");
  assert.equal(c.MERKLE_LEAF_PREFIX, "MHG1-LEAF");
  assert.equal(c.MERKLE_NODE_PREFIX, "MHG1-NODE");
  assert.equal(c.HASHCASH_PREFIX, "hashcash|v4|");
  assert.equal(c.POW_PAGE_BYTES_DEFAULT, 16384);
  assert.equal(c.POW_MIX_ROUNDS_DEFAULT, 2);
});

test("pow-config exposes documented difficulty knobs", async () => {
  const mod = await import("../../pow-config.js");
  const cfg = mod.__testNormalizeConfig?.({}) ?? null;
  assert.ok(cfg, "need test-only normalize export");
  assert.equal(cfg.POW_PAGE_BYTES, 16384);
  assert.equal(cfg.POW_MIX_ROUNDS, 2);
});

test("pow-config normalizes page bytes alignment and mix rounds bounds", async () => {
  const mod = await import("../../pow-config.js");
  const cfg = mod.__testNormalizeConfig?.({ POW_PAGE_BYTES: 16399, POW_MIX_ROUNDS: 9 }) ?? null;
  assert.ok(cfg, "need test-only normalize export");
  assert.equal(cfg.POW_PAGE_BYTES, 16384);
  assert.equal(cfg.POW_MIX_ROUNDS, 4);
});
