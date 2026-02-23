import test from "node:test";
import assert from "node:assert/strict";

import { __testNormalizeConfig } from "../../pow-config.js";

test("pow-config exposes equihash knobs and removes legacy ccr/mhg knobs", () => {
  const cfg = __testNormalizeConfig({});

  assert.equal(cfg.POW_EQ_N, 90);
  assert.equal(cfg.POW_EQ_K, 5);

  assert.equal("POW_CHAL_ROUNDS" in cfg, false);
  assert.equal("POW_SAMPLE_K" in cfg, false);
  assert.equal("POW_OPEN_BATCH" in cfg, false);
  assert.equal("POW_SEGMENT_LEN" in cfg, false);
  assert.equal("POW_PAGE_BYTES" in cfg, false);
  assert.equal("POW_MIX_ROUNDS" in cfg, false);
  assert.equal("POW_HASHCASH_BITS" in cfg, false);
  assert.equal("POW_COMMIT_TTL_SEC" in cfg, false);
  assert.equal("POW_MAX_GEN_TIME_SEC" in cfg, false);
  assert.equal("POW_COMMIT_COOKIE" in cfg, false);

  // Non-PoW controls remain available on normalized config.
  assert.equal(cfg.PROOF_TTL_SEC, 600);
  assert.equal(cfg.ATOMIC_CONSUME, false);
  assert.equal(cfg.POW_TICKET_TTL_SEC, 600);
});

test("pow-config normalizes equihash k bounds", () => {
  const valid = __testNormalizeConfig({ POW_EQ_N: 96, POW_EQ_K: 7 });
  assert.equal(valid.POW_EQ_K, 7);
  assert.equal(valid.POW_EQ_N, 96);

  const low = __testNormalizeConfig({ POW_EQ_K: 1 });
  assert.equal(low.POW_EQ_K, 5);

  const high = __testNormalizeConfig({ POW_EQ_K: 20 });
  assert.equal(high.POW_EQ_K, 5);

  const nonInteger = __testNormalizeConfig({ POW_EQ_K: 4.5 });
  assert.equal(nonInteger.POW_EQ_K, 5);

  const highButLegacy = __testNormalizeConfig({ POW_EQ_N: 250, POW_EQ_K: 9 });
  assert.equal(highButLegacy.POW_EQ_K, 5);
  assert.equal(highButLegacy.POW_EQ_N, 90);
});

test("pow-config enforces coupled equihash n/k validity", () => {
  const validPair = __testNormalizeConfig({ POW_EQ_N: 96, POW_EQ_K: 5 });
  assert.equal(validPair.POW_EQ_N, 96);
  assert.equal(validPair.POW_EQ_K, 5);

  const invalidModulo = __testNormalizeConfig({ POW_EQ_N: 96, POW_EQ_K: 8 });
  assert.equal(invalidModulo.POW_EQ_N, 90);
  assert.equal(invalidModulo.POW_EQ_K, 5);

  const invalidOddN = __testNormalizeConfig({ POW_EQ_N: 95, POW_EQ_K: 4 });
  assert.equal(invalidOddN.POW_EQ_N, 90);
  assert.equal(invalidOddN.POW_EQ_K, 5);
});

test("pow-config preserves configurable POW_API_PREFIX with normalization", () => {
  const custom = __testNormalizeConfig({ POW_API_PREFIX: "pow-api/" });
  assert.equal(custom.POW_API_PREFIX, "/pow-api");

  const empty = __testNormalizeConfig({ POW_API_PREFIX: "   " });
  assert.equal(empty.POW_API_PREFIX, "/__pow");
});

test("pow-config strips legacy commit/hashcash knobs from input", () => {
  const cfg = __testNormalizeConfig({
    POW_HASHCASH_BITS: 9,
    POW_COMMIT_TTL_SEC: 120,
    POW_MAX_GEN_TIME_SEC: 300,
    POW_COMMIT_COOKIE: "__Host-pow_commit",
  });

  assert.equal("POW_HASHCASH_BITS" in cfg, false);
  assert.equal("POW_COMMIT_TTL_SEC" in cfg, false);
  assert.equal("POW_MAX_GEN_TIME_SEC" in cfg, false);
  assert.equal("POW_COMMIT_COOKIE" in cfg, false);
});
