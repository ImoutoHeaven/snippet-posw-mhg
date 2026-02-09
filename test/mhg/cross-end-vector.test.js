import test from "node:test";
import assert from "node:assert/strict";

import { buildCrossEndFixture } from "../../esm/mhg-worker.js";
import { verifyOpenBatchVector } from "../../lib/mhg/verify.js";

test("fixed vectors produce cross-end consistent verification", async () => {
  const vec = {
    graphSeedHex: "00112233445566778899aabbccddeeff",
    nonceHex: "0f0e0d0c0b0a09080706050403020100",
    pageBytes: 64,
    pages: 128,
    indices: [1, 64, 127],
  };
  const fixture = await buildCrossEndFixture(vec);
  const out = await verifyOpenBatchVector(fixture);
  assert.equal(out.ok, true);
});

test("1-bit tamper is rejected by server verification", async () => {
  const vec = {
    graphSeedHex: "00112233445566778899aabbccddeeff",
    nonceHex: "0f0e0d0c0b0a09080706050403020100",
    pageBytes: 64,
    pages: 128,
    indices: [64],
  };
  const fixture = await buildCrossEndFixture(vec, {
    mutatePages: (pages) => {
      pages[63] = pages[63].slice();
      pages[63][0] ^= 0x01;
    },
  });
  const out = await verifyOpenBatchVector(fixture);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "equation_failed");
});
