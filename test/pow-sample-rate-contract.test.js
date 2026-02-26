import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizePowSampleRate,
  computePowSampleExtraCount,
  sampleIndicesDeterministicV2,
  makeXoshiro128ss,
  parseSegmentLenSpec,
  computeSegLensForIndices,
  derivePowSeedBytes16,
  deriveSegLenSeed16,
} from "../lib/pow/api-protocol-shared.js";

test("normalizePowSampleRate accepts float and clamps", () => {
  assert.equal(normalizePowSampleRate(0.01), 0.01);
  assert.equal(normalizePowSampleRate(2), 1);
  assert.equal(normalizePowSampleRate(0), 0.01);
});

test("computePowSampleExtraCount uses ceil(L*rate) with anchors", () => {
  assert.equal(computePowSampleExtraCount(8192, 0.01), 80);
  assert.equal(computePowSampleExtraCount(20, 0.5), 8);
  assert.equal(computePowSampleExtraCount(1, 0.5), 0);
});

test("sampleIndicesDeterministicV2 keeps edge anchors", () => {
  const rng = makeXoshiro128ss(new Uint8Array(16).fill(7));
  const out = sampleIndicesDeterministicV2({
    maxIndex: 20,
    extraCount: 0,
    forceEdge1: true,
    forceEdgeLast: true,
    rng,
  });
  assert.equal(out[0], 1);
  assert.equal(out[1], 20);
});

test("shared deterministic helpers are exported and usable", async () => {
  assert.deepEqual(parseSegmentLenSpec(4), { mode: "fixed", fixed: 4 });
  assert.deepEqual(parseSegmentLenSpec("2-4"), { mode: "range", min: 2, max: 4 });

  const rng = makeXoshiro128ss(new Uint8Array(16).fill(3));
  const segs = computeSegLensForIndices([1, 2, 3], parseSegmentLenSpec("2-4"), rng);
  assert.equal(segs.length, 3);
  for (const value of segs) {
    assert.ok(value >= 2 && value <= 4);
  }

  const seedA = await derivePowSeedBytes16("pow-secret", 7, "commitMac", "sid");
  const seedB = await derivePowSeedBytes16("pow-secret", 7, "commitMac", "sid");
  assert.equal(seedA.length, 16);
  assert.deepEqual(seedA, seedB);

  const segSeedA = await deriveSegLenSeed16("pow-secret", 7, "commitMac", "sid");
  const segSeedB = await deriveSegLenSeed16("pow-secret", 7, "commitMac", "sid");
  assert.equal(segSeedA.length, 16);
  assert.deepEqual(segSeedA, segSeedB);
});
