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

test("default sampling covers every bucket with a non-anchor index", () => {
  const maxIndex = 8192;
  const extraCount = computePowSampleExtraCount(maxIndex, 0.01);
  const out = sampleIndicesDeterministicV2({
    maxIndex,
    extraCount,
    forceEdge1: true,
    forceEdgeLast: true,
    rng: makeXoshiro128ss(new Uint8Array(16).fill(7)),
  });

  assert.equal(extraCount, 80);
  assert.equal(out.length, 82);
  assert.deepEqual(out.slice(0, 2), [1, maxIndex]);
  assert.equal(new Set(out).size, out.length);

  const coveredBuckets = new Set(
    out.slice(2).map((index) => Math.floor(((index - 1) * 64) / maxIndex)),
  );
  assert.equal(coveredBuckets.size, 64);
  assert.ok(out.slice(2).every((index) => index > 1 && index < maxIndex));

  const rerun = sampleIndicesDeterministicV2({
    maxIndex,
    extraCount,
    forceEdge1: true,
    forceEdgeLast: true,
    rng: makeXoshiro128ss(new Uint8Array(16).fill(7)),
  });
  assert.deepEqual(rerun, out);
});

test("low budgets select a shuffled subset of non-anchor buckets", () => {
  const maxIndex = 8192;
  const out = sampleIndicesDeterministicV2({
    maxIndex,
    extraCount: 8,
    forceEdge1: true,
    forceEdgeLast: true,
    rng: makeXoshiro128ss(new Uint8Array(16).fill(9)),
  });

  assert.equal(out.length, 10);
  assert.deepEqual(out.slice(0, 2), [1, maxIndex]);
  const coveredBuckets = new Set(
    out.slice(2).map((index) => Math.floor(((index - 1) * 64) / maxIndex)),
  );
  assert.equal(coveredBuckets.size, 8);
  assert.ok(out.slice(2).every((index) => index > 1 && index < maxIndex));
});

test("bucket draws refill around forced endpoint selections", () => {
  const sample = (randInt) =>
    sampleIndicesDeterministicV2({
      maxIndex: 257,
      extraCount: 2,
      forceEdge1: true,
      forceEdgeLast: true,
      rng: { shuffle: (values) => values, randInt },
    });

  const lower = sample(() => 0);
  const upper = sample((span) => span - 1);
  assert.deepEqual(lower, [1, 257, 2, 129]);
  assert.deepEqual(upper, [1, 257, 128, 256]);
});

test("sampling respects tiny graphs, bounds, and exact budgets", () => {
  for (const maxIndex of [1, 2, 3, 127, 128, 129, 255, 256, 257]) {
    for (const extraCount of [0, 1, 2, 7, maxIndex]) {
      for (const forceEdge1 of [false, true]) {
        for (const forceEdgeLast of [false, true]) {
          const anchors = [
            ...new Set([
              ...(forceEdge1 ? [1] : []),
              ...(forceEdgeLast ? [maxIndex] : []),
            ]),
          ];
          const out = sampleIndicesDeterministicV2({
            maxIndex,
            extraCount,
            forceEdge1,
            forceEdgeLast,
            rng: makeXoshiro128ss(new Uint8Array(16).fill(maxIndex)),
          });
          assert.equal(out.length, Math.min(maxIndex, anchors.length + extraCount));
          assert.equal(new Set(out).size, out.length);
          assert.ok(out.every((index) => Number.isInteger(index) && index >= 1 && index <= maxIndex));
          assert.deepEqual(out.slice(0, anchors.length), anchors);
        }
      }
    }
  }
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
