import test from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

import { blake2b } from "../../lib/equihash/blake2b.js";
import { verifyEquihash } from "../../lib/equihash/verify.js";

const encoder = new TextEncoder();

const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));

// Fixed vector generated offline with Python hashlib.blake2b (not runtime oracle generation).
const FIXTURE = {
  n: 24,
  k: 2,
  seed: encoder.encode("eqh-fixed-seed-v1"),
  nonce: encoder.encode("eqh-fixed-nonce!"),
  proof: hexToBytes("00000000000000ea000013b300001614"),
  indices: [0, 234, 5043, 5652],
  // Expected 24-bit hash words for each index from the same offline Python fixture script.
  indexWordHex: ["5ad91e", "5a73e1", "f3e364", "f3499b"],
};

const packU32be = (n) => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

const hashWordHex = ({ seed, nonce, index, n, k }) => {
  const input = new Uint8Array(seed.length + nonce.length + 4);
  input.set(seed, 0);
  input.set(nonce, seed.length);
  input.set(packU32be(index), seed.length + nonce.length);

  const personalization = new Uint8Array(16);
  personalization.set(encoder.encode("ZcashPoW"));
  const view = new DataView(personalization.buffer);
  view.setUint32(8, n >>> 0, true);
  view.setUint32(12, k >>> 0, true);

  const digest = blake2b(input, Math.ceil(n / 8), { personalization });
  return Buffer.from(digest).toString("hex");
};

const measure = (fn, iterations) => {
  for (let i = 0; i < 3; i += 1) {
    fn();
  }
  const times = [];
  for (let i = 0; i < iterations; i += 1) {
    const t0 = performance.now();
    fn();
    times.push(performance.now() - t0);
  }
  times.sort((a, b) => a - b);
  const median = times[Math.floor(times.length / 2)];
  const p95 = times[Math.floor(times.length * 0.95)];
  return { median, p95 };
};

const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
};

const assertThreshold = (value, limit, label) => {
  assert.ok(
    value <= limit,
    `${label} regression: expected <= ${limit.toFixed(3)}ms, got ${value.toFixed(3)}ms`,
  );
};

test("equihash fixed-vector acceptance and tamper reject", () => {
  assert.equal(verifyEquihash(FIXTURE), true);

  const tampered = FIXTURE.proof.slice();
  tampered[tampered.length - 1] ^= 0x01;
  assert.equal(verifyEquihash({ ...FIXTURE, proof: tampered }), false);
});

test("equihash serialized cross-check fixture guards endianness/personalization", () => {
  for (let i = 0; i < FIXTURE.indices.length; i += 1) {
    const computed = hashWordHex({
      seed: FIXTURE.seed,
      nonce: FIXTURE.nonce,
      index: FIXTURE.indices[i],
      n: FIXTURE.n,
      k: FIXTURE.k,
    });
    assert.equal(computed, FIXTURE.indexWordHex[i]);
  }
});

test("equihash verifier fails closed on malformed proof shape", () => {
  assert.equal(verifyEquihash({ ...FIXTURE, proof: FIXTURE.proof.subarray(0, FIXTURE.proof.length - 1) }), false);

  const dup = FIXTURE.proof.slice();
  dup.set(dup.subarray(0, 4), 4);
  assert.equal(verifyEquihash({ ...FIXTURE, proof: dup }), false);

  const reordered = FIXTURE.proof.slice();
  reordered.set(FIXTURE.proof.subarray(4, 8), 0);
  reordered.set(FIXTURE.proof.subarray(0, 4), 4);
  assert.equal(verifyEquihash({ ...FIXTURE, proof: reordered }), false);

  assert.equal(verifyEquihash({ ...FIXTURE, proof: "not-bytes" }), false);
  assert.equal(verifyEquihash({ ...FIXTURE, proof: null }), false);
});

test("equihash verifier never throws on malformed input", () => {
  const malformedInputs = [
    null,
    undefined,
    "bad",
    1,
    {},
    { seed: new Uint8Array([1]), nonce: new Uint8Array([2]), proof: new Uint8Array(1), n: 24, k: 2 },
    { seed: {}, nonce: {}, proof: {}, n: "x", k: "y" },
    { seed: new Uint8Array(10), nonce: new Uint8Array(10), proof: new Uint8Array(7), n: 90, k: 5 },
  ];

  for (const input of malformedInputs) {
    assert.doesNotThrow(() => {
      const out = verifyEquihash(input);
      assert.equal(typeof out, "boolean");
    });
  }
});

test("equihash verifier supports n=90 k=5 malformed early reject", () => {
  const seed = encoder.encode("seed:n90k5");
  const nonce = encoder.encode("nonce:n90k5");
  const expectedProofBytes = (1 << 5) * 4;
  const malformedProof = new Uint8Array(expectedProofBytes - 1);
  assert.equal(verifyEquihash({ seed, nonce, proof: malformedProof, n: 90, k: 5 }), false);
});

test("equihash verifier enforces hard-cut n/k bounds and coupling", () => {
  const seed = encoder.encode("seed:eq-params");
  const nonce = encoder.encode("nonce:eq-params");
  const proof = new Uint8Array((1 << 5) * 4);

  assert.equal(verifyEquihash({ seed, nonce, proof, n: 95, k: 5 }), false);
  assert.equal(verifyEquihash({ seed, nonce, proof, n: 90, k: 1 }), false);
  assert.equal(verifyEquihash({ seed, nonce, proof, n: 250, k: 9 }), false);
  assert.equal(verifyEquihash({ seed, nonce, proof, n: 96, k: 8 }), false);
});

test("equihash verifier telemetry: valid and malformed input timings", (t) => {
  const validStats = measure(() => {
    assert.equal(verifyEquihash(FIXTURE), true);
  }, 35);

  const malformed = FIXTURE.proof.subarray(0, FIXTURE.proof.length - 1);
  const malformedInput = { ...FIXTURE, proof: malformed };
  const malformedStats = measure(() => {
    assert.equal(verifyEquihash(malformedInput), false);
  }, 75);

  const batchInput = FIXTURE;
  // Capture several p95 windows and use the median window to reduce CI scheduler jitter.
  const batchP95Windows = Array.from({ length: 5 }, () =>
    measure(() => {
      for (let i = 0; i < 25; i += 1) {
        verifyEquihash(batchInput);
      }
    }, 12).p95,
  );
  const batchP95 = median(batchP95Windows);

  assertThreshold(validStats.median, 5, "single verify median");
  assertThreshold(batchP95, 12, "batch verify p95");
  assertThreshold(malformedStats.p95, 2, "malformed reject p95");

  t.diagnostic(
    `equihash timings ms: singleMedian=${validStats.median.toFixed(3)} `
      + `batchP95=${batchP95.toFixed(3)} windows=${batchP95Windows.map((v) => v.toFixed(3)).join(",")} `
      + `malformedP95=${malformedStats.p95.toFixed(3)}`,
  );
});
