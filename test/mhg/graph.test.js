import test from "node:test";
import assert from "node:assert/strict";

const U32_MAX_PLUS_ONE = 0x1_0000_0000;

const u32be = (value) => {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, false);
  return out;
};

const asU32 = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false);
};

const referenceDraw32 = async ({ seed, label, i, ctr }) => {
  const { sha256 } = await import("../../lib/mhg/hash.js");
  const digest = await sha256("MHG1-PRF", seed, label, u32be(i), u32be(ctr));
  return asU32(digest.subarray(0, 4));
};

const referencePickDistinct = async ({ seed, i, label, exclude }) => {
  const limit = Math.floor(U32_MAX_PLUS_ONE / i) * i;
  let ctr = 0;
  while (true) {
    const n = await referenceDraw32({ seed, label, i, ctr });
    ctr += 1;
    if (n >= limit) continue;
    const pick = n % i;
    if (exclude.has(pick)) continue;
    return pick;
  }
};

const referenceStaticParentsOf = async (i, seed) => {
  const p0 = i - 1;
  const p1 = await referencePickDistinct({ seed, i, label: "p1", exclude: new Set([p0]) });
  return { p0, p1 };
};

const oracleP2V4 = async ({ i, seed, pageBytes, p0, p1, p0Page, p1Page }) => {
  const { sha256 } = await import("../../lib/mhg/hash.js");
  const seedP2 = await sha256("MHG1-P2|v4", seed, u32be(i), u32be(pageBytes), p0Page, p1Page);
  const limit = Math.floor(U32_MAX_PLUS_ONE / i) * i;
  let ctr = 0;
  while (true) {
    const n = await referenceDraw32({ seed: seedP2, label: "p2", i, ctr });
    ctr += 1;
    if (n >= limit) continue;
    const pick = n % i;
    if (pick === p0 || pick === p1) continue;
    return pick;
  }
};

test("graph parent API no longer exports parentsOf", async () => {
  const graph = await import("../../lib/mhg/graph.js");
  const parentContract = await import("../../lib/mhg/parent-contract.js");

  assert.equal("parentsOf" in graph, false);
  assert.equal("parentsOf" in parentContract, false);
});

test("uniformMod fails closed when PRF cannot produce an acceptable sample", async () => {
  const { uniformMod } = await import("../../lib/mhg/graph.js");
  const subtleDigest = globalThis.crypto.subtle.digest;
  let digestCalls = 0;
  globalThis.crypto.subtle.digest = async () => {
    digestCalls += 1;
    if (digestCalls % 128 === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    return new Uint8Array(32).fill(0xff);
  };
  const stuckSampling = uniformMod({ seed: new Uint8Array(16), label: "p1", i: 3, mod: 3 })
    .then(() => "resolved")
    .catch((err) => `rejected:${err.message}`);

  try {
    const outcome = await Promise.race([
      stuckSampling,
      new Promise((resolve) => setTimeout(() => resolve("timeout"), 300)),
    ]);

    assert.match(outcome, /^rejected:/);
  } finally {
    globalThis.crypto.subtle.digest = async () => {
      throw new Error("forced-stop");
    };
    await Promise.race([
      stuckSampling.catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, 50)),
    ]);
    globalThis.crypto.subtle.digest = subtleDigest;
  }
});

test("uniformMod rejects mod > 2^32 before sampling", async () => {
  const { uniformMod } = await import("../../lib/mhg/graph.js");
  const subtleDigest = globalThis.crypto.subtle.digest;
  let digestCalls = 0;
  globalThis.crypto.subtle.digest = async (...args) => {
    digestCalls += 1;
    return subtleDigest.call(globalThis.crypto.subtle, ...args);
  };

  try {
    await assert.rejects(
      uniformMod({ seed: new Uint8Array(16), label: "p1", i: 3, mod: U32_MAX_PLUS_ONE + 1 }),
      {
        name: "RangeError",
        message: /mod must be a positive integer <= 4294967296/,
      }
    );
    assert.equal(digestCalls, 0);
  } finally {
    globalThis.crypto.subtle.digest = subtleDigest;
  }
});

test("deriveDynamicParent2 fast-fails when uniformModExclude mod exceeds 2^32", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const subtleDigest = globalThis.crypto.subtle.digest;
  const decoder = new TextDecoder();
  let prfCalls = 0;
  let totalDigestCalls = 0;

  globalThis.crypto.subtle.digest = async (...args) => {
    totalDigestCalls += 1;
    const payload = args[1];
    const bytes = payload instanceof ArrayBuffer
      ? new Uint8Array(payload)
      : new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
    if (decoder.decode(bytes.subarray(0, 8)) === "MHG1-PRF") {
      prfCalls += 1;
    }
    return subtleDigest.call(globalThis.crypto.subtle, ...args);
  };

  try {
    await assert.rejects(
      deriveDynamicParent2({
        i: U32_MAX_PLUS_ONE + 1,
        seed: new Uint8Array(16),
        pageBytes: 64,
        p0: 1,
        p1: 2,
        p0Page: new Uint8Array(64),
        p1Page: new Uint8Array(64),
      }),
      {
        name: "RangeError",
        message: /mod must be a positive integer <= 4294967296/,
      }
    );
    assert.equal(prfCalls, 0);
    assert.equal(totalDigestCalls > 0, true);
  } finally {
    globalThis.crypto.subtle.digest = subtleDigest;
  }
});

test("staticParentsOf returns p0=i-1 and PRF p1", async () => {
  const { staticParentsOf } = await import("../../lib/mhg/graph.js");
  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 1);

  const expected = await referenceStaticParentsOf(37, seed);
  const actual = await staticParentsOf(37, seed);

  assert.deepEqual(actual, expected);
  assert.equal(actual.p0, 36);
  assert.notEqual(actual.p1, actual.p0);
  assert.ok(actual.p1 >= 0 && actual.p1 < 37);
});

test("deriveDynamicParent2 uses v4 dual-page rejection-sampling contract", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");

  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 1);
  const i = 37;
  const pageBytes = 64;
  const p0 = 36;
  const p1 = 7;
  const p0Page = Uint8Array.from({ length: pageBytes }, (_, idx) => (idx + 3) % 251);
  const p1Page = Uint8Array.from({ length: pageBytes }, (_, idx) => (idx * 7 + 11) % 251);

  const p2BaseExpected = await oracleP2V4({ i, seed, pageBytes, p0, p1, p0Page, p1Page });
  const p2Base = await deriveDynamicParent2({ i, seed, pageBytes, p0, p1, p0Page, p1Page });
  assert.equal(p2Base, p2BaseExpected);

  const p0PageVariant = p0Page.slice();
  let p2P0VariantExpected = p2BaseExpected;
  for (let x = 1; x <= 255; x += 1) {
    p0PageVariant[p0PageVariant.length - 1] = x;
    p2P0VariantExpected = await oracleP2V4({
      i,
      seed,
      pageBytes,
      p0,
      p1,
      p0Page: p0PageVariant,
      p1Page,
    });
    if (p2P0VariantExpected !== p2BaseExpected) break;
  }
  assert.notEqual(p2P0VariantExpected, p2BaseExpected);
  const p2P0Variant = await deriveDynamicParent2({
    i,
    seed,
    pageBytes,
    p0,
    p1,
    p0Page: p0PageVariant,
    p1Page,
  });
  assert.equal(p2P0Variant, p2P0VariantExpected);
  assert.notEqual(p2P0Variant, p2Base);

  const p1PageVariant = p1Page.slice();
  let p2P1VariantExpected = p2BaseExpected;
  for (let x = 1; x <= 255; x += 1) {
    p1PageVariant[p1PageVariant.length - 1] = x;
    p2P1VariantExpected = await oracleP2V4({
      i,
      seed,
      pageBytes,
      p0,
      p1,
      p0Page,
      p1Page: p1PageVariant,
    });
    if (p2P1VariantExpected !== p2BaseExpected) {
      break;
    }
  }
  assert.notEqual(p2P1VariantExpected, p2BaseExpected);
  const p2P1Variant = await deriveDynamicParent2({
    i,
    seed,
    pageBytes,
    p0,
    p1,
    p0Page,
    p1Page: p1PageVariant,
  });
  assert.equal(p2P1Variant, p2P1VariantExpected);
  assert.notEqual(p2P1Variant, p2Base);
});

test("deriveDynamicParent2 enforces dual-page invariants", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 5);
  const pageBytes = 64;
  const p0Page = new Uint8Array(pageBytes);
  const p1Page = new Uint8Array(pageBytes);

  await assert.rejects(
    async () => deriveDynamicParent2({ i: 9, seed, pageBytes, p0: 8, p1: 1, p1Page }),
    /p0Page must be Uint8Array exactly matching pageBytes/
  );
  await assert.rejects(
    async () => deriveDynamicParent2({ i: 9, seed, pageBytes, p0: 8, p1: 1, p0Page, p1Page: new Uint8Array(32) }),
    /p1Page must be Uint8Array exactly matching pageBytes/
  );
});

test("deriveDynamicParent2 fails closed on invariant violations", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 3);
  const pageBytes = 64;
  const p0Page = new Uint8Array(pageBytes);
  const p1Page = new Uint8Array(pageBytes);

  await assert.rejects(
    async () => deriveDynamicParent2({ i: 4, seed, pageBytes, p0: 9, p1: 1, p0Page, p1Page }),
    /parent invariants violated/
  );
});

test("deriveDynamicParent2 requires seed-bound dynamic parent contract for i>=3", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const p0Page = new Uint8Array(64);
  const p1Page = new Uint8Array(64);

  await assert.rejects(
    async () => deriveDynamicParent2({ i: 5, pageBytes: 64, p0: 4, p1: 0, p0Page, p1Page }),
    /seed must be Uint8Array/
  );
});

test("sampling always includes edge_1 and edge_last", async () => {
  const { sampleIndices } = await import("../../lib/mhg/graph.js");

  const out = await sampleIndices({
    maxIndex: 8191,
    count: 32,
    seed: new Uint8Array(16),
  });

  assert.equal(out.includes(1), true);
  assert.equal(out.includes(8191), true);
});
