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

const pageWithTop32 = (value) => {
  const page = new Uint8Array(16);
  page.set(u32be(value >>> 0), 0);
  return page;
};

test("parentsOf keeps boundary semantics for i=1 and i=2", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = new Uint8Array(16);

  assert.deepEqual(await parentsOf(1, seed), { p0: 0, p1: 0, p2: 0 });
  assert.deepEqual(await parentsOf(2, seed), { p0: 1, p1: 0, p2: 0 });
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

test("deriveDynamicParent2 uses Top32(prevPage)%i with deterministic probing", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");

  // i=3, p0=2, p1=0, j0=2 -> collide with p0, then 0 -> collide with p1, then 1 -> return.
  const p2 = deriveDynamicParent2({ i: 3, prevPage: pageWithTop32(2), p0: 2, p1: 0 });
  assert.equal(p2, 1);
});

test("deriveDynamicParent2 probes with wraparound on small i", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");

  // i=4, p0=3, p1=0, j0=3 -> 0 -> 1
  const p2 = deriveDynamicParent2({ i: 4, prevPage: pageWithTop32(3), p0: 3, p1: 0 });
  assert.equal(p2, 1);
});

test("parentsOf derives hybrid p2 from prevPage for i>=3", async () => {
  const { parentsOf, staticParentsOf } = await import("../../lib/mhg/graph.js");
  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 11);

  const { p0, p1 } = await staticParentsOf(10, seed);
  const prevPage = pageWithTop32(p0);
  const result = await parentsOf(10, seed, prevPage);

  assert.equal(result.p0, p0);
  assert.equal(result.p1, p1);
  assert.ok(result.p2 >= 0 && result.p2 < 10);
  assert.notEqual(result.p2, p0);
  assert.notEqual(result.p2, p1);
});

test("parentsOf requires prevPage for i>=3", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = new Uint8Array(16);

  await assert.rejects(
    () => parentsOf(3, seed),
    /prevPage must be Uint8Array with length >= 4 for i >= 3/
  );
  await assert.rejects(
    () => parentsOf(3, seed, "bad"),
    /prevPage must be Uint8Array with length >= 4 for i >= 3/
  );
  await assert.rejects(
    () => parentsOf(3, seed, new Uint8Array(3)),
    /prevPage must be Uint8Array with length >= 4 for i >= 3/
  );
});

test("deriveDynamicParent2 fails closed on invariant violations", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");

  assert.throws(
    () => deriveDynamicParent2({ i: 4, prevPage: pageWithTop32(0), p0: 9, p1: 1 }),
    /parent invariants violated/
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
