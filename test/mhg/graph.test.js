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

test("deriveDynamicParent2 binds to full prevPage hash, not top32", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const { sha256, u32be } = await import("../../lib/mhg/hash.js");

  const resolveCandidate = (candidate, i, p0, p1) => {
    let x = candidate;
    for (let checks = 0; checks < 3; checks += 1) {
      if (x !== p0 && x !== p1) return x;
      x = (x + 1) % i;
    }
    throw new Error("parent invariants violated");
  };

  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 1);
  const i = 37;
  const pageBytes = 64;
  const p0 = 36;
  const p1 = 7;

  const pageA = new Uint8Array(64);
  pageA.set([0, 0, 0, 9], 0);

  const expectedFromPage = async (page) => {
    const h = await sha256("MHG1-P2", seed, u32be(i), u32be(pageBytes), page);
    const c = new DataView(h.buffer, h.byteOffset, h.byteLength).getUint32(0, false) % i;
    return resolveCandidate(c, i, p0, p1);
  };

  const pageB = pageA.slice();
  const p2AExpected = await expectedFromPage(pageA);
  let p2BExpected = p2AExpected;
  for (let x = 1; x <= 255; x += 1) {
    pageB[63] = x;
    p2BExpected = await expectedFromPage(pageB);
    if (p2BExpected !== p2AExpected) break;
  }
  assert.deepEqual(pageA.subarray(0, 4), pageB.subarray(0, 4));
  assert.notEqual(p2AExpected, p2BExpected);

  const p2A = await deriveDynamicParent2({ i, seed, prevPage: pageA, pageBytes, p0, p1 });
  const p2B = await deriveDynamicParent2({ i, seed, prevPage: pageB, pageBytes, p0, p1 });

  assert.equal(p2A, p2AExpected);
  assert.equal(p2B, p2BExpected);
});

test("deriveDynamicParent2 keeps wraparound probing invariants under hash candidate collisions", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const { sha256, u32be } = await import("../../lib/mhg/hash.js");

  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 9);
  const i = 4;
  const pageBytes = 64;
  const p0 = 3;
  const p1 = 0;

  const page = new Uint8Array(64);
  let forced = false;
  for (let x = 0; x <= 255; x += 1) {
    page[63] = x;
    const h = await sha256("MHG1-P2", seed, u32be(i), u32be(pageBytes), page);
    const c = new DataView(h.buffer, h.byteOffset, h.byteLength).getUint32(0, false) % i;
    if (c === p0) {
      forced = true;
      break;
    }
  }
  assert.equal(forced, true);

  const p2 = await deriveDynamicParent2({ i, seed, prevPage: page, pageBytes, p0, p1 });
  assert.equal(p2, 1);
});

test("parentsOf derives full-page-hash p2 from prevPage for i>=3", async () => {
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

test("parentsOf enforces full-page prevPage contract for i>=3", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = new Uint8Array(16);

  await assert.rejects(
    async () => parentsOf(3, seed),
    /pageBytes must be an integer >= 16 and multiple of 16/
  );
  await assert.rejects(
    async () => parentsOf(3, seed, "bad"),
    /pageBytes must be an integer >= 16 and multiple of 16/
  );
  await assert.rejects(
    async () => parentsOf(3, seed, new Uint8Array(64), 32),
    /prevPage must be Uint8Array exactly matching pageBytes for full-page p2 derivation/
  );
});

test("deriveDynamicParent2 fails closed on invariant violations", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const seed = Uint8Array.from({ length: 16 }, (_, idx) => idx + 3);
  const pageBytes = 64;
  const prevPage = new Uint8Array(pageBytes);

  await assert.rejects(
    async () => deriveDynamicParent2({ i: 4, seed, prevPage, pageBytes, p0: 9, p1: 1 }),
    /parent invariants violated/
  );
});

test("deriveDynamicParent2 requires seed-bound dynamic parent contract for i>=3", async () => {
  const { deriveDynamicParent2 } = await import("../../lib/mhg/graph.js");
  const prevPage = new Uint8Array(64);

  await assert.rejects(
    async () => deriveDynamicParent2({ i: 5, prevPage, pageBytes: 64, p0: 4, p1: 0 }),
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
