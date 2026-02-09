import test from "node:test";
import assert from "node:assert/strict";

test("parents are deterministic and in-range", async () => {
  const { parentsOf } = await import("../../lib/mhg/graph.js");
  const seed = new Uint8Array(16);

  const a = await parentsOf(100, seed);
  const b = await parentsOf(100, seed);

  assert.deepEqual(a, b);
  assert.equal(a.p0, 99);
  assert.ok(a.p1 >= 0 && a.p1 < 100);
  assert.ok(a.p2 >= 0 && a.p2 < 100);
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
