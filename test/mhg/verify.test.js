import test from "node:test";
import assert from "node:assert/strict";

test("segmentLen=2 verifies equation closure", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const out = await verifyBatch({ fixture: "valid-seg2" });
  assert.equal(out.ok, true);
});

test("segmentLen=1 still verifies predecessor relation", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const ok = await verifyBatch({ fixture: "valid-seg1-predecessor" });
  assert.equal(ok.ok, true);

  const bad = await verifyBatch({ fixture: "tampered-seg1-current-only" });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, "equation_failed");
});

test("segmentLen normalizes by floor+clamp", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const out = await verifyBatch({ fixture: "valid-seg2", segmentLen: 0.6 });
  assert.equal(out.ok, true);
});
