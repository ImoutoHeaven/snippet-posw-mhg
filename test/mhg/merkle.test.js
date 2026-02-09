import test from "node:test";
import assert from "node:assert/strict";

test("merkle proof verifies for odd leaf count", async () => {
  const { buildMerkle, buildProof, verifyProof } = await import("../../lib/mhg/merkle.js");
  const pages = [new Uint8Array(64), new Uint8Array(64), new Uint8Array(64)];

  const tree = await buildMerkle(pages);
  const proof = buildProof(tree, 2);

  const ok = await verifyProof({
    root: tree.root,
    index: 2,
    page: pages[2],
    proof,
    leafCount: 3,
  });

  assert.equal(ok, true);
});
