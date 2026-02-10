import test from "node:test";
import assert from "node:assert/strict";

const subtle = globalThis.crypto?.subtle;
const enc = new TextEncoder();

const u32be = (value) => {
  const out = new Uint8Array(4);
  const v = value >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

const concat = (...chunks) => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const sha256 = async (...chunks) => new Uint8Array(await subtle.digest("SHA-256", concat(...chunks)));

test("leaf hash binds index", async () => {
  const { leafHash } = await import("../../lib/mhg/merkle.js");
  const page = new Uint8Array(64);
  const leaf1 = await leafHash(1, page);
  const leaf2 = await leafHash(2, page);
  assert.notDeepEqual(Buffer.from(leaf1), Buffer.from(leaf2));
});

test("merkle prefixes follow whitepaper constants", async () => {
  const { leafHash, nodeHash } = await import("../../lib/mhg/merkle.js");
  const page = Uint8Array.from({ length: 64 }, (_, i) => i);
  const expectedLeaf = await sha256(enc.encode("MHG1-LEAF"), u32be(7), page);
  const actualLeaf = await leafHash(7, page);
  assert.deepEqual(Buffer.from(actualLeaf), Buffer.from(expectedLeaf));

  const left = Uint8Array.from({ length: 32 }, (_, i) => i);
  const right = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
  const expectedNode = await sha256(enc.encode("MHG1-NODE"), left, right);
  const actualNode = await nodeHash(left, right);
  assert.deepEqual(Buffer.from(actualNode), Buffer.from(expectedNode));
});

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
