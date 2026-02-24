import test from "node:test";
import assert from "node:assert/strict";
import { parentsOf } from "../../lib/mhg/graph.js";
import { makeGenesisPage, mixPage } from "../../lib/mhg/mix-aes.js";
import { buildMerkle, buildProof } from "../../lib/mhg/merkle.js";

const b64u = (bytes) =>
  Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const makeOpenVector = async ({ omit = [] } = {}) => {
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 16 - i);
  const pageBytes = 64;

  const p0 = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  const p1 = await mixPage({ i: 1, p0, p1: p0, p2: p0, graphSeed, nonce, pageBytes });
  const p2 = await mixPage({ i: 2, p0: p1, p1: p0, p2: p0, graphSeed, nonce, pageBytes });
  const pages = [p0, p1, p2];
  const tree = await buildMerkle(pages);
  const need = new Set([2]);
  const e = [2];
  for (const j of e) {
    const p = await parentsOf(j, graphSeed);
    need.add(p.p0);
    need.add(p.p1);
    need.add(p.p2);
  }
  const nodes = {};
  for (const idx of need) {
    if (omit.includes(idx)) continue;
    nodes[String(idx)] = {
      pageB64: b64u(pages[idx]),
      proof: buildProof(tree, idx).map((x) => b64u(x)),
    };
  }

  return {
    root: tree.root,
    leafCount: tree.leafCount,
    graphSeed,
    nonce,
    pageBytes,
    opens: [{ i: 2, seg: 1, nodes }],
  };
};

const makeDynamicOpenVector = async ({ steps = 40, seg = 4, omit = [] } = {}) => {
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 16 - i);
  const pageBytes = 64;

  const pages = new Array(steps + 1);
  const parentByIndex = {};
  pages[0] = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  for (let i = 1; i <= steps; i += 1) {
    const p = await parentsOf(i, graphSeed, i >= 3 ? pages[i - 1] : undefined);
    parentByIndex[i] = p;
    pages[i] = await mixPage({
      i,
      p0: pages[p.p0],
      p1: pages[p.p1],
      p2: pages[p.p2],
      graphSeed,
      nonce,
      pageBytes,
    });
  }

  const tree = await buildMerkle(pages);
  const need = new Set();
  const eqStart = Math.max(1, steps - seg + 1);
  for (let j = eqStart; j <= steps; j += 1) {
    const p = await parentsOf(j, graphSeed, j >= 3 ? pages[j - 1] : undefined);
    need.add(j);
    need.add(p.p0);
    need.add(p.p1);
    need.add(p.p2);
  }

  const nodes = {};
  for (const idx of need) {
    if (omit.includes(idx)) continue;
    nodes[String(idx)] = {
      pageB64: b64u(pages[idx]),
      proof: buildProof(tree, idx).map((x) => b64u(x)),
    };
  }

  return {
    root: tree.root,
    leafCount: tree.leafCount,
    graphSeed,
    nonce,
    pageBytes,
    parentByIndex,
    opens: [{ i: steps, seg, nodes }],
  };
};

test("segmentLen=2 verifies equation closure", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const out = await verifyBatch({ fixture: "valid-seg2" });
  assert.equal(out.ok, true);
});

test("segmentLen hard-clamps into [2,16]", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const low = await verifyBatch({ fixture: "valid-seg2", segmentLen: 1 });
  assert.equal(low.ok, true);

  const high = await verifyBatch({ fixture: "valid-seg2", segmentLen: 17 });
  assert.equal(high.ok, true);
});

test("segmentLen normalizes by floor+clamp", async () => {
  const { verifyBatch } = await import("../../lib/mhg/verify.js");
  const out = await verifyBatch({ fixture: "valid-seg2", segmentLen: 0.6 });
  assert.equal(out.ok, true);
});

test("open entry must include closure nodes for segment", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const vector = await makeDynamicOpenVector({ steps: 24, seg: 3 });
  const missing = vector.parentByIndex[24].p0;
  delete vector.opens[0].nodes[String(missing)];
  const out = await verifyOpenBatchVector(vector);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing_witness");
  assert.equal(out.index, missing);
});

test("dynamic parent equations verify from witnessed pages", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const out = await verifyOpenBatchVector(await makeDynamicOpenVector({ steps: 40, seg: 4 }));
  assert.equal(out.ok, true);
});

test("open.seg must be an integer in [2,16]", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const segOne = await verifyOpenBatchVector(await makeOpenVector());
  assert.equal(segOne.ok, false);
  assert.equal(segOne.reason, "bad_open");

  const segHigh = await verifyOpenBatchVector(await makeDynamicOpenVector({ steps: 20, seg: 17 }));
  assert.equal(segHigh.ok, false);
  assert.equal(segHigh.reason, "bad_open");

  const floatVector = await makeDynamicOpenVector({ steps: 20, seg: 3 });
  floatVector.opens[0].seg = 3.2;
  const segFloat = await verifyOpenBatchVector(floatVector);
  assert.equal(segFloat.ok, false);
  assert.equal(segFloat.reason, "bad_open");
});

test("missing p0 witness returns missing_witness", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const vector = await makeDynamicOpenVector({ steps: 26, seg: 2 });
  const missing = vector.parentByIndex[26].p0;
  delete vector.opens[0].nodes[String(missing)];
  const out = await verifyOpenBatchVector(vector);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing_witness");
  assert.equal(out.index, missing);
});

test("missing p1 witness returns missing_witness", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const vector = await makeDynamicOpenVector({ steps: 27, seg: 2 });
  const missing = vector.parentByIndex[27].p1;
  delete vector.opens[0].nodes[String(missing)];
  const out = await verifyOpenBatchVector(vector);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing_witness");
  assert.equal(out.index, missing);
});

test("missing p2 witness returns missing_witness", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const vector = await makeDynamicOpenVector({ steps: 28, seg: 2 });
  const missing = vector.parentByIndex[28].p2;
  delete vector.opens[0].nodes[String(missing)];
  const out = await verifyOpenBatchVector(vector);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "missing_witness");
  assert.equal(out.index, missing);
});

test("rejects extra node keys beyond required closure set", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const vector = await makeDynamicOpenVector({ steps: 30, seg: 3 });
  vector.opens[0].nodes.extra = vector.opens[0].nodes["30"];
  const out = await verifyOpenBatchVector(vector);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "bad_open");
});

test("rejects wrong node page length before proof verification", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");
  const vector = await makeDynamicOpenVector({ steps: 20, seg: 3 });
  const k = Object.keys(vector.opens[0].nodes)[0];
  const page = Buffer.from(vector.opens[0].nodes[k].pageB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  vector.opens[0].nodes[k].pageB64 = b64u(page.subarray(0, page.length - 1));
  const out = await verifyOpenBatchVector(vector);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "bad_open");
});

test("present-but-malformed required nodes return bad_open", async () => {
  const { verifyOpenBatchVector } = await import("../../lib/mhg/verify.js");

  const nullNode = await makeDynamicOpenVector({ steps: 22, seg: 2 });
  const nullKey = String(nullNode.parentByIndex[22].p0);
  nullNode.opens[0].nodes[nullKey] = null;
  const nullOut = await verifyOpenBatchVector(nullNode);
  assert.equal(nullOut.ok, false);
  assert.equal(nullOut.reason, "bad_open");

  const nonObjectNode = await makeDynamicOpenVector({ steps: 22, seg: 2 });
  const nonObjectKey = String(nonObjectNode.parentByIndex[22].p1);
  nonObjectNode.opens[0].nodes[nonObjectKey] = "x";
  const nonObjectOut = await verifyOpenBatchVector(nonObjectNode);
  assert.equal(nonObjectOut.ok, false);
  assert.equal(nonObjectOut.reason, "bad_open");

  const missingPage = await makeDynamicOpenVector({ steps: 22, seg: 2 });
  const missingPageKey = String(missingPage.parentByIndex[22].p2);
  delete missingPage.opens[0].nodes[missingPageKey].pageB64;
  const missingPageOut = await verifyOpenBatchVector(missingPage);
  assert.equal(missingPageOut.ok, false);
  assert.equal(missingPageOut.reason, "bad_open");

  const badProof = await makeDynamicOpenVector({ steps: 22, seg: 2 });
  const badProofKey = String(badProof.parentByIndex[22].p0);
  badProof.opens[0].nodes[badProofKey].proof = "not-an-array";
  const badProofOut = await verifyOpenBatchVector(badProof);
  assert.equal(badProofOut.ok, false);
  assert.equal(badProofOut.reason, "bad_open");
});
