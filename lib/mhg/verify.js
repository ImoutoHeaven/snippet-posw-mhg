import { parentsOf } from "./graph.js";
import { makeGenesisPage, mixPage } from "./mix-aes.js";
import { buildMerkle, buildProof, verifyProof } from "./merkle.js";

const clampSegmentLen = (value) => Math.max(1, Math.min(16, Math.floor(value)));

const equalBytes = (a, b) => {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
};

const decodeB64Url = (value) => {
  if (typeof value !== "string" || !value) return null;
  let b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
};

const normalizeProof = (value) => {
  if (!Array.isArray(value)) return null;
  const out = [];
  for (const entry of value) {
    const bytes = entry instanceof Uint8Array ? entry : decodeB64Url(String(entry || ""));
    if (!(bytes instanceof Uint8Array)) return null;
    out.push(bytes);
  }
  return out;
};

export const buildEqSet = ({ index, segmentLen }) => {
  const out = [];
  const start = Math.max(1, index - segmentLen + 1);
  for (let i = start; i <= index; i += 1) {
    out.push(i);
  }
  return out;
};

export const buildNeedSet = ({ eqSet, equations }) => {
  const needed = new Set();
  for (const i of eqSet) {
    const edge = equations[i];
    if (!edge) {
      throw new RangeError(`missing equation for index ${i}`);
    }
    needed.add(i);
    needed.add(edge.p0);
    needed.add(edge.p1);
    needed.add(edge.p2);
  }
  return needed;
};

const buildWitness = async ({ pages }) => {
  const tree = await buildMerkle(pages);
  const witness = {};
  for (let i = 0; i < pages.length; i += 1) {
    witness[i] = {
      page: pages[i],
      proof: buildProof(tree, i),
    };
  }
  return { root: tree.root, witness, leafCount: tree.leafCount };
};

const makeFixtureSet = async () => {
  const graphSeed = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const nonce = Uint8Array.from({ length: 16 }, (_, i) => 16 - i);
  const pageBytes = 64;

  const p0 = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  const p1 = await mixPage({ i: 1, p0, p1: p0, p2: p0, graphSeed, nonce, pageBytes });
  const p2 = await mixPage({ i: 2, p0: p1, p1: p0, p2: p0, graphSeed, nonce, pageBytes });

  const equations = {
    1: { p0: 0, p1: 0, p2: 0 },
    2: { p0: 1, p1: 0, p2: 0 },
  };

  const validPages = [p0, p1, p2];
  const valid = await buildWitness({ pages: validPages });

  const tamperedP2 = p2.slice();
  tamperedP2[0] ^= 1;
  const tampered = await buildWitness({ pages: [p0, p1, tamperedP2] });

  return {
    "valid-seg2": {
      graphSeed,
      nonce,
      pageBytes,
      root: valid.root,
      leafCount: valid.leafCount,
      witness: valid.witness,
      equations,
      index: 2,
      segmentLen: 2,
    },
    "valid-seg1-predecessor": {
      graphSeed,
      nonce,
      pageBytes,
      root: valid.root,
      leafCount: valid.leafCount,
      witness: valid.witness,
      equations,
      index: 2,
      segmentLen: 1,
    },
    "tampered-seg1-current-only": {
      graphSeed,
      nonce,
      pageBytes,
      root: tampered.root,
      leafCount: tampered.leafCount,
      witness: tampered.witness,
      equations,
      index: 2,
      segmentLen: 1,
    },
  };
};

let fixtureCache;
const loadFixture = async (name) => {
  if (!fixtureCache) {
    fixtureCache = await makeFixtureSet();
  }
  return fixtureCache[name];
};

export const verifyBatch = async ({ fixture, segmentLen } = {}) => {
  const input = await loadFixture(fixture);
  if (!input) {
    return { ok: false, reason: "unknown_fixture" };
  }

  const normalizedSegmentLen = clampSegmentLen(segmentLen ?? input.segmentLen ?? 2);
  const eqSet = buildEqSet({ index: input.index, segmentLen: normalizedSegmentLen });
  const needSet = buildNeedSet({ eqSet, equations: input.equations });

  for (const idx of needSet) {
    const node = input.witness[idx];
    if (!node) {
      return { ok: false, reason: "missing_witness", index: idx };
    }
    const proofOk = await verifyProof({
      root: input.root,
      index: idx,
      page: node.page,
      proof: node.proof,
      leafCount: input.leafCount,
    });
    if (!proofOk) {
      return { ok: false, reason: "proof_failed", index: idx };
    }
  }

  for (const i of eqSet) {
    const edge = input.equations[i];
    const current = input.witness[i].page;
    const mixed = await mixPage({
      i,
      p0: input.witness[edge.p0].page,
      p1: input.witness[edge.p1].page,
      p2: input.witness[edge.p2].page,
      graphSeed: input.graphSeed,
      nonce: input.nonce,
      pageBytes: input.pageBytes,
    });
    if (!equalBytes(mixed, current)) {
      return { ok: false, reason: "equation_failed", index: i };
    }
  }

  return { ok: true };
};

export const verifyOpenBatchVector = async ({
  root,
  rootB64,
  leafCount,
  graphSeed,
  nonce,
  pageBytes = 64,
  opens,
}) => {
  const rootBytes = root instanceof Uint8Array ? root : decodeB64Url(String(rootB64 || ""));
  if (!(rootBytes instanceof Uint8Array) || !Number.isInteger(leafCount) || leafCount <= 1) {
    return { ok: false, reason: "bad_vector" };
  }
  if (!(graphSeed instanceof Uint8Array) || graphSeed.length !== 16) {
    return { ok: false, reason: "bad_vector" };
  }
  if (!(nonce instanceof Uint8Array) || nonce.length !== 16) {
    return { ok: false, reason: "bad_vector" };
  }
  if (!Array.isArray(opens) || opens.length === 0) {
    return { ok: false, reason: "bad_vector" };
  }

  for (const open of opens) {
    const idx = Number.parseInt(open && open.i, 10);
    if (!Number.isInteger(idx) || idx < 1 || idx >= leafCount) {
      return { ok: false, reason: "bad_open" };
    }
    const page = decodeB64Url(String(open.page || ""));
    const p0 = decodeB64Url(String(open.p0 || ""));
    const p1 = decodeB64Url(String(open.p1 || ""));
    const p2 = decodeB64Url(String(open.p2 || ""));
    const proofPage = normalizeProof(open?.proof?.page);
    const proofP0 = normalizeProof(open?.proof?.p0);
    const proofP1 = normalizeProof(open?.proof?.p1);
    const proofP2 = normalizeProof(open?.proof?.p2);
    if (!page || !p0 || !p1 || !p2 || !proofPage || !proofP0 || !proofP1 || !proofP2) {
      return { ok: false, reason: "bad_open" };
    }
    const parents = await parentsOf(idx, graphSeed);
    const pageOk = await verifyProof({ root: rootBytes, index: idx, page, proof: proofPage, leafCount });
    const p0Ok = await verifyProof({
      root: rootBytes,
      index: parents.p0,
      page: p0,
      proof: proofP0,
      leafCount,
    });
    const p1Ok = await verifyProof({
      root: rootBytes,
      index: parents.p1,
      page: p1,
      proof: proofP1,
      leafCount,
    });
    const p2Ok = await verifyProof({
      root: rootBytes,
      index: parents.p2,
      page: p2,
      proof: proofP2,
      leafCount,
    });
    if (!pageOk || !p0Ok || !p1Ok || !p2Ok) {
      return { ok: false, reason: "proof_failed", index: idx };
    }
    const expected = await mixPage({
      i: idx,
      p0,
      p1,
      p2,
      graphSeed,
      nonce,
      pageBytes,
    });
    if (!equalBytes(expected, page)) {
      return { ok: false, reason: "equation_failed", index: idx };
    }
  }

  return { ok: true };
};
