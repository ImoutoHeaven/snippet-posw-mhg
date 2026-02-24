import { deriveDynamicParent2, staticParentsOf } from "./graph.js";
import { makeGenesisPage, mixPage } from "./mix-aes.js";
import { buildMerkle, buildProof, verifyProof } from "./merkle.js";

const clampSegmentLen = (value) => Math.max(2, Math.min(16, Math.floor(value)));

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

const normalizeOpenNodes = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
};

const parseIntegerLike = (value) => {
  if (typeof value === "number") {
    return Number.isInteger(value) ? value : null;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    const n = Number(value);
    return Number.isSafeInteger(n) ? n : null;
  }
  return null;
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
  mixRounds = 2,
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
    const seg = parseIntegerLike(open && open.seg);
    if (!Number.isInteger(seg) || seg < 2 || seg > 16) {
      return { ok: false, reason: "bad_open" };
    }
    const nodes = normalizeOpenNodes(open && open.nodes);
    if (!nodes) {
      return { ok: false, reason: "bad_open" };
    }

    const eqSet = buildEqSet({ index: idx, segmentLen: seg });
    const equations = {};
    const required = new Set();
    const decodedNodes = new Map();

    const loadRequiredNode = (needIdx) => {
      if (decodedNodes.has(needIdx)) {
        return { ok: true, node: decodedNodes.get(needIdx) };
      }
      const nodeKey = String(needIdx);
      if (!Object.prototype.hasOwnProperty.call(nodes, nodeKey)) {
        return { ok: false, reason: "missing_witness", index: needIdx };
      }
      const rawNode = nodes[nodeKey];
      if (!rawNode || typeof rawNode !== "object") {
        return { ok: false, reason: "bad_open" };
      }
      const page = decodeB64Url(String(rawNode.pageB64 || ""));
      const proof = normalizeProof(rawNode.proof);
      if (!(page instanceof Uint8Array) || !proof) {
        return { ok: false, reason: "bad_open" };
      }
      if (page.length !== pageBytes) {
        return { ok: false, reason: "bad_open" };
      }
      for (const step of proof) {
        if (!(step instanceof Uint8Array) || step.length !== rootBytes.length) {
          return { ok: false, reason: "bad_open" };
        }
      }
      const decoded = { page, proof };
      decodedNodes.set(needIdx, decoded);
      return { ok: true, node: decoded };
    };

    for (const j of eqSet) {
      let edge;
      if (j === 1) {
        edge = { p0: 0, p1: 0, p2: 0 };
      } else if (j === 2) {
        edge = { p0: 1, p1: 0, p2: 0 };
      } else {
        const { p0, p1 } = await staticParentsOf(j, graphSeed);
        const p0Node = loadRequiredNode(p0);
        if (!p0Node.ok) {
          if (p0Node.reason === "missing_witness") {
            return { ok: false, reason: "missing_witness", index: p0Node.index };
          }
          return { ok: false, reason: "bad_open" };
        }
        const p2 = deriveDynamicParent2({ i: j, prevPage: p0Node.node.page, p0, p1 });
        edge = { p0, p1, p2 };
      }
      equations[j] = edge;
      required.add(j);
      required.add(edge.p0);
      required.add(edge.p1);
      required.add(edge.p2);
    }

    const nodeKeys = Object.keys(nodes);
    if (nodeKeys.length > required.size) {
      return { ok: false, reason: "bad_open" };
    }
    for (const key of nodeKeys) {
      if (!/^(0|[1-9]\d*)$/.test(key)) {
        return { ok: false, reason: "bad_open" };
      }
      const keyIdx = Number(key);
      if (!required.has(keyIdx)) {
        return { ok: false, reason: "bad_open" };
      }
    }

    for (const needIdx of required) {
      const node = loadRequiredNode(needIdx);
      if (!node.ok) {
        if (node.reason === "missing_witness") {
          return { ok: false, reason: "missing_witness", index: needIdx };
        }
        return { ok: false, reason: "bad_open" };
      }
    }

    for (const needIdx of required) {
      const node = decodedNodes.get(needIdx);
      const proofOk = await verifyProof({
        root: rootBytes,
        index: needIdx,
        page: node.page,
        proof: node.proof,
        leafCount,
      });
      if (!proofOk) {
        return { ok: false, reason: "proof_failed", index: needIdx };
      }
    }

    for (const j of eqSet) {
      const edge = equations[j];
      const current = decodedNodes.get(j).page;
      const expected = await mixPage({
        i: j,
        p0: decodedNodes.get(edge.p0).page,
        p1: decodedNodes.get(edge.p1).page,
        p2: decodedNodes.get(edge.p2).page,
        graphSeed,
        nonce,
        pageBytes,
        mixRounds,
      });
      if (!equalBytes(expected, current)) {
        return { ok: false, reason: "equation_failed", index: j };
      }
    }
  }

  return { ok: true };
};
