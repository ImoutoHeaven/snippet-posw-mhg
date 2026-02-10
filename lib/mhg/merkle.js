import { MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX } from "./constants.js";

const subtle = globalThis.crypto?.subtle;
const encoder = new TextEncoder();

if (!subtle) {
  throw new Error("WebCrypto subtle API is required");
}

const concatBytes = (...chunks) => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

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

const assertBytes = (name, value) => {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be Uint8Array`);
  }
};

const digest = async (...chunks) => {
  const data = concatBytes(...chunks);
  return new Uint8Array(await subtle.digest("SHA-256", data));
};

const u32be = (value) => {
  const out = new Uint8Array(4);
  const v = value >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

export const leafHash = async (index, page) => {
  if (!Number.isInteger(index) || index < 0) {
    throw new RangeError("index must be a non-negative integer");
  }
  assertBytes("page", page);
  return digest(encoder.encode(MERKLE_LEAF_PREFIX), u32be(index), page);
};

export const nodeHash = async (left, right) => {
  assertBytes("left", left);
  assertBytes("right", right);
  return digest(encoder.encode(MERKLE_NODE_PREFIX), left, right);
};

export const buildMerkle = async (pages) => {
  if (!Array.isArray(pages) || pages.length === 0) {
    throw new RangeError("pages must be a non-empty array");
  }

  const leaves = await Promise.all(pages.map((page, index) => leafHash(index, page)));
  const levels = [leaves];

  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      const left = prev[i];
      const right = prev[i + 1] ?? left;
      next.push(await nodeHash(left, right));
    }
    levels.push(next);
  }

  return {
    root: levels[levels.length - 1][0],
    levels,
    leafCount: leaves.length,
  };
};

export const buildProof = (tree, index) => {
  if (!tree || !Array.isArray(tree.levels)) {
    throw new TypeError("tree.levels must be an array");
  }
  if (!Number.isInteger(index) || index < 0 || index >= tree.leafCount) {
    throw new RangeError("index out of range");
  }

  const proof = [];
  let cursor = index;
  for (let level = 0; level < tree.levels.length - 1; level += 1) {
    const nodes = tree.levels[level];
    const siblingIndex = cursor ^ 1;
    proof.push(nodes[siblingIndex] ?? nodes[cursor]);
    cursor = Math.floor(cursor / 2);
  }

  return proof;
};

export const verifyProof = async ({ root, index, page, proof, leafCount }) => {
  assertBytes("root", root);
  assertBytes("page", page);
  if (!Array.isArray(proof)) {
    return false;
  }
  if (!Number.isInteger(index) || index < 0) {
    return false;
  }
  if (!Number.isInteger(leafCount) || leafCount <= 0 || index >= leafCount) {
    return false;
  }

  let expectedDepth = 0;
  for (let width = leafCount; width > 1; width = Math.ceil(width / 2)) {
    expectedDepth += 1;
  }
  if (proof.length !== expectedDepth) {
    return false;
  }

  let hash = await leafHash(index, page);
  let cursor = index;

  for (const sibling of proof) {
    if (!(sibling instanceof Uint8Array)) {
      return false;
    }
    const left = cursor % 2 === 0 ? hash : sibling;
    const right = cursor % 2 === 0 ? sibling : hash;
    hash = await nodeHash(left, right);
    cursor = Math.floor(cursor / 2);
  }

  return equalBytes(hash, root);
};
