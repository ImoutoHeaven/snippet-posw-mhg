import { blake2b } from "./blake2b.js";
import { isValidEquihashParams } from "./params.js";

const encoder = new TextEncoder();

const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
};

const strictInt = (value) => {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number.parseInt(value, 10);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
};

const u32be = (bytes, offset) =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

const toBigBits = (bytes, bitLength) => {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  const extra = BigInt(bytes.length * 8 - bitLength);
  return extra > 0n ? value >> extra : value;
};

const makePersonalization = (n, k) => {
  const out = new Uint8Array(16);
  out.set(encoder.encode("ZcashPoW"), 0);
  const view = new DataView(out.buffer);
  view.setUint32(8, n >>> 0, true);
  view.setUint32(12, k >>> 0, true);
  return out;
};

const parseIndices = (proof, count) => {
  if (proof instanceof Uint8Array) {
    if (proof.length !== count * 4) return null;
    const out = new Array(count);
    for (let i = 0; i < count; i += 1) {
      out[i] = u32be(proof, i * 4);
    }
    return out;
  }

  if (!Array.isArray(proof) || proof.length !== count) return null;
  const out = new Array(count);
  for (let i = 0; i < proof.length; i += 1) {
    const item = strictInt(proof[i]);
    if (item === null || item < 0 || item > 0xffffffff) return null;
    out[i] = item >>> 0;
  }
  return out;
};

const validateIndexOrder = (indices) => {
  for (let i = 1; i < indices.length; i += 1) {
    if (indices[i - 1] >= indices[i]) return false;
  }
  return true;
};

const hashIndexBits = (seed, nonce, index, n, personalization) => {
  const input = new Uint8Array(seed.length + nonce.length + 4);
  input.set(seed, 0);
  input.set(nonce, seed.length);
  const off = seed.length + nonce.length;
  input[off] = (index >>> 24) & 0xff;
  input[off + 1] = (index >>> 16) & 0xff;
  input[off + 2] = (index >>> 8) & 0xff;
  input[off + 3] = index & 0xff;

  const outBytes = Math.ceil(n / 8);
  const digest = blake2b(input, outBytes, { personalization });
  return toBigBits(digest, n);
};

export const verifyEquihash = (input) => {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return false;

    const n = strictInt(input.n);
    const k = strictInt(input.k);
    if (!isValidEquihashParams(n, k)) return false;

    const denom = k + 1;
    const collisionBits = n / denom;
    if (collisionBits < 4 || collisionBits > 32) return false;

    const expectedCount = 1 << k;

    const seed = toBytes(input.seed);
    const nonce = toBytes(input.nonce);
    const proofBytes = toBytes(input.proof);

    if (!(seed instanceof Uint8Array) || seed.length === 0 || seed.length > 256) return false;
    if (!(nonce instanceof Uint8Array) || nonce.length === 0 || nonce.length > 256) return false;

    const indices = parseIndices(proofBytes ?? input.proof, expectedCount);
    if (!indices) return false;
    if (!validateIndexOrder(indices)) return false;

    const personalization = makePersonalization(n, k);
    let layer = indices.map((index) => ({ bits: hashIndexBits(seed, nonce, index, n, personalization), first: index }));
    let bitLength = n;

    for (let round = 0; round < k; round += 1) {
      if (layer.length % 2 !== 0) return false;

      const next = [];
      const shift = BigInt(bitLength - collisionBits);
      const remBits = bitLength - collisionBits;
      const mask = remBits === 0 ? 0n : (1n << BigInt(remBits)) - 1n;

      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = layer[i + 1];
        if (!left || !right) return false;

        const leftPrefix = left.bits >> shift;
        const rightPrefix = right.bits >> shift;
        if (leftPrefix !== rightPrefix) return false;

        if (left.first >= right.first) return false;

        next.push({ bits: (left.bits ^ right.bits) & mask, first: left.first });
      }

      layer = next;
      bitLength = remBits;
    }

    return layer.length === 1 && layer[0].bits === 0n;
  } catch {
    return false;
  }
};
