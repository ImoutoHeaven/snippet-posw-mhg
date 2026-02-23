import { blake2b } from "../lib/equihash/blake2b.js";

const encoder = new TextEncoder();

const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return encoder.encode(value);
  return null;
};

const b64u = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const randomNonce = (size = 24) => {
  const out = new Uint8Array(size);
  crypto.getRandomValues(out);
  return out;
};

const makePersonalization = (n, k) => {
  const out = new Uint8Array(16);
  out.set(encoder.encode("ZcashPoW"), 0);
  const view = new DataView(out.buffer);
  view.setUint32(8, n >>> 0, true);
  view.setUint32(12, k >>> 0, true);
  return out;
};

const toBigBits = (bytes, bitLength) => {
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  const extra = BigInt(bytes.length * 8 - bitLength);
  return extra > 0n ? value >> extra : value;
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

let cancelled = false;
let cfg = { n: 90, k: 5, rows: 1 << 16, maxAttempts: 24 };

const emitProgress = (attempt, round = 0) => {
  postMessage({ type: "PROGRESS", phase: "solve", attempt, round });
};

const checkCancelled = () => {
  if (cancelled) throw new Error("solver cancelled");
};

const solveOne = ({ seed, nonce, n, k, rows }) => {
  const collisionBits = n / (k + 1);
  const personalization = makePersonalization(n, k);
  const initial = new Array(rows);

  for (let i = 0; i < rows; i += 1) {
    const bits = hashIndexBits(seed, nonce, i >>> 0, n, personalization);
    initial[i] = { bits, first: i >>> 0, last: i >>> 0, indices: [i >>> 0] };
  }

  let layer = initial;
  let bitLength = n;

  for (let round = 0; round < k; round += 1) {
    const shift = BigInt(bitLength - collisionBits);
    const remBits = bitLength - collisionBits;
    const mask = remBits === 0 ? 0n : (1n << BigInt(remBits)) - 1n;
    const buckets = new Map();

    for (let i = 0; i < layer.length; i += 1) {
      const entry = layer[i];
      const prefix = entry.bits >> shift;
      const key = prefix.toString();
      const list = buckets.get(key);
      if (list) list.push(entry);
      else buckets.set(key, [entry]);
    }

    const next = [];
    for (const bucket of buckets.values()) {
      if (bucket.length < 2) continue;
      bucket.sort((a, b) => a.first - b.first);
      for (let i = 0; i < bucket.length - 1; i += 1) {
        const left = bucket[i];
        for (let j = i + 1; j < bucket.length; j += 1) {
          const right = bucket[j];
          if (left.last >= right.first) continue;
          next.push({
            bits: (left.bits ^ right.bits) & mask,
            first: left.first,
            last: right.last,
            indices: left.indices.concat(right.indices),
          });
          break;
        }
      }
    }

    if (!next.length) return null;
    layer = next;
    bitLength = remBits;
  }

  for (let i = 0; i < layer.length; i += 1) {
    const entry = layer[i];
    if (entry.bits !== 0n) continue;
    if (entry.indices.length !== (1 << k)) continue;
    const out = new Uint8Array(entry.indices.length * 4);
    for (let j = 0; j < entry.indices.length; j += 1) {
      const idx = entry.indices[j] >>> 0;
      const off = j * 4;
      out[off] = (idx >>> 24) & 0xff;
      out[off + 1] = (idx >>> 16) & 0xff;
      out[off + 2] = (idx >>> 8) & 0xff;
      out[off + 3] = idx & 0xff;
    }
    return out;
  }
  return null;
};

const solveEquihash = async ({ seed, n, k }) => {
  const normalizedN = Number.isInteger(n) ? n : cfg.n;
  const normalizedK = Number.isInteger(k) ? k : cfg.k;
  if (normalizedN < 8 || normalizedN > 256 || normalizedK < 1 || normalizedK > 8) {
    throw new Error("invalid equihash params");
  }
  if (normalizedN % (normalizedK + 1) !== 0) {
    throw new Error("invalid equihash params");
  }

  const seedBytes = toBytes(seed);
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length === 0) {
    throw new Error("seed required");
  }

  for (let attempt = 1; attempt <= cfg.maxAttempts; attempt += 1) {
    checkCancelled();
    emitProgress(attempt, 0);
    const nonce = randomNonce(24);
    const proof = solveOne({ seed: seedBytes, nonce, n: normalizedN, k: normalizedK, rows: cfg.rows });
    if (proof) {
      return { nonceB64: b64u(nonce), proofB64: b64u(proof) };
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  throw new Error("no solution found");
};

self.onmessage = (event) => {
  const data = event && event.data ? event.data : {};
  const type = data.type;
  const rid = data.rid;

  const sendError = (err) => {
    postMessage({ type: "ERROR", rid, message: err && err.message ? err.message : String(err) });
  };

  (async () => {
    try {
      if (type === "CANCEL") {
        cancelled = true;
        postMessage({ type: "OK", rid });
        return;
      }
      if (type === "DISPOSE") {
        cancelled = true;
        postMessage({ type: "OK", rid });
        return;
      }
      if (type === "INIT") {
        cancelled = false;
        cfg = {
          n: Number.isInteger(data.n) ? data.n : 90,
          k: Number.isInteger(data.k) ? data.k : 5,
          rows: Math.max(1 << 14, Math.min(1 << 19, Math.floor(Number(data.rows) || (1 << 16)))),
          maxAttempts: Math.max(1, Math.min(64, Math.floor(Number(data.maxAttempts) || 24))),
        };
        postMessage({ type: "OK", rid });
        return;
      }
      if (type === "SOLVE") {
        const out = await solveEquihash({ seed: data.seed, n: data.n, k: data.k });
        postMessage({ type: "OK", rid, nonceB64: out.nonceB64, proofB64: out.proofB64 });
        return;
      }
      throw new Error("unknown command");
    } catch (err) {
      sendError(err);
    }
  })();
};
