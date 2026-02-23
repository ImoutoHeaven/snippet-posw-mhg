const MASK_64 = 0xffffffffffffffffn;

const IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const rotr64 = (value, bits) => {
  const b = BigInt(bits);
  return ((value >> b) | (value << (64n - b))) & MASK_64;
};

const add64 = (a, b) => (a + b) & MASK_64;

const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return new TextEncoder().encode(value);
  return null;
};

const readU64LE = (bytes, offset) => {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[offset + i]);
  }
  return value;
};

const writeU64LE = (value, out, offset) => {
  let v = value;
  for (let i = 0; i < 8; i += 1) {
    out[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
};

const compress = (h, block, t0, t1, isLast) => {
  const m = new Array(16);
  for (let i = 0; i < 16; i += 1) {
    m[i] = readU64LE(block, i * 8);
  }

  const v = new Array(16);
  for (let i = 0; i < 8; i += 1) v[i] = h[i];
  for (let i = 0; i < 8; i += 1) v[i + 8] = IV[i];
  v[12] ^= t0;
  v[13] ^= t1;
  if (isLast) v[14] ^= MASK_64;

  const G = (a, b, c, d, x, y) => {
    v[a] = add64(add64(v[a], v[b]), x);
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = add64(add64(v[a], v[b]), y);
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 63);
  };

  for (let r = 0; r < 12; r += 1) {
    const s = SIGMA[r];
    G(0, 4, 8, 12, m[s[0]], m[s[1]]);
    G(1, 5, 9, 13, m[s[2]], m[s[3]]);
    G(2, 6, 10, 14, m[s[4]], m[s[5]]);
    G(3, 7, 11, 15, m[s[6]], m[s[7]]);
    G(0, 5, 10, 15, m[s[8]], m[s[9]]);
    G(1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(2, 7, 8, 13, m[s[12]], m[s[13]]);
    G(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  for (let i = 0; i < 8; i += 1) {
    h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK_64;
  }
};

export const blake2b = (input, outLen = 64, options = {}) => {
  const msgBytes = toBytes(input);
  const keyBytes = options?.key === undefined || options?.key === null ? new Uint8Array() : toBytes(options.key);
  const saltBytes = options?.salt === undefined || options?.salt === null ? new Uint8Array() : toBytes(options.salt);
  const personalBytes =
    options?.personalization === undefined || options?.personalization === null
      ? new Uint8Array()
      : toBytes(options.personalization);

  if (!(msgBytes instanceof Uint8Array)) {
    throw new TypeError("input must be bytes-like or string");
  }
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length > 64) {
    throw new TypeError("key must be bytes-like with length <= 64");
  }
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length > 16) {
    throw new TypeError("salt must be bytes-like with length <= 16");
  }
  if (!(personalBytes instanceof Uint8Array) || personalBytes.length > 16) {
    throw new TypeError("personalization must be bytes-like with length <= 16");
  }
  if (!Number.isInteger(outLen) || outLen < 1 || outLen > 64) {
    throw new TypeError("outLen must be an integer in [1, 64]");
  }

  const param = new Uint8Array(64);
  param[0] = outLen;
  param[1] = keyBytes.length;
  param[2] = 1;
  param[3] = 1;
  param.set(saltBytes, 32);
  param.set(personalBytes, 48);

  const h = new Array(8);
  for (let i = 0; i < 8; i += 1) {
    h[i] = IV[i] ^ readU64LE(param, i * 8);
  }

  let message = msgBytes;
  if (keyBytes.length > 0) {
    message = new Uint8Array(128 + msgBytes.length);
    message.set(keyBytes, 0);
    message.set(msgBytes, 128);
  }

  let offset = 0;
  let t0 = 0n;
  let t1 = 0n;

  if (message.length === 0) {
    compress(h, new Uint8Array(128), t0, t1, true);
  } else {
    while (offset < message.length) {
      const blockLen = Math.min(128, message.length - offset);
      const block = new Uint8Array(128);
      block.set(message.subarray(offset, offset + blockLen));

      t0 += BigInt(blockLen);
      if (t0 > MASK_64) {
        t0 &= MASK_64;
        t1 = (t1 + 1n) & MASK_64;
      }

      const isLast = offset + blockLen >= message.length;
      compress(h, block, t0, t1, isLast);
      offset += blockLen;
    }
  }

  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i += 1) {
    writeU64LE(h[i], out, i * 8);
  }
  return out.subarray(0, outLen);
};
