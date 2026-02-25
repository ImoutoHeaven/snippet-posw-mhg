import { sha256, u32be } from "./hash.js";

const U32_MAX_PLUS_ONE = 0x1_0000_0000;

const asU32 = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false);
};

const assertPageBytes = (pageBytes) => {
  if (!Number.isInteger(pageBytes) || pageBytes < 16 || pageBytes % 16 !== 0) {
    throw new RangeError("pageBytes must be an integer >= 16 and multiple of 16");
  }
};

const requirePrevPage = (prevPage, pageBytes) => {
  if (!(prevPage instanceof Uint8Array) || prevPage.length !== pageBytes) {
    throw new TypeError("prevPage must be Uint8Array exactly matching pageBytes for full-page p2 derivation");
  }
};

export const draw32 = async ({ seed, label, i, ctr }) => {
  const digest = await sha256("MHG1-PRF", seed, label, u32be(i), u32be(ctr));
  return asU32(digest.subarray(0, 4));
};

export const uniformMod = async ({ seed, label, i, mod, ctr = 0 }) => {
  if (!Number.isInteger(mod) || mod <= 0) {
    throw new RangeError("mod must be a positive integer");
  }
  const limit = Math.floor(U32_MAX_PLUS_ONE / mod) * mod;
  while (true) {
    const n = await draw32({ seed, label, i, ctr });
    ctr += 1;
    if (n < limit) {
      return { value: n % mod, ctr };
    }
  }
};

export const pickDistinct = async ({ seed, label, i, count, maxExclusive, exclude = new Set() }) => {
  const out = [];
  const seen = new Set(exclude);
  let ctr = 0;
  while (out.length < count && seen.size < maxExclusive) {
    const next = await uniformMod({ seed, label, i, mod: maxExclusive, ctr });
    ctr = next.ctr;
    const n = next.value;
    if (seen.has(n)) {
      continue;
    }
    seen.add(n);
    out.push(n);
  }
  while (out.length < count) {
    const next = await uniformMod({ seed, label, i, mod: maxExclusive, ctr });
    ctr = next.ctr;
    out.push(next.value);
  }
  return out;
};

export const staticParentsOf = async (i, seed) => {
  if (!Number.isInteger(i) || i < 3) {
    throw new RangeError("index i must be an integer >= 3");
  }
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }

  const p0 = i - 1;
  const [p1] = await pickDistinct({
    seed,
    label: "p1",
    i,
    count: 1,
    maxExclusive: i,
    exclude: new Set([p0]),
  });
  return { p0, p1 };
};

export const deriveDynamicParent2 = async ({ i, seed, prevPage, pageBytes, p0, p1 }) => {
  if (!Number.isInteger(i) || i < 3) {
    throw new RangeError("index i must be an integer >= 3");
  }
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }
  assertPageBytes(pageBytes);
  requirePrevPage(prevPage, pageBytes);

  if (!Number.isInteger(p0) || !Number.isInteger(p1) || p0 < 0 || p1 < 0 || p0 >= i || p1 >= i || p0 === p1) {
    throw new Error("parent invariants violated");
  }

  const digest = await sha256("MHG1-P2", seed, u32be(i), u32be(pageBytes), prevPage);
  let candidate = asU32(digest.subarray(0, 4)) % i;

  for (let checks = 0; checks < 3; checks += 1) {
    if (candidate !== p0 && candidate !== p1) {
      return candidate;
    }
    candidate = (candidate + 1) % i;
  }

  throw new Error("parent invariants violated");
};

export const parentsOf = async (i, seed, prevPage, pageBytes) => {
  if (!Number.isInteger(i) || i <= 0) {
    throw new RangeError("index i must be a positive integer");
  }
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }

  if (i === 1) {
    return { p0: 0, p1: 0, p2: 0 };
  }
  if (i === 2) {
    return { p0: 1, p1: 0, p2: 0 };
  }

  const normalizedPageBytes = pageBytesFromInputs(prevPage, pageBytes);
  requirePrevPage(prevPage, normalizedPageBytes);
  const { p0, p1 } = await staticParentsOf(i, seed);
  const p2 = await deriveDynamicParent2({
    i,
    seed,
    prevPage,
    pageBytes: normalizedPageBytes,
    p0,
    p1,
  });
  return { p0, p1, p2 };
};

const pageBytesFromInputs = (prevPage, pageBytes) => {
  const normalized = pageBytes ?? (prevPage instanceof Uint8Array ? prevPage.length : undefined);
  assertPageBytes(normalized);
  return normalized;
};
