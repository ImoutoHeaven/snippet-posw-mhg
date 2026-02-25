import { sha256, u32be } from "./hash.js";

const U32_MAX_PLUS_ONE = 0x1_0000_0000;
const REJECTION_MAX_CTR = 4096;

const asU32 = (bytes) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, false);
};

const assertPageBytes = (pageBytes) => {
  if (!Number.isInteger(pageBytes) || pageBytes < 16 || pageBytes % 16 !== 0) {
    throw new RangeError("pageBytes must be an integer >= 16 and multiple of 16");
  }
};

const assertMod = (mod) => {
  if (!Number.isInteger(mod) || mod <= 0 || mod > U32_MAX_PLUS_ONE) {
    throw new RangeError("mod must be a positive integer <= 4294967296");
  }
};

const requirePage = (name, page, pageBytes) => {
  if (!(page instanceof Uint8Array) || page.length !== pageBytes) {
    throw new TypeError(`${name} must be Uint8Array exactly matching pageBytes`);
  }
};

const assertParentInvariants = ({ i, p0, p1 }) => {
  if (!Number.isInteger(i) || i < 3) {
    throw new RangeError("index i must be an integer >= 3");
  }
  if (!Number.isInteger(p0) || !Number.isInteger(p1) || p0 < 0 || p1 < 0 || p0 >= i || p1 >= i || p0 === p1) {
    throw new Error("parent invariants violated");
  }
};

export const draw32 = async ({ seed, label, i, ctr }) => {
  const digest = await sha256("MHG1-PRF", seed, label, u32be(i), u32be(ctr));
  return asU32(digest.subarray(0, 4));
};

export const uniformMod = async ({ seed, label, i, mod, ctr = 0 }) => {
  assertMod(mod);
  const limit = Math.floor(U32_MAX_PLUS_ONE / mod) * mod;
  const startCtr = Number.isInteger(ctr) && ctr >= 0 ? ctr : 0;
  const stopCtr = startCtr + REJECTION_MAX_CTR;

  for (let cursor = startCtr; cursor < stopCtr; cursor += 1) {
    const n = await draw32({ seed, label, i, ctr: cursor });
    if (n < limit) {
      return { value: n % mod, ctr: cursor + 1 };
    }
  }

  throw new Error("parent invariants violated");
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

const uniformModExclude = async ({ seed, label, i, mod, exclude, maxCtr }) => {
  assertMod(mod);
  if (!Number.isInteger(maxCtr) || maxCtr <= 0) {
    throw new RangeError("maxCtr must be a positive integer");
  }

  const limit = Math.floor(U32_MAX_PLUS_ONE / mod) * mod;
  let ctr = 0;
  while (ctr < maxCtr) {
    const n = await draw32({ seed, label, i, ctr });
    ctr += 1;
    if (n >= limit) {
      continue;
    }
    const pick = n % mod;
    if (exclude.has(pick)) {
      continue;
    }
    return pick;
  }

  throw new Error("parent invariants violated");
};

export const deriveDynamicParent2 = async ({ i, seed, pageBytes, p0, p1, p0Page, p1Page }) => {
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }
  assertPageBytes(pageBytes);
  requirePage("p0Page", p0Page, pageBytes);
  requirePage("p1Page", p1Page, pageBytes);
  assertParentInvariants({ i, p0, p1 });

  const seedP2 = await sha256("MHG1-P2|v4", seed, u32be(i), u32be(pageBytes), p0Page, p1Page);
  return uniformModExclude({
    seed: seedP2,
    label: "p2",
    i,
    mod: i,
    exclude: new Set([p0, p1]),
    maxCtr: 1 << 20,
  });
};
