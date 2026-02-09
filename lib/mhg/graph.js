const U32_MAX_PLUS_ONE = 0x1_0000_0000;

const initState = (seed, a = 0, b = 0) => {
  let x = 0x9e3779b9 ^ (a >>> 0) ^ (b >>> 0);
  for (let i = 0; i < seed.length; i += 1) {
    x ^= (seed[i] + 0x9e3779b9 + ((x << 6) >>> 0) + (x >>> 2)) >>> 0;
    x >>>= 0;
  }
  if (x === 0) {
    x = 0xa341316c;
  }
  return { x };
};

export const draw32 = (state) => {
  let x = state.x >>> 0;
  x ^= (x << 13) >>> 0;
  x ^= x >>> 17;
  x ^= (x << 5) >>> 0;
  state.x = x >>> 0;
  return state.x;
};

export const uniformMod = (state, mod) => {
  if (!Number.isInteger(mod) || mod <= 0) {
    throw new RangeError("mod must be a positive integer");
  }
  const limit = Math.floor(U32_MAX_PLUS_ONE / mod) * mod;
  while (true) {
    const n = draw32(state);
    if (n < limit) {
      return n % mod;
    }
  }
};

export const pickDistinct = ({ state, count, maxExclusive, exclude = new Set() }) => {
  const out = [];
  const seen = new Set(exclude);
  while (out.length < count && seen.size < maxExclusive) {
    const n = uniformMod(state, maxExclusive);
    if (seen.has(n)) {
      continue;
    }
    seen.add(n);
    out.push(n);
  }
  while (out.length < count) {
    out.push(uniformMod(state, maxExclusive));
  }
  return out;
};

export const parentsOf = async (i, seed) => {
  if (!Number.isInteger(i) || i <= 0) {
    throw new RangeError("index i must be a positive integer");
  }
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }

  const p0 = i - 1;
  const state = initState(seed, i, 0x70617265);
  const [p1, p2] = pickDistinct({
    state,
    count: 2,
    maxExclusive: i,
    exclude: new Set([p0]),
  });

  return { p0, p1, p2 };
};

export const sampleIndices = async ({ maxIndex, count, seed }) => {
  if (!(seed instanceof Uint8Array)) {
    throw new TypeError("seed must be Uint8Array");
  }
  const max = Math.floor(maxIndex);
  const requested = Math.max(0, Math.floor(count));
  if (max < 1) {
    return [];
  }

  const forced = [];
  if (max >= 1) {
    forced.push(1);
    forced.push(max);
  }

  const out = [];
  const seen = new Set();
  for (const idx of forced) {
    if (!seen.has(idx)) {
      seen.add(idx);
      out.push(idx);
    }
  }

  const target = Math.min(max, Math.max(requested, out.length));
  const state = initState(seed, max, requested ^ 0x73616d70);

  while (out.length < target) {
    const idx = uniformMod(state, max) + 1;
    if (seen.has(idx)) {
      continue;
    }
    seen.add(idx);
    out.push(idx);
  }

  return out;
};
