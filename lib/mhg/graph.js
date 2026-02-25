import { uniformMod } from "./parent-contract.js";

export {
  deriveDynamicParent2,
  draw32,
  pickDistinct,
  staticParentsOf,
  uniformMod,
} from "./parent-contract.js";

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
  let ctr = 0;

  while (out.length < target) {
    const next = await uniformMod({ seed, label: "sample", i: max, mod: max, ctr });
    ctr = next.ctr;
    const idx = next.value + 1;
    if (seen.has(idx)) {
      continue;
    }
    seen.add(idx);
    out.push(idx);
  }

  return out;
};
