const asStrictInt = (value) => {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/u.test(value)) {
    const parsed = Number.parseInt(value, 10);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
};

export const EQ_N_MIN = 8;
export const EQ_N_MAX = 256;
export const EQ_K_MIN = 2;
export const EQ_K_MAX = 8;
export const EQ_DEFAULT_N = 90;
export const EQ_DEFAULT_K = 5;

export const isValidEquihashParams = (nRaw, kRaw) => {
  const n = asStrictInt(nRaw);
  const k = asStrictInt(kRaw);
  if (n === null || k === null) return false;
  if (n < EQ_N_MIN || n > EQ_N_MAX || n % 2 !== 0) return false;
  if (k < EQ_K_MIN || k > EQ_K_MAX) return false;
  return n % (k + 1) === 0;
};

export const normalizeEquihashParams = (nRaw, kRaw) => {
  if (isValidEquihashParams(nRaw, kRaw)) {
    return { n: Number(nRaw), k: Number(kRaw) };
  }
  return { n: EQ_DEFAULT_N, k: EQ_DEFAULT_K };
};
