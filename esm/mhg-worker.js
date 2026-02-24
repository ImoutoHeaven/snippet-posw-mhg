import { parentsOf as canonicalParentsOf } from "../lib/mhg/parent-contract.js";

const encoder = new TextEncoder();
const LABEL = {
  leaf: encoder.encode("MHG1-LEAF"),
  node: encoder.encode("MHG1-NODE"),
  key: encoder.encode("MHG1-KEY"),
  iv0: encoder.encode("MHG1-IV0"),
  pa: encoder.encode("MHG1-PA"),
  pb: encoder.encode("MHG1-PB"),
  graphPrefix: encoder.encode("mhg|graph|v2|"),
  bar: encoder.encode("|"),
  hashcashV4: encoder.encode("hashcash|v4|"),
  nonceV1: encoder.encode("mhg|commit-nonce|v1|"),
};

const b64u = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const b64uToBytes = (value) => {
  const raw = String(value || "");
  if (!raw) return null;
  let b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};

const hexToBytes = (hex) => {
  if (typeof hex !== "string" || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) return null;
    out[i] = byte;
  }
  return out;
};

const normalizeHashInput = (data) => {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return encoder.encode(String(data ?? ""));
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

const readU32be = (bytes, offset) =>
  (((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0);

const rotl32 = (value, bits) => ((value << bits) | (value >>> (32 - bits))) >>> 0;

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const concat = (...chunks) => {
  const normalized = chunks.map(normalizeHashInput);
  let total = 0;
  for (const chunk of normalized) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of normalized) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const sha256 = async (...chunks) => {
  const bytes = concat(...chunks);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
};

const leafHash = async (index, page) => sha256(LABEL.leaf, u32be(index), page);
const nodeHash = async (left, right) => sha256(LABEL.node, left, right);

const keyCache = new Map();

const getImportedKey = async ({ graphSeed, nonce }) => {
  const keyId = `${bytesToHex(graphSeed)}:${bytesToHex(nonce)}`;
  let keyPromise = keyCache.get(keyId);
  if (!keyPromise) {
    keyPromise = (async () => {
      const keyMaterial = await sha256(LABEL.key, graphSeed, nonce);
      return crypto.subtle.importKey("raw", keyMaterial.slice(0, 32), { name: "AES-CBC" }, false, ["encrypt"]);
    })();
    keyCache.set(keyId, keyPromise);
  }
  try {
    return await keyPromise;
  } catch (error) {
    keyCache.delete(keyId);
    throw error;
  }
};

const xor3 = (a, b, c) => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i] ^ c[i];
  return out;
};

const rotlBytes = (buf, k) => {
  const n = buf.length;
  if (n === 0) return new Uint8Array(0);
  const shift = ((k % n) + n) % n;
  if (shift === 0) return buf.slice();
  const out = new Uint8Array(n);
  out.set(buf.subarray(shift), 0);
  out.set(buf.subarray(0, shift), n - shift);
  return out;
};

const aesCbcNoPadding = async ({ key, iv, input, pageBytes }) => {
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, input));
  return encrypted.subarray(0, pageBytes);
};

const makeGenesisPage = async ({ graphSeed, nonce, pageBytes }) => {
  const key = await getImportedKey({ graphSeed, nonce });
  const iv0 = (await sha256(LABEL.iv0, graphSeed, nonce)).slice(0, 16);
  return aesCbcNoPadding({ key, iv: iv0, input: new Uint8Array(pageBytes), pageBytes });
};

const mixPage = async ({ i, p0, p1, p2, graphSeed, nonce, pageBytes, mixRounds = 2 }) => {
  const key = await getImportedKey({ graphSeed, nonce });
  const pa = await sha256(LABEL.pa, graphSeed, nonce, u32be(i));
  const pb = await sha256(LABEL.pb, graphSeed, nonce, u32be(i));
  const off1 = readU32be(pa, 0) % pageBytes;
  const off2 = readU32be(pa, 4) % pageBytes;
  const off3 = readU32be(pa, 8) % pageBytes;
  const off4 = readU32be(pa, 12) % pageBytes;
  const off5 = readU32be(pa, 16) % pageBytes;
  const iv1 = pb.slice(0, 16);
  const iv2 = pb.slice(16, 32);
  let state = p0;
  let dyn1 = off1;
  let dyn2 = off2;
  let dyn3 = off3;
  let dyn4 = off4;
  let dyn5 = off5;
  for (let round = 0; round < mixRounds; round += 1) {
    const dep = readU32be(state, 0);
    dyn1 = (dyn1 + dep) % pageBytes;
    dyn2 = (dyn2 + rotl32(dep, 8)) % pageBytes;
    dyn3 = (dyn3 + rotl32(dep, 16)) % pageBytes;
    dyn4 = (dyn4 + rotl32(dep, 24)) % pageBytes;
    dyn5 = (dyn5 + ((dep ^ 0x9e3779b9) >>> 0)) % pageBytes;

    const x0 = xor3(state, rotlBytes(p1, dyn1), rotlBytes(p2, dyn2));
    const x1 = await aesCbcNoPadding({ key, iv: iv1, input: x0, pageBytes });
    const x2 = xor3(x1, rotlBytes(p1, dyn3), rotlBytes(p2, dyn4));
    const x3 = await aesCbcNoPadding({ key, iv: iv2, input: x2, pageBytes });
    state = xor3(x3, x0, rotlBytes(x1, dyn5));
  }
  return state;
};

const createParentsResolver = (graphSeed, pages) => {
  const cache = new Map();
  return async (index) => {
    if (cache.has(index)) return cache.get(index);
    const value =
      index >= 3
        ? await canonicalParentsOf(index, graphSeed, pages[index - 1])
        : await canonicalParentsOf(index, graphSeed);
    cache.set(index, value);
    return value;
  };
};

const buildMerkle = async (pages) => {
  const leaves = await Promise.all(pages.map((page, index) => leafHash(index, page)));
  const levels = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      const left = prev[i];
      const right = prev[i + 1] || left;
      next.push(await nodeHash(left, right));
    }
    levels.push(next);
  }
  return { root: levels[levels.length - 1][0], levels, leafCount: leaves.length };
};

const buildProof = (levels, index) => {
  const out = [];
  let cursor = index;
  for (let level = 0; level < levels.length - 1; level += 1) {
    const nodes = levels[level];
    const sibling = cursor ^ 1;
    out.push(nodes[sibling] || nodes[cursor]);
    cursor = Math.floor(cursor / 2);
  }
  return out;
};

const deriveCommitNonce = async ({ ticketB64, steps, pageBytes, mixRounds, hashcashBits, attempt }) => {
  const raw = await sha256(
    LABEL.nonceV1,
    encoder.encode(ticketB64),
    u32be(steps),
    u32be(pageBytes),
    u32be(mixRounds),
    u32be(hashcashBits),
    u32be(attempt)
  );
  return b64u(raw.slice(0, 16));
};

const deriveGraphSeed16 = async (ticketB64, nonceString) => {
  const digest = await sha256(
    LABEL.graphPrefix,
    encoder.encode(ticketB64),
    LABEL.bar,
    encoder.encode(nonceString)
  );
  return digest.slice(0, 16);
};

const deriveNonce16 = async (nonceString) => {
  const raw = b64uToBytes(nonceString);
  if (!raw) {
    const digest = await sha256(encoder.encode(nonceString));
    return digest.slice(0, 16);
  }
  if (raw.length >= 16) return raw.slice(0, 16);
  const digest = await sha256(raw);
  return digest.slice(0, 16);
};

const leadingZeroBits = (bytes) => {
  let count = 0;
  for (const b of bytes) {
    if (b === 0) {
      count += 8;
      continue;
    }
    for (let i = 7; i >= 0; i -= 1) {
      if (b & (1 << i)) return count + (7 - i);
    }
  }
  return count;
};

const hashcashRootLast = async (root, lastPage) => sha256(LABEL.hashcashV4, root, lastPage);

const shouldYield = (counter, every) =>
  Number.isFinite(every) && every > 0 && counter % every === 0;

const sleep0 = () => new Promise((resolve) => setTimeout(resolve, 0));

const buildEqSet = (index, segmentLen) => {
  const start = Math.max(1, index - segmentLen + 1);
  const out = [];
  for (let i = start; i <= index; i += 1) out.push(i);
  return out;
};

const toOpenEntry = async ({ idx, seg, pages, levels, graphSeed }) => {
  const segmentLen = seg;
  if (!Number.isInteger(segmentLen) || segmentLen < 2 || segmentLen > 16) {
    throw new Error("segs invalid");
  }
  const eqSet = buildEqSet(idx, segmentLen);
  const need = new Set();
  for (const j of eqSet) {
    const p = j >= 3 ? await canonicalParentsOf(j, graphSeed, pages[j - 1]) : await canonicalParentsOf(j, graphSeed);
    need.add(j);
    need.add(p.p0);
    need.add(p.p1);
    need.add(p.p2);
  }
  const sortedNeed = Array.from(need).sort((a, b) => a - b);
  const nodes = {};
  for (const needIdx of sortedNeed) {
    nodes[String(needIdx)] = {
      pageB64: b64u(pages[needIdx]),
      proof: buildProof(levels, needIdx).map((x) => b64u(x)),
    };
  }
  return {
    i: idx,
    seg: segmentLen,
    nodes,
  };
};

const buildGraphPages = async ({
  graphSeed,
  nonce,
  pageBytes,
  mixRounds = 2,
  pages,
  yieldEvery = 1024,
  onProgress,
  checkCancelled,
}) => {
  const out = new Array(pages);
  const parentsOfIndex = createParentsResolver(graphSeed, out);
  const total = Math.max(0, pages - 1);
  out[0] = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  if (typeof onProgress === "function") onProgress(0, total);
  for (let i = 1; i < pages; i += 1) {
    if (typeof checkCancelled === "function") checkCancelled();
    const p = await parentsOfIndex(i);
    out[i] = await mixPage({
      i,
      p0: out[p.p0],
      p1: out[p.p1],
      p2: out[p.p2],
      graphSeed,
      nonce,
      pageBytes,
      mixRounds,
    });
    if (typeof onProgress === "function") onProgress(i, total);
    if (shouldYield(i, yieldEvery)) {
      await sleep0();
    }
  }
  return out;
};

export const buildCrossEndFixture = async (vector, options = {}) => {
  const graphSeed = hexToBytes(vector.graphSeedHex);
  const nonce = hexToBytes(vector.nonceHex);
  if (!graphSeed || graphSeed.length !== 16) throw new Error("graphSeedHex invalid");
  if (!nonce || nonce.length !== 16) throw new Error("nonceHex invalid");
  const pageBytes = Number(vector.pageBytes || 64);
  const mixRounds = Number(vector.mixRounds || 2);
  const pageCount = Number(vector.pages || 128);
  const indices = Array.isArray(vector.indices) ? vector.indices.map((x) => Number(x)) : [];
  const pages = await buildGraphPages({ graphSeed, nonce, pageBytes, mixRounds, pages: pageCount });
  if (typeof options.mutatePages === "function") options.mutatePages(pages);
  const tree = await buildMerkle(pages);
  const segs = Array.isArray(vector.segs) ? vector.segs : [];
  const opens = await Promise.all(
    indices.map((idx, pos) => toOpenEntry({ idx, seg: segs[pos] ?? 2, pages, levels: tree.levels, graphSeed }))
  );
  return {
    root: tree.root,
    rootB64: b64u(tree.root),
    leafCount: tree.leafCount,
    graphSeed,
    nonce,
    pageBytes,
    opens,
  };
};

let cancelled = false;
let state = null;

const emitProgress = (phase, done = 0, total = 0, attempt = 0) => {
  postMessage({ type: "PROGRESS", phase, done, total, attempt });
};

const initWorkerState = (payload) => {
  const ticketB64 = typeof payload.ticketB64 === "string" ? payload.ticketB64 : "";
  if (!ticketB64) throw new Error("ticketB64 required");

  const steps = payload.steps;
  const hashcashBits = payload.hashcashBits;
  const pageBytes = payload.pageBytes;
  const mixRounds = payload.mixRounds;

  if (!Number.isInteger(steps) || steps < 1) throw new Error("steps invalid");
  if (!Number.isInteger(hashcashBits) || hashcashBits < 0) throw new Error("hashcashBits invalid");
  if (!Number.isInteger(pageBytes) || pageBytes < 16 || pageBytes % 16 !== 0) throw new Error("pageBytes invalid");
  if (!Number.isInteger(mixRounds) || mixRounds < 0) throw new Error("mixRounds invalid");

  state = {
    ticketB64,
    steps,
    hashcashBits,
    pageBytes,
    mixRounds,
    yieldEvery: Math.max(1, Math.floor(Number(payload.yieldEvery) || 1024)),
    progressEvery: Math.max(1, Math.floor(Number(payload.progressEvery) || 1024)),
    nonce: "",
    graphSeed: null,
    nonce16: null,
    pages: null,
    levels: null,
    rootB64: "",
    ready: false,
  };
  cancelled = false;
};

const checkCancelled = () => {
  if (cancelled) throw new Error("mhg aborted");
};

const computeCommit = async () => {
  if (!state) throw new Error("not initialized");
  const progressEvery = state.progressEvery;
  let attempt = 0;
  while (true) {
    checkCancelled();
    attempt += 1;
    const nonce = await deriveCommitNonce({
      ticketB64: state.ticketB64,
      steps: state.steps,
      pageBytes: state.pageBytes,
      mixRounds: state.mixRounds,
      hashcashBits: state.hashcashBits,
      attempt,
    });
    const graphSeed = await deriveGraphSeed16(state.ticketB64, nonce);
    const nonce16 = await deriveNonce16(nonce);
    const pages = await buildGraphPages({
      graphSeed,
      nonce: nonce16,
      pageBytes: state.pageBytes,
      mixRounds: state.mixRounds,
      pages: state.steps + 1,
      yieldEvery: state.yieldEvery,
      checkCancelled,
      onProgress: (done, total) => {
        if (done === 0 || done === total || done % progressEvery === 0) {
          emitProgress("chain", done, total, attempt - 1);
        }
      },
    });
    const tree = await buildMerkle(pages);
    if (state.hashcashBits > 0) {
      const digest = await hashcashRootLast(tree.root, pages[state.steps]);
      if (leadingZeroBits(digest) < state.hashcashBits) {
        emitProgress("hashcash", 0, 0, attempt);
        continue;
      }
    }
    state.nonce = nonce;
    state.graphSeed = graphSeed;
    state.nonce16 = nonce16;
    state.pages = pages;
    state.levels = tree.levels;
    state.rootB64 = b64u(tree.root);
    state.ready = true;
    return { rootB64: state.rootB64, nonce };
  }
};

const computeOpen = async (payload) => {
  if (!state || !state.ready) throw new Error("commit missing");
  const indices = payload.indices;
  const segs = payload.segs;
  if (!Array.isArray(indices)) throw new Error("indices required");
  if (!Array.isArray(segs)) throw new Error("segs required");
  if (!indices.length) throw new Error("indices required");
  if (segs.length !== indices.length) throw new Error("segs required");
  const opens = [];
  for (let i = 0; i < indices.length; i += 1) {
    checkCancelled();
    const idx = indices[i];
    const seg = segs[i];
    if (!Number.isInteger(idx) || idx < 1 || idx > state.steps) throw new Error("indices invalid");
    if (!Number.isInteger(seg) || seg < 2 || seg > 16) throw new Error("segs invalid");
    opens.push(
      await toOpenEntry({
        idx,
        seg,
        pages: state.pages,
        levels: state.levels,
        graphSeed: state.graphSeed,
      })
    );
    emitProgress("open", i + 1, indices.length, 0);
  }
  return opens;
};

if (typeof self !== "undefined" && typeof self.addEventListener === "function") {
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
          postMessage({ type: "CANCEL_OK", rid });
          return;
        }
        if (type === "DISPOSE") {
          cancelled = true;
          state = null;
          postMessage({ type: "DISPOSE_OK", rid });
          return;
        }
        if (type === "INIT") {
          initWorkerState(data);
          postMessage({ type: "INIT_OK", rid });
          return;
        }
        if (type === "COMMIT") {
          const out = await computeCommit();
          postMessage({ type: "COMMIT_OK", rid, rootB64: out.rootB64, nonce: out.nonce });
          return;
        }
        if (type === "OPEN") {
          const opens = await computeOpen(data);
          postMessage({ type: "OPEN_OK", rid, opens });
          return;
        }
        throw new Error("unknown command");
      } catch (err) {
        sendError(err);
      }
    })();
  };
}
