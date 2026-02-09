const encoder = new TextEncoder();

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

const u32be = (value) => {
  const out = new Uint8Array(4);
  const v = value >>> 0;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

const concat = (...chunks) => {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
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

const leafHash = async (page) => sha256(encoder.encode("mhg:leaf"), page);
const nodeHash = async (left, right) => sha256(encoder.encode("mhg:node"), left, right);

const deriveKey = async ({ graphSeed, nonce, index }) => {
  const idx = u32be(index);
  const keyMaterial = await sha256(encoder.encode("mhg:key"), graphSeed, nonce, idx);
  const ivMaterial = await sha256(encoder.encode("mhg:iv"), graphSeed, nonce, idx);
  const key = await crypto.subtle.importKey(
    "raw",
    keyMaterial.slice(0, 16),
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );
  return { key, iv: ivMaterial.slice(0, 16) };
};

const xor3 = (a, b, c) => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i] ^ c[i];
  return out;
};

const mixPage = async ({ index, p0, p1, p2, graphSeed, nonce, pageBytes }) => {
  const input = xor3(p0, p1, p2);
  const { key, iv } = await deriveKey({ graphSeed, nonce, index });
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, input));
  return encrypted.slice(0, pageBytes);
};

const expandGenesisSeed = async ({ graphSeed, nonce, pageBytes }) => {
  const out = new Uint8Array(pageBytes);
  let counter = 0;
  let offset = 0;
  while (offset < pageBytes) {
    const block = await sha256(encoder.encode("mhg:genesis:block"), graphSeed, nonce, u32be(counter));
    const take = Math.min(block.length, pageBytes - offset);
    out.set(block.subarray(0, take), offset);
    offset += take;
    counter += 1;
  }
  return out;
};

const makeGenesisPage = async ({ graphSeed, nonce, pageBytes }) => {
  const seedPage = await expandGenesisSeed({ graphSeed, nonce, pageBytes });
  const zero = new Uint8Array(pageBytes);
  return mixPage({ index: 0, p0: seedPage, p1: zero, p2: zero, graphSeed, nonce, pageBytes });
};

const initState = (seed, a = 0, b = 0) => {
  let x = 0x9e3779b9 ^ (a >>> 0) ^ (b >>> 0);
  for (let i = 0; i < seed.length; i += 1) {
    x ^= (seed[i] + 0x9e3779b9 + ((x << 6) >>> 0) + (x >>> 2)) >>> 0;
    x >>>= 0;
  }
  if (x === 0) x = 0xa341316c;
  return { x };
};

const draw32 = (state) => {
  let x = state.x >>> 0;
  x ^= (x << 13) >>> 0;
  x ^= x >>> 17;
  x ^= (x << 5) >>> 0;
  state.x = x >>> 0;
  return state.x;
};

const uniformMod = (state, mod) => {
  const limit = Math.floor(0x1_0000_0000 / mod) * mod;
  while (true) {
    const n = draw32(state);
    if (n < limit) return n % mod;
  }
};

const parentsOf = (index, graphSeed) => {
  const p0 = index - 1;
  const state = initState(graphSeed, index, 0x70617265);
  const seen = new Set([p0]);
  const picks = [];
  while (picks.length < 2 && seen.size < index) {
    const n = uniformMod(state, index);
    if (seen.has(n)) continue;
    seen.add(n);
    picks.push(n);
  }
  while (picks.length < 2) picks.push(uniformMod(state, index));
  return { p0, p1: picks[0], p2: picks[1] };
};

const buildMerkle = async (pages) => {
  const leaves = await Promise.all(pages.map((page) => leafHash(page)));
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

const randomNonce = () => {
  const raw = new Uint8Array(16);
  crypto.getRandomValues(raw);
  return b64u(raw);
};

const deriveGraphSeed16 = async (ticketB64, nonceString) => {
  const digest = await sha256(
    encoder.encode("mhg|graph|v2|"),
    encoder.encode(ticketB64),
    encoder.encode("|"),
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

const hashcashRootLast = async (root, lastPage) => sha256(encoder.encode("hashcash|v3|"), root, lastPage);

const toOpenEntry = ({ idx, pages, levels, graphSeed }) => {
  const p = parentsOf(idx, graphSeed);
  return {
    i: idx,
    page: b64u(pages[idx]),
    p0: b64u(pages[p.p0]),
    p1: b64u(pages[p.p1]),
    p2: b64u(pages[p.p2]),
    proof: {
      page: buildProof(levels, idx).map((x) => b64u(x)),
      p0: buildProof(levels, p.p0).map((x) => b64u(x)),
      p1: buildProof(levels, p.p1).map((x) => b64u(x)),
      p2: buildProof(levels, p.p2).map((x) => b64u(x)),
    },
  };
};

const buildGraphPages = async ({ graphSeed, nonce, pageBytes, pages }) => {
  const out = new Array(pages);
  out[0] = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  for (let i = 1; i < pages; i += 1) {
    const p = parentsOf(i, graphSeed);
    out[i] = await mixPage({
      index: i,
      p0: out[p.p0],
      p1: out[p.p1],
      p2: out[p.p2],
      graphSeed,
      nonce,
      pageBytes,
    });
  }
  return out;
};

export const buildCrossEndFixture = async (vector, options = {}) => {
  const graphSeed = hexToBytes(vector.graphSeedHex);
  const nonce = hexToBytes(vector.nonceHex);
  if (!graphSeed || graphSeed.length !== 16) throw new Error("graphSeedHex invalid");
  if (!nonce || nonce.length !== 16) throw new Error("nonceHex invalid");
  const pageBytes = Number(vector.pageBytes || 64);
  const pageCount = Number(vector.pages || 128);
  const indices = Array.isArray(vector.indices) ? vector.indices.map((x) => Number(x)) : [];
  const pages = await buildGraphPages({ graphSeed, nonce, pageBytes, pages: pageCount });
  if (typeof options.mutatePages === "function") options.mutatePages(pages);
  const tree = await buildMerkle(pages);
  const opens = indices.map((idx) => toOpenEntry({ idx, pages, levels: tree.levels, graphSeed }));
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
  state = {
    ticketB64,
    steps: Math.max(1, Math.floor(Number(payload.steps) || 1)),
    hashcashBits: Math.max(0, Math.floor(Number(payload.hashcashBits) || 0)),
    pageBytes: 64,
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
  let attempt = 0;
  while (true) {
    checkCancelled();
    attempt += 1;
    const nonce = randomNonce();
    const graphSeed = await deriveGraphSeed16(state.ticketB64, nonce);
    const nonce16 = await deriveNonce16(nonce);
    const pages = await buildGraphPages({
      graphSeed,
      nonce: nonce16,
      pageBytes: state.pageBytes,
      pages: state.steps + 1,
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
  const indices = Array.isArray(payload.indices) ? payload.indices : [];
  if (!indices.length) throw new Error("indices required");
  const opens = [];
  for (let i = 0; i < indices.length; i += 1) {
    checkCancelled();
    const idx = Math.floor(Number(indices[i]));
    if (!Number.isFinite(idx) || idx < 1 || idx > state.steps) throw new Error("indices invalid");
    opens.push(toOpenEntry({ idx, pages: state.pages, levels: state.levels, graphSeed: state.graphSeed }));
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
