// Cloudflare Snippet: pow-config header injector

const CONFIG = [];

const DEFAULTS = {
  powcheck: false,
  turncheck: false,
  bindPathMode: "none",
  bindPathQueryName: "path",
  bindPathHeaderName: "",
  stripBindPathHeader: false,
  POW_VERSION: 3,
  POW_API_PREFIX: "/__pow",
  POW_DIFFICULTY_BASE: 8192,
  POW_DIFFICULTY_COEFF: 1.0,
  POW_MIN_STEPS: 512,
  POW_MAX_STEPS: 8192,
  POW_HASHCASH_BITS: 3,
  POW_SEGMENT_LEN: "48-64",
  POW_SAMPLE_K: 15,
  POW_SPINE_K: 2,
  POW_CHAL_ROUNDS: 12,
  POW_OPEN_BATCH: 15,
  POW_FORCE_EDGE_1: true,
  POW_FORCE_EDGE_LAST: true,
  POW_COMMIT_TTL_SEC: 120,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 600,
  PROOF_RENEW_ENABLE: false,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 30,
  ATOMIC_CONSUME: false,
  ATOMIC_TURN_QUERY: "__ts",
  ATOMIC_TICKET_QUERY: "__tt",
  ATOMIC_CONSUME_QUERY: "__ct",
  ATOMIC_TURN_HEADER: "x-turnstile",
  ATOMIC_TICKET_HEADER: "x-ticket",
  ATOMIC_CONSUME_HEADER: "x-consume",
  ATOMIC_COOKIE_NAME: "__Secure-pow_a",
  STRIP_ATOMIC_QUERY: true,
  STRIP_ATOMIC_HEADERS: true,
  INNER_AUTH_QUERY_NAME: "",
  INNER_AUTH_QUERY_VALUE: "",
  INNER_AUTH_HEADER_NAME: "",
  INNER_AUTH_HEADER_VALUE: "",
  stripInnerAuthQuery: false,
  stripInnerAuthHeader: false,
  POW_BIND_PATH: true,
  POW_BIND_IPRANGE: true,
  POW_BIND_COUNTRY: false,
  POW_BIND_ASN: false,
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/glue.js",
};

const COMPILED_CONFIG = __COMPILED_CONFIG__.map((entry) => ({
  hostRegex: entry.host ? new RegExp(entry.host.s, entry.host.f || "") : null,
  pathRegex: entry.path ? new RegExp(entry.path.s, entry.path.f || "") : null,
  config: entry.config || {},
}));

const INNER_HEADER = "X-Pow-Inner";
const INNER_MAC = "X-Pow-Inner-Mac";
const CONFIG_SECRET = "replace-me";
const isPlaceholderConfigSecret = (value) =>
  typeof value !== "string" || !value.trim() || value === "replace-me";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const base64UrlEncode = (bytes) => {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
};

const base64UrlEncodeNoPad = (bytes) => base64UrlEncode(bytes).replace(/=+$/g, "");

const base64UrlDecodeToBytes = (b64u) => {
  if (!b64u || typeof b64u !== "string") return null;
  let b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
};

const utf8ToBytes = (value) => encoder.encode(String(value ?? ""));

const getHmacKey = (secret) => {
  const key = typeof secret === "string" ? secret : "";
  if (!key) {
    return Promise.reject(new Error("HMAC secret missing"));
  }
  if (!hmacKeyCache.has(key)) {
    hmacKeyCache.set(
      key,
      crypto.subtle.importKey(
        "raw",
        encoder.encode(key),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      )
    );
  }
  return hmacKeyCache.get(key);
};

const hmacSha256 = async (secret, data) => {
  const key = await getHmacKey(secret);
  const payload = encoder.encode(data);
  const buf = await crypto.subtle.sign("HMAC", key, payload);
  return new Uint8Array(buf);
};

const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const bytes = await hmacSha256(secret, data);
  return base64UrlEncodeNoPad(bytes);
};

const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 256;
const NONCE_MIN_LEN = 16;
const NONCE_MAX_LEN = 64;
const SPINE_SEED_MIN_LEN = 16;
const SPINE_SEED_MAX_LEN = 64;
const TB_LEN = 16;

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

const normalizeNumber = (value, fallback) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
};

const normalizeBoolean = (value, fallback) =>
  value === true ? true : value === false ? false : fallback;

const normalizeString = (value, fallback) =>
  typeof value === "string" ? value : fallback;

const normalizePath = (pathname) => {
  if (typeof pathname !== "string") return null;
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.length === 0) return "/";
  return decoded.startsWith("/") ? decoded : `/${decoded}`;
};

const parseCookieHeader = (cookieHeader) => {
  const out = new Map();
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(";");
  for (let part of parts) {
    part = part.trim();
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (!key) continue;
    try {
      value = decodeURIComponent(value);
    } catch {
      // ignore decoding errors
    }
    out.set(key, value);
  }
  return out;
};

const getClientIP = (request) =>
  request.headers.get("CF-Connecting-IP") ||
  request.headers.get("cf-connecting-ip") ||
  "0.0.0.0";

const isIpv4 = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
const isIpv6 = (ip) => ip.includes(":");

const parseIpv4 = (ip) => {
  if (!isIpv4(ip)) return null;
  const parts = ip.split(".").map((v) => Number.parseInt(v, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return null;
  }
  return parts;
};

const formatIpv4 = (bytes) => bytes.join(".");

const ipv4Cidr = (ip, prefix) => {
  const bytes = parseIpv4(ip);
  if (!bytes) return null;
  const p = Math.min(32, Math.max(0, Number(prefix)));
  const ipInt = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  const mask = p === 0 ? 0 : (~0 << (32 - p)) >>> 0;
  const net = ipInt & mask;
  const netBytes = [
    (net >>> 24) & 0xff,
    (net >>> 16) & 0xff,
    (net >>> 8) & 0xff,
    net & 0xff,
  ];
  return `${formatIpv4(netBytes)}/${p}`;
};

const parseIpv6Hextets = (part) => {
  if (!part) return [];
  const tokens = part.split(":");
  const out = [];
  for (const token of tokens) {
    if (!token) continue;
    if (token.includes(".")) {
      const v4 = parseIpv4(token);
      if (!v4) return null;
      const hi = (v4[0] << 8) | v4[1];
      const lo = (v4[2] << 8) | v4[3];
      out.push(hi, lo);
      continue;
    }
    const value = Number.parseInt(token, 16);
    if (!Number.isFinite(value) || value < 0 || value > 0xffff) return null;
    out.push(value);
  }
  return out;
};

const parseIpv6 = (ip) => {
  if (!ip || typeof ip !== "string") return null;
  const raw = ip.split("%")[0];
  if (!raw) return null;
  if (raw === "::") return new Uint8Array(16);
  const parts = raw.split("::");
  if (parts.length > 2) return null;
  const head = parseIpv6Hextets(parts[0]);
  if (head === null) return null;
  const tail = parts.length === 2 ? parseIpv6Hextets(parts[1]) : [];
  if (tail === null) return null;
  const total = head.length + tail.length;
  if (total > 8) return null;
  const zeros = parts.length === 2 ? 8 - total : 0;
  if (parts.length === 1 && total !== 8) return null;
  const full = head.concat(Array(zeros).fill(0)).concat(tail);
  if (full.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (full[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = full[i] & 0xff;
  }
  return bytes;
};

const formatIpv6 = (bytes) => {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    const value = (bytes[i] << 8) | bytes[i + 1];
    parts.push(value.toString(16).padStart(4, "0"));
  }
  return parts.join(":");
};

const ipv6Cidr = (ip, prefix) => {
  const bytes = parseIpv6(ip);
  if (!bytes) return null;
  const p = Math.min(128, Math.max(0, Number(prefix)));
  const fullBytes = Math.floor(p / 8);
  const rem = p % 8;
  const out = new Uint8Array(bytes);
  for (let i = 0; i < 16; i++) {
    if (i < fullBytes) continue;
    if (i === fullBytes && rem > 0) {
      const mask = 0xff << (8 - rem);
      out[i] = out[i] & mask;
    } else {
      out[i] = 0;
    }
  }
  return `${formatIpv6(out)}/${p}`;
};

const computeIpScope = (ip, config) => {
  const v4Prefix = normalizeNumber(config.IPV4_PREFIX, DEFAULTS.IPV4_PREFIX);
  const v6Prefix = normalizeNumber(config.IPV6_PREFIX, DEFAULTS.IPV6_PREFIX);
  if (isIpv4(ip)) {
    return ipv4Cidr(ip, v4Prefix) || "unknown";
  }
  if (isIpv6(ip)) {
    return ipv6Cidr(ip, v6Prefix) || "unknown";
  }
  return "unknown";
};

const getRequestCf = (request) => {
  const cf = request && request.cf;
  return cf && typeof cf === "object" ? cf : null;
};

const normalizeCfValue = (value) => {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return String(value);
};

const normalizeCountry = (value) => {
  const raw = normalizeCfValue(value);
  return raw ? raw.toUpperCase() : "unknown";
};

const normalizeAsn = (value) => {
  const num = Number(value);
  return Number.isFinite(num) ? String(Math.trunc(num)) : "unknown";
};

const normalizeTlsFingerprint = (value) => {
  if (typeof value !== "string") return "";
  return value.trim();
};

const buildTlsFingerprintHash = async (request) => {
  const cf = getRequestCf(request);
  if (!cf) return "";
  const extensions = normalizeTlsFingerprint(cf.tlsClientExtensionsSha1);
  const ciphers = normalizeTlsFingerprint(cf.tlsClientCiphersSha1);
  if (!extensions || !ciphers) return "";
  const digest = await sha256Bytes(`${extensions}|${ciphers}`);
  return base64UrlEncodeNoPad(digest);
};

const normalizeConfig = (baseConfig) => {
  const merged = { ...DEFAULTS, ...(baseConfig || {}) };
  return {
    ...merged,
    powcheck: normalizeBoolean(merged.powcheck, DEFAULTS.powcheck),
    turncheck: normalizeBoolean(merged.turncheck, DEFAULTS.turncheck),
    POW_BIND_PATH: normalizeBoolean(merged.POW_BIND_PATH, DEFAULTS.POW_BIND_PATH),
    POW_BIND_IPRANGE: normalizeBoolean(merged.POW_BIND_IPRANGE, DEFAULTS.POW_BIND_IPRANGE),
    POW_BIND_COUNTRY: normalizeBoolean(merged.POW_BIND_COUNTRY, DEFAULTS.POW_BIND_COUNTRY),
    POW_BIND_ASN: normalizeBoolean(merged.POW_BIND_ASN, DEFAULTS.POW_BIND_ASN),
    POW_BIND_TLS: normalizeBoolean(merged.POW_BIND_TLS, DEFAULTS.POW_BIND_TLS),
    IPV4_PREFIX: normalizeNumber(merged.IPV4_PREFIX, DEFAULTS.IPV4_PREFIX),
    IPV6_PREFIX: normalizeNumber(merged.IPV6_PREFIX, DEFAULTS.IPV6_PREFIX),
    POW_API_PREFIX: normalizeString(merged.POW_API_PREFIX, DEFAULTS.POW_API_PREFIX),
    POW_COMMIT_COOKIE: normalizeString(merged.POW_COMMIT_COOKIE, DEFAULTS.POW_COMMIT_COOKIE),
  };
};

const pickConfigWithId = (hostname, path) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  const requestPath = typeof path === "string" ? path : "";
  if (!host) return null;
  for (let i = 0; i < COMPILED_CONFIG.length; i++) {
    const rule = COMPILED_CONFIG[i];
    if (!rule || !rule.hostRegex) continue;
    if (!rule.hostRegex.test(host)) continue;
    if (rule.pathRegex && !rule.pathRegex.test(requestPath)) continue;
    return { cfgId: i, config: rule.config || null };
  }
  return null;
};

const getConfigById = (cfgId) => {
  if (!Number.isInteger(cfgId) || cfgId < 0 || cfgId >= COMPILED_CONFIG.length) {
    return null;
  }
  const entry = COMPILED_CONFIG[cfgId];
  return entry && entry.config ? entry.config : null;
};

const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = decoder.decode(bytes);
  const parts = raw.split(".");
  if (parts.length !== 6) return null;
  const cfgId = Number.parseInt(parts[4], 10);
  if (!Number.isFinite(cfgId)) return null;
  return { cfgId };
};

const parsePowCommitCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 9) return null;
  if (parts[0] !== "v4") return null;
  const ticketB64 = parts[1] || "";
  const rootB64 = parts[2] || "";
  const pathHash = parts[3] || "";
  const tb = parts[4] || "";
  const nonce = parts[5] || "";
  const exp = Number.parseInt(parts[6], 10);
  const spineSeed = parts[7] || "";
  const mac = parts[8] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN)) return null;
  if (!(pathHash === "any" || isBase64Url(pathHash, 1, B64_HASH_MAX_LEN))) return null;
  if (!(tb === "any" || isBase64Url(tb, TB_LEN, TB_LEN))) return null;
  if (!isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) return null;
  if (!isBase64Url(spineSeed, SPINE_SEED_MIN_LEN, SPINE_SEED_MAX_LEN)) {
    return null;
  }
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  if (!Number.isFinite(exp) || exp <= 0) return null;
  return { ticketB64 };
};

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const resolveCfgIdFromPowApi = async (request, requestPath) => {
  if (!requestPath.startsWith(`${DEFAULTS.POW_API_PREFIX}/`)) return null;
  const action = requestPath.slice(DEFAULTS.POW_API_PREFIX.length);
  if (action === "/commit" || action === "/turn") {
    const body = await readJsonBody(request.clone());
    const ticketB64 = body && typeof body.ticketB64 === "string" ? body.ticketB64 : "";
    const ticket = parsePowTicket(ticketB64);
    return ticket ? ticket.cfgId : null;
  }
  if (action === "/challenge" || action === "/open") {
    const cookies = parseCookieHeader(request.headers.get("Cookie"));
    const commitRaw = cookies.get(DEFAULTS.POW_COMMIT_COOKIE) || "";
    const commit = parsePowCommitCookie(commitRaw);
    const ticket = commit ? parsePowTicket(commit.ticketB64) : null;
    return ticket ? ticket.cfgId : null;
  }
  return null;
};

const buildDerivedBindings = async (request, config) => {
  const bindIp = config.POW_BIND_IPRANGE !== false;
  const bindCountry = config.POW_BIND_COUNTRY === true;
  const bindAsn = config.POW_BIND_ASN === true;
  const bindTls = config.POW_BIND_TLS === true;
  const ipScope = bindIp ? computeIpScope(getClientIP(request), config) : "any";
  const cf = getRequestCf(request);
  const country = bindCountry ? normalizeCountry(cf && cf.country) : "any";
  const asn = bindAsn ? normalizeAsn(cf && cf.asn) : "any";
  let tlsFingerprint = "any";
  if (bindTls) {
    tlsFingerprint = await buildTlsFingerprintHash(request);
  }
  return { ipScope, country, asn, tlsFingerprint };
};

const buildSignedInnerPayload = async (request, cfgId, config) => {
  const normalizedConfig = normalizeConfig(config);
  const derived = await buildDerivedBindings(request, normalizedConfig);
  const payloadObj = { v: 1, id: cfgId, c: normalizedConfig, d: derived };
  const payload = base64UrlEncodeNoPad(utf8ToBytes(JSON.stringify(payloadObj)));
  const mac = await hmacSha256Base64UrlNoPad(CONFIG_SECRET, payload);
  return { payload, mac };
};

const resolveConfig = async (request, url, requestPath) => {
  const cfgIdFromApi = await resolveCfgIdFromPowApi(request, requestPath);
  if (Number.isInteger(cfgIdFromApi)) {
    const config = getConfigById(cfgIdFromApi);
    if (!config) {
      return { cfgId: -1, config: DEFAULTS };
    }
    return { cfgId: cfgIdFromApi, config };
  }
  const selected = pickConfigWithId(url.hostname, requestPath);
  if (selected) return { cfgId: selected.cfgId, config: selected.config || DEFAULTS };
  return { cfgId: -1, config: DEFAULTS };
};

export { hmacSha256Base64UrlNoPad };

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const requestPath = normalizePath(url.pathname);
    if (!requestPath) {
      return new Response(null, { status: 400 });
    }

    if (isPlaceholderConfigSecret(CONFIG_SECRET)) {
      return new Response(null, { status: 500 });
    }

    const resolved = await resolveConfig(request, url, requestPath);
    const { payload, mac } = await buildSignedInnerPayload(
      request,
      resolved.cfgId,
      resolved.config
    );

    const headers = new Headers(request.headers);
    headers.delete(INNER_HEADER);
    headers.delete(INNER_MAC);
    headers.set(INNER_HEADER, payload);
    headers.set(INNER_MAC, mac);

    const forward = new Request(request, { headers });
    return fetch(forward);
  },
};
