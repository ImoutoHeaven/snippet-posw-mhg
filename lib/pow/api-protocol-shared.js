import { verifyViaSiteverifyAggregator } from "./siteverify-client.js";

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export const B64_HASH_MAX_LEN = 64;
export const B64_TICKET_MAX_LEN = 256;
export const NONCE_MIN_LEN = 16;
export const NONCE_MAX_LEN = 64;
export const TOKEN_MIN_LEN = 16;
export const TOKEN_MAX_LEN = 64;
export const CAPTCHA_TAG_LEN = 16;
export const TURN_TOKEN_MIN_LEN = 20;
export const TURN_TOKEN_MAX_LEN = 4096;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

export const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

export const timingSafeEqual = (a, b) => {
  const aNorm = typeof a === "string" ? a : "";
  const bNorm = typeof b === "string" ? b : "";
  if (aNorm.length !== bNorm.length) return false;
  let diff = 0;
  for (let i = 0; i < aNorm.length; i += 1) {
    diff |= aNorm.charCodeAt(i) ^ bNorm.charCodeAt(i);
  }
  return diff === 0;
};

export const base64UrlEncodeNoPad = (bytes) => {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

export const base64UrlDecodeToBytes = (b64u) => {
  if (!b64u || typeof b64u !== "string") return null;
  let b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
};

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
        ["sign"],
      ),
    );
  }
  return hmacKeyCache.get(key);
};

export const hmacSha256 = async (secret, data) => {
  const key = await getHmacKey(secret);
  const payload = encoder.encode(data);
  const buf = await crypto.subtle.sign("HMAC", key, payload);
  return new Uint8Array(buf);
};

export const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const bytes = await hmacSha256(secret, data);
  return base64UrlEncodeNoPad(bytes);
};

const u32BE = (bytes, offset) =>
  ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

const rotl = (value, count) => ((value << count) | (value >>> (32 - count))) >>> 0;

const clampInt = (value, lo, hi) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(num)));
};

const bucketIdOf = (idx, max, bucketCount) => {
  const value = Math.floor(((idx - 1) * bucketCount) / max);
  return Math.max(0, Math.min(bucketCount - 1, value));
};

const bucketRange = (bucket, max, bucketCount) => {
  const start = 1 + Math.floor((bucket * max) / bucketCount);
  const end = 1 + Math.floor(((bucket + 1) * max) / bucketCount);
  const lo = Math.max(1, Math.min(max, start));
  const hi = Math.max(lo, Math.min(max + 1, end));
  return { lo, hi };
};

const pickFromBucket = (rng, bucket, max, bucketCount) => {
  const { lo, hi } = bucketRange(bucket, max, bucketCount);
  const span = Math.max(1, hi - lo);
  const idx = lo + rng.randInt(span);
  return Math.max(1, Math.min(max, idx));
};

export const normalizePowSampleRate = (value, fallback = 0.01) => {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return fallback;
  return Math.min(1, num);
};

export const computePowSampleExtraCount = (L, rate) => {
  const leafCount = Math.max(0, Math.floor(Number(L) || 0));
  if (leafCount <= 0) return 0;
  const normalizedRate = normalizePowSampleRate(rate);
  const totalTarget = Math.ceil(leafCount * normalizedRate);
  const fixedAnchors = leafCount === 1 ? 1 : 2;
  const maxExtra = Math.max(0, leafCount - fixedAnchors);
  return Math.max(0, Math.min(maxExtra, totalTarget - fixedAnchors));
};

export const makeXoshiro128ss = (seed16) => {
  let a = u32BE(seed16, 0);
  let b = u32BE(seed16, 4);
  let c = u32BE(seed16, 8);
  let d = u32BE(seed16, 12);
  if ((a | b | c | d) === 0) d = 1;

  const nextU32 = () => {
    const result = rotl(Math.imul(a, 5) >>> 0, 7);
    const out = Math.imul(result, 9) >>> 0;
    const t = (b << 9) >>> 0;
    c ^= a;
    d ^= b;
    b ^= c;
    a ^= d;
    c ^= t;
    d = rotl(d, 11);
    return out >>> 0;
  };

  const nextFloat = () => nextU32() / 4294967296;
  const randInt = (span) => Math.floor(nextFloat() * span);
  const shuffle = (array) => {
    for (let i = array.length - 1; i > 0; i -= 1) {
      const j = randInt(i + 1);
      const tmp = array[i];
      array[i] = array[j];
      array[j] = tmp;
    }
  };

  return { nextU32, nextFloat, randInt, shuffle };
};

export const parseSegmentLenSpec = (raw) => {
  if (raw === null || raw === undefined) return null;
  const isNumericString = typeof raw === "string" && /^\d+$/.test(raw.trim());
  if (typeof raw === "number" && Number.isFinite(raw)) {
    const fixed = clampInt(raw, 2, 16);
    return { mode: "fixed", fixed };
  }
  if (isNumericString) {
    const fixed = clampInt(raw, 2, 16);
    return { mode: "fixed", fixed };
  }
  if (typeof raw === "string") {
    const match = raw.trim().match(/^(\d+)\s*-\s*(\d+)$/);
    if (match) {
      const min = clampInt(match[1], 2, 16);
      const max = clampInt(match[2], 2, 16);
      if (min <= max && max - min <= 15) {
        return { mode: "range", min, max };
      }
    }
  }
  return null;
};

export const computeSegLensForIndices = (indices, segSpec, rngSeg) => {
  if (!segSpec || segSpec.mode !== "range") {
    const fixed = clampInt(segSpec && segSpec.fixed, 2, 16);
    return indices.map(() => fixed);
  }
  const span = Math.max(1, Math.floor(segSpec.max - segSpec.min + 1));
  return indices.map(() => segSpec.min + rngSeg.randInt(span));
};

export const sampleIndicesDeterministicV2 = ({ maxIndex, extraCount, forceEdge1, forceEdgeLast, rng }) => {
  const max = Math.floor(Number(maxIndex) || 0);
  if (max <= 0) return [];
  const out = new Set();
  if (forceEdge1 && max >= 1) out.add(1);
  if (forceEdgeLast && max >= 1) out.add(max);
  const extra = Math.max(0, Math.floor(Number(extraCount) || 0));
  const target = Math.min(max, out.size + extra);
  if (target <= out.size) return Array.from(out).sort((a, b) => a - b);

  const bucketCount = Math.min(64, Math.max(1, Math.floor(max / 128)));
  const covered = new Array(bucketCount).fill(false);
  for (const v of out) covered[bucketIdOf(v, max, bucketCount)] = true;

  let need = target - out.size;
  const buckets = [];
  for (let b = 0; b < bucketCount; b += 1) {
    if (!covered[b]) buckets.push(b);
  }
  rng.shuffle(buckets);
  const coverN = Math.min(need, buckets.length);
  for (let i = 0; i < coverN; i += 1) {
    const bucket = buckets[i];
    const idx = pickFromBucket(rng, bucket, max, bucketCount);
    out.add(idx);
    covered[bucket] = true;
    need = target - out.size;
    if (need <= 0) break;
  }

  let attempts = 0;
  const maxAttempts = Math.max(256, need * 32);
  while (need > 0 && attempts < maxAttempts) {
    const bucket = rng.randInt(bucketCount);
    const idx = pickFromBucket(rng, bucket, max, bucketCount);
    const before = out.size;
    out.add(idx);
    if (out.size !== before) need -= 1;
    attempts += 1;
  }

  if (need > 0) {
    for (let i = 1; i <= max && need > 0; i += 1) {
      if (!out.has(i)) {
        out.add(i);
        need -= 1;
      }
    }
  }

  const result = Array.from(out);
  rng.shuffle(result);
  const anchors = [];
  if (forceEdge1 && max >= 1) anchors.push(1);
  if (forceEdgeLast && max >= 1 && max !== 1) anchors.push(max);
  if (anchors.length) {
    for (const anchor of anchors) {
      const idx = result.indexOf(anchor);
      if (idx >= 0) result.splice(idx, 1);
    }
    return anchors.concat(result);
  }
  return result;
};

export const derivePowSeedBytes16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `D|${cfgId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

export const deriveSegLenSeed16 = async (powSecret, cfgId, commitMac, sid) => {
  const bytes = await hmacSha256(powSecret, `G|${cfgId}|${commitMac}|${sid}`);
  return bytes.slice(0, 16);
};

export const sha256Bytes = async (data) => {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
};

export const makePowCommitMac = async (powSecret, ticketB64, rootB64, pathHash, captchaTag, nonce, exp) =>
  hmacSha256Base64UrlNoPad(
    powSecret,
    `C2|${ticketB64}|${rootB64}|${pathHash}|${captchaTag}|${nonce}|${exp}`,
  );

export const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

export const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

export const makePowStateToken = async (powSecret, cfgId, sid, commitMac, cursor, batchLen) =>
  hmacSha256Base64UrlNoPad(powSecret, `S2|${cfgId}|${sid}|${commitMac}|${cursor}|${batchLen}`);

export const getPowDifficultyBinding = (config) => ({
  pageBytes: (() => {
    const raw = Number(config?.POW_PAGE_BYTES);
    if (!Number.isFinite(raw)) return 16384;
    const pageBytes = Math.floor(raw);
    if (pageBytes < 16) return 16384;
    return Math.floor(pageBytes / 16) * 16;
  })(),
  mixRounds: (() => {
    const raw = Number(config?.POW_MIX_ROUNDS);
    if (!Number.isFinite(raw)) return 2;
    return Math.max(1, Math.min(4, Math.floor(raw)));
  })(),
});

export const makePowBindingString = (
  ticket,
  hostname,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  pageBytes,
  mixRounds,
) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  return (
    ticket.v +
    "|" +
    ticket.e +
    "|" +
    ticket.L +
    "|" +
    ticket.r +
    "|" +
    ticket.cfgId +
    "|" +
    host +
    "|" +
    pathHash +
    "|" +
    ipScope +
    "|" +
    country +
    "|" +
    asn +
    "|" +
    tlsFingerprint +
    "|" +
    pageBytes +
    "|" +
    mixRounds +
    "|" +
    ticket.issuedAt
  );
};

export const verifyTicketMac = async (ticket, url, bindingValues, config, powSecret) => {
  const difficultyBinding = getPowDifficultyBinding(config);
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
  );
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return "";
  return bindingString;
};

export const encodePowTicket = (ticket) => {
  if (!Number.isFinite(ticket.issuedAt) || ticket.issuedAt <= 0) {
    throw new Error("invalid ticket issuedAt");
  }
  const raw = `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.issuedAt}.${ticket.mac}`;
  return base64UrlEncodeNoPad(encoder.encode(raw));
};

export const parsePowTicket = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = decoder.decode(bytes);
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  const v = Number.parseInt(parts[0], 10);
  const e = Number.parseInt(parts[1], 10);
  const L = Number.parseInt(parts[2], 10);
  const r = parts[3] || "";
  const cfgId = Number.parseInt(parts[4], 10);
  const issuedAt = Number.parseInt(parts[5], 10);
  const mac = parts[6] || "";
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  if (!isBase64Url(r, 1, B64_HASH_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v, e, L, r, cfgId, issuedAt, mac };
};

export const parsePowCommitCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 8) return null;
  if (parts[0] !== "v5") return null;
  const ticketB64 = parts[1] || "";
  const rootB64 = parts[2] || "";
  const pathHash = parts[3] || "";
  const captchaTag = parts[4] || "";
  const nonce = parts[5] || "";
  const exp = Number.parseInt(parts[6], 10);
  const mac = parts[7] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(rootB64, 1, B64_HASH_MAX_LEN)) return null;
  if (!(pathHash === "any" || isBase64Url(pathHash, 1, B64_HASH_MAX_LEN))) return null;
  if (!(captchaTag === "any" || isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN))) {
    return null;
  }
  if (!isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, rootB64, pathHash, captchaTag, nonce, exp, mac };
};

export const parseProofCookie = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 7 || parts[0] !== "v1") return null;
  const ticketB64 = parts[1] || "";
  const iat = Number.parseInt(parts[2], 10);
  const last = Number.parseInt(parts[3], 10);
  const n = Number.parseInt(parts[4], 10);
  const m = Number.parseInt(parts[5], 10);
  const mac = parts[6] || "";
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v: 1, ticketB64, iat, last, n, m, mac };
};

export const parseConsumeToken = (value) => {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 6 || parts[0] !== "v2") return null;
  const ticketB64 = parts[1] || "";
  const exp = Number.parseInt(parts[2], 10);
  const captchaTag = parts[3] || "";
  const m = Number.parseInt(parts[4], 10);
  const mac = parts[5] || "";
  if (exp <= 0) return null;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  if (!(captchaTag === "any" || isBase64Url(captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN))) {
    return null;
  }
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { ticketB64, exp, captchaTag, m, mac };
};

export const normalizePathHash = (pathHash, config) => {
  if (config.POW_BIND_PATH === false) return "any";
  return isBase64Url(pathHash, 1, B64_HASH_MAX_LEN) ? pathHash : "";
};

export const computePathHash = async (canonicalPath) =>
  base64UrlEncodeNoPad(await sha256Bytes(canonicalPath));

export const getPowBindingValuesWithPathHash = async (pathHash, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const bindIp = config.POW_BIND_IPRANGE !== false;
  const bindCountry = config.POW_BIND_COUNTRY === true;
  const bindAsn = config.POW_BIND_ASN === true;
  const bindTls = config.POW_BIND_TLS === true;
  const normalizedPathHash =
    bindPath && typeof pathHash === "string" && pathHash ? pathHash : bindPath ? "" : "any";
  if (bindPath && !normalizedPathHash) return null;
  const source = derived && typeof derived === "object" ? derived : null;
  const ipScope = bindIp && source && typeof source.ipScope === "string" ? source.ipScope : "";
  if (bindIp && !ipScope) return null;
  const country = bindCountry && source && typeof source.country === "string" ? source.country : "";
  if (bindCountry && !country) return null;
  const asn = bindAsn && source && typeof source.asn === "string" ? source.asn : "";
  if (bindAsn && !asn) return null;
  const tlsFingerprint =
    bindTls && source && typeof source.tlsFingerprint === "string" ? source.tlsFingerprint : "";
  if (bindTls && !tlsFingerprint) return null;
  return {
    pathHash: normalizedPathHash,
    ipScope: bindIp ? ipScope : "any",
    country: bindCountry ? country : "any",
    asn: bindAsn ? asn : "any",
    tlsFingerprint: bindTls ? tlsFingerprint : "any",
  };
};

export const getPowBindingValues = async (canonicalPath, config, derived) => {
  const bindPath = config.POW_BIND_PATH !== false;
  const pathHash = bindPath ? await computePathHash(canonicalPath) : "any";
  return getPowBindingValuesWithPathHash(pathHash, config, derived);
};

const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

export const resolveCaptchaRequirements = (config) => {
  const needTurn = config.turncheck === true;
  return { needTurn };
};

const validateTurnToken = (value) => {
  if (!value) return null;
  const token = String(value).trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

export const captchaTagV1 = async (turnToken) => {
  const turn = typeof turnToken === "string" ? turnToken : "";
  const material = `ctag|v1|t=${turn}`;
  return base64UrlEncodeNoPad((await sha256Bytes(material)).slice(0, 12));
};

export const parseCanonicalCaptchaTokens = (captchaToken, needTurn) => {
  if (!needTurn) {
    return { ok: true, malformed: false, tokens: { turnstile: "" } };
  }

  let envelope = null;
  if (typeof captchaToken === "string") {
    const raw = captchaToken.trim();
    if (!raw) return { ok: false, malformed: true, tokens: null };
    try {
      envelope = JSON.parse(raw);
    } catch {
      return { ok: false, malformed: true, tokens: null };
    }
  } else {
    envelope = captchaToken;
  }

  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return { ok: false, malformed: true, tokens: null };
  }

  const keys = Object.keys(envelope);
  for (const key of keys) {
    if (key !== "turnstile") {
      return { ok: false, malformed: true, tokens: null };
    }
    if (typeof envelope[key] !== "string") {
      return { ok: false, malformed: true, tokens: null };
    }
  }

  const turnRaw = typeof envelope.turnstile === "string" ? envelope.turnstile : "";
  const turnstile = needTurn ? validateTurnToken(turnRaw) : "";
  if (needTurn && !turnstile) {
    return { ok: false, malformed: true, tokens: null };
  }
  return { ok: true, malformed: false, tokens: { turnstile } };
};

const getClientIP = (request, fallback = "") =>
  request.headers.get("CF-Connecting-IP") || request.headers.get("cf-connecting-ip") || fallback;

export const verifyRequiredCaptchaForTicket = async (
  request,
  config,
  ticket,
  captchaToken,
  remoteIpFallback = "",
) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  if (!needTurn && !aggregatorPowAtomic) {
    return { ok: true, malformed: false, captchaTag: "any" };
  }
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  const turnToken = parsed.tokens.turnstile;
  const payload = {
    ticketMac: ticket.mac,
    remoteip: getClientIP(request, remoteIpFallback),
    token: {},
    providers: {},
    checks: {},
  };

  if (needTurn) {
    const turnSecret = config.TURNSTILE_SECRET;
    if (!turnSecret) return { ok: false, malformed: false, captchaTag: "" };
    payload.token.turnstile = turnToken;
    payload.providers.turnstile = { secret: turnSecret };
  }

  const verifyResult = await verifyViaSiteverifyAggregator({
    config,
    payload,
    powConsume: {
      cfgId: ticket.cfgId,
      ticketMac: ticket.mac,
      expireAt: ticket.e,
    },
  });
  if (!verifyResult || verifyResult.ok !== true) {
    return { ok: false, malformed: false, captchaTag: "" };
  }

  const captchaTag = needTurn ? await captchaTagV1(turnToken) : "any";
  return { ok: true, malformed: false, captchaTag };
};

export const deriveLocalCaptchaTag = async (config, captchaToken) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  if (!needTurn) return { ok: true, malformed: false, captchaTag: "any" };
  const parsed = parseCanonicalCaptchaTokens(captchaToken, needTurn);
  if (!parsed.ok) return { ok: false, malformed: parsed.malformed, captchaTag: "" };
  return {
    ok: true,
    malformed: false,
    captchaTag: await captchaTagV1(parsed.tokens.turnstile),
  };
};
