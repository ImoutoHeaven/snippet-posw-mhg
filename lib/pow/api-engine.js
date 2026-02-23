import { verifyEquihash } from "../equihash/verify.js";
import { isValidEquihashParams, normalizeEquihashParams } from "../equihash/params.js";
import { verifyViaSiteverifyAggregator } from "./siteverify-client.js";

const PROOF_COOKIE = "__Host-proof";
const POW_HINT_HEADER = "x-pow-h";

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const B64_HASH_MAX_LEN = 64;
const B64_TICKET_MAX_LEN = 256;
const TURN_TOKEN_MIN_LEN = 20;
const TURN_TOKEN_MAX_LEN = 4096;
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;
const DECIMAL_INT_RE = /^(0|[1-9][0-9]*)$/;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const hmacKeyCache = new Map();

const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) =>
  new Response(JSON.stringify(payload), { status, headers });

const denyApi = (hint) => {
  const headers = new Headers();
  headers.set(POW_HINT_HEADER, hint);
  return new Response(JSON.stringify({ ok: false, reason: hint }), {
    status: 403,
    headers,
  });
};

const denyStale = () => denyApi("stale");
const denyCheat = () => denyApi("cheat");

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

const isBase64Url = (value, minLen, maxLen) => {
  if (typeof value !== "string") return false;
  const len = value.length;
  if (len < minLen || len > maxLen) return false;
  return BASE64URL_RE.test(value);
};

const isExpired = (expire, nowSeconds) => expire > 0 && expire < nowSeconds;

const base64UrlEncodeNoPad = (bytes) => {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const base64UrlDecodeToBytes = (b64u) => {
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

const timingSafeEqual = (a, b) => {
  const aNorm = typeof a === "string" ? a : "";
  const bNorm = typeof b === "string" ? b : "";
  if (aNorm.length !== bNorm.length) return false;
  let diff = 0;
  for (let i = 0; i < aNorm.length; i += 1) {
    diff |= aNorm.charCodeAt(i) ^ bNorm.charCodeAt(i);
  }
  return diff === 0;
};

const parseStrictDecimalInt = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) return null;
    if (value < min || value > max) return null;
    return value;
  }
  if (typeof value !== "string") return null;
  if (!DECIMAL_INT_RE.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) return null;
  if (parsed < min || parsed > max) return null;
  return parsed;
};

const makeProofMac = async (powSecret, ticketB64, iat, last, n, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `O|${ticketB64}|${iat}|${last}|${n}|${m}`);

const makeConsumeMac = async (powSecret, ticketB64, exp, captchaTag, m) =>
  hmacSha256Base64UrlNoPad(powSecret, `U|${ticketB64}|${exp}|${captchaTag}|${m}`);

const setCookie = (headers, name, value, maxAge) => {
  const parts = [
    `${name}=${encodeURIComponent(String(value || ""))}`,
    "Path=/",
    "Secure",
    "SameSite=Lax",
    "HttpOnly",
  ];
  if (typeof maxAge === "number") {
    parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  }
  headers.append("Set-Cookie", parts.join("; "));
};

const decodePowEnvelope = (pow) => {
  if (!pow || typeof pow !== "object" || Array.isArray(pow)) return null;
  const nonceB64 = typeof pow.nonceB64 === "string" ? pow.nonceB64 : "";
  const proofB64 = typeof pow.proofB64 === "string" ? pow.proofB64 : "";
  if (!nonceB64 || !proofB64) return null;
  const nonce = base64UrlDecodeToBytes(nonceB64);
  const proof = base64UrlDecodeToBytes(proofB64);
  if (!(nonce instanceof Uint8Array) || !(proof instanceof Uint8Array)) return null;
  return { nonce, proof };
};

const makeEquihashSeed = (ticketB64, pathHash) =>
  encoder.encode(`${String(ticketB64 || "")}|${String(pathHash || "")}`);

const parseVerifyBody = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, reason: "bad_request" };
  }
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  if (!ticketB64 || !pathHash) {
    return { ok: false, reason: "bad_request" };
  }
  if (Object.prototype.hasOwnProperty.call(body, "pow")) {
    const pow = body.pow;
    if (!pow || typeof pow !== "object" || Array.isArray(pow)) {
      return { ok: false, reason: "bad_request" };
    }
    const nonceB64 = typeof pow.nonceB64 === "string" ? pow.nonceB64 : "";
    const proofB64 = typeof pow.proofB64 === "string" ? pow.proofB64 : "";
    if (!nonceB64 || !proofB64) {
      return { ok: false, reason: "bad_request" };
    }
  }
  return {
    ok: true,
    ticketB64,
    pathHash,
    pow: Object.prototype.hasOwnProperty.call(body, "pow") ? body.pow : null,
    captchaToken: body.captchaToken,
  };
};

const resolveVerifyMask = (config) => {
  const needPow = config.powcheck === true;
  const needTurn = config.turncheck === true;
  return (needPow ? 1 : 0) | (needTurn ? 2 : 0);
};

const resolveVerifyTtl = (ticket, config, nowSeconds) => {
  const proofTtl = Math.max(0, Math.floor(Number(config?.PROOF_TTL_SEC) || 0));
  const remaining = Math.floor(Number(ticket?.e) || 0) - nowSeconds;
  if (!Number.isFinite(remaining) || remaining <= 0 || proofTtl <= 0) return 0;
  return Math.max(1, Math.min(proofTtl, remaining));
};

const issueVerifyProofCookie = async ({ headers, powSecret, ticketB64, nowSeconds, ttl, mask }) => {
  const iat = nowSeconds;
  const last = nowSeconds;
  const n = 0;
  const mac = await makeProofMac(powSecret, ticketB64, iat, last, n, mask);
  const proofValue = `v1.${ticketB64}.${iat}.${last}.${n}.${mask}.${mac}`;
  setCookie(headers, PROOF_COOKIE, proofValue, ttl);
};

const getPowBindingValuesWithPathHash = async (pathHash, config, derived) => {
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

const validateTurnToken = (value) => {
  if (!value) return null;
  const token = String(value).trim();
  if (token.length < TURN_TOKEN_MIN_LEN || token.length > TURN_TOKEN_MAX_LEN) return null;
  if (CONTROL_CHAR_RE.test(token)) return null;
  return token;
};

const captchaTagV1 = async (turnToken) => {
  const turn = typeof turnToken === "string" ? turnToken : "";
  const material = `ctag|v1|t=${turn}`;
  return base64UrlEncodeNoPad((await sha256Bytes(material)).slice(0, 12));
};

const parseCanonicalCaptchaTokens = (captchaToken, needTurn) => {
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

const CAPTCHA_DENY_REASONS = new Set([
  "provider_failed",
  "captcha_failed",
  "captcha_rejected",
  "captcha_invalid",
  "turnstile_failed",
  "turnstile_rejected",
  "turnstile_invalid",
]);

const isCaptchaVerdict = (agg) => {
  if (!agg || typeof agg !== "object") return false;
  const reason = typeof agg.reason === "string" ? agg.reason : "";
  if (CAPTCHA_DENY_REASONS.has(reason)) return true;
  const providers = agg.providers && typeof agg.providers === "object" ? agg.providers : null;
  const turn = providers && providers.turnstile && typeof providers.turnstile === "object"
    ? providers.turnstile
    : null;
  if (!turn) return false;
  if (turn.ok === false) return true;
  const normalized = turn.normalized && typeof turn.normalized === "object" ? turn.normalized : null;
  return normalized ? normalized.success === false : false;
};

const makeTicketV4BindingString = ({
  ticket,
  host,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  eqN,
  eqK,
}) => {
  const ticketObj = ticket && typeof ticket === "object" ? ticket : null;
  if (!ticketObj) return "";
  const normalizedHost = typeof host === "string" ? host.toLowerCase() : "";
  return [
    ticketObj.v,
    ticketObj.e,
    ticketObj.cfgId,
    normalizedHost,
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint,
    eqN,
    eqK,
    ticketObj.issuedAt,
  ].join("|");
};

const encodePowTicketV4 = (ticket) => {
  if (!Number.isFinite(ticket?.issuedAt) || ticket.issuedAt <= 0) {
    throw new Error("invalid ticket issuedAt");
  }
  if (!Number.isFinite(ticket?.e) || ticket.e <= 0) {
    throw new Error("invalid ticket expireAt");
  }
  if (!Number.isInteger(ticket?.cfgId) || ticket.cfgId < 0) {
    throw new Error("invalid ticket cfgId");
  }
  if (!isBase64Url(ticket?.mac, 1, B64_HASH_MAX_LEN)) {
    throw new Error("invalid ticket mac");
  }
  const raw = `${ticket.v}.${ticket.e}.${ticket.cfgId}.${ticket.issuedAt}.${ticket.mac}`;
  return base64UrlEncodeNoPad(encoder.encode(raw));
};

const parsePowTicketV4 = (ticketB64) => {
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN)) return null;
  const bytes = base64UrlDecodeToBytes(ticketB64);
  if (!bytes) return null;
  const raw = decoder.decode(bytes);
  const parts = raw.split(".");
  if (parts.length !== 5) return null;
  const v = parseStrictDecimalInt(parts[0], 1);
  const e = parseStrictDecimalInt(parts[1], 1);
  const cfgId = parseStrictDecimalInt(parts[2], 0);
  const issuedAt = parseStrictDecimalInt(parts[3], 1);
  const mac = parts[4] || "";
  if (v === null || e === null || cfgId === null || issuedAt === null) return null;
  if (v !== 4) return null;
  if (!isBase64Url(mac, 1, B64_HASH_MAX_LEN)) return null;
  return { v, e, cfgId, issuedAt, mac };
};

const issuePowTicketV4 = async ({
  powSecret,
  powVersion,
  cfgId,
  issuedAt,
  expireAt,
  host,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  eqN,
  eqK,
}) => {
  const normalizedVersion = parseStrictDecimalInt(powVersion, 1) ?? 4;
  const normalizedCfgId = parseStrictDecimalInt(cfgId, 0);
  const normalizedIssuedAt = parseStrictDecimalInt(issuedAt, 1);
  const normalizedExpireAt = parseStrictDecimalInt(expireAt, 1);
  const normalizedEqN = parseStrictDecimalInt(eqN, 1);
  const normalizedEqK = parseStrictDecimalInt(eqK, 1);
  if (normalizedCfgId === null || normalizedIssuedAt === null || normalizedExpireAt === null) {
    throw new Error("invalid ticket numeric fields");
  }
  if (!isValidEquihashParams(normalizedEqN, normalizedEqK)) {
    throw new Error("invalid equihash params");
  }
  if (normalizedVersion !== 4) {
    throw new Error("invalid ticket version");
  }
  const ticket = {
    v: normalizedVersion,
    e: normalizedExpireAt,
    cfgId: normalizedCfgId,
    issuedAt: normalizedIssuedAt,
    mac: "",
  };
  const binding = makeTicketV4BindingString({
    ticket,
    host,
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint,
    eqN: normalizedEqN,
    eqK: normalizedEqK,
  });
  ticket.mac = await hmacSha256Base64UrlNoPad(powSecret, binding);
  return encodePowTicketV4(ticket);
};

const verifyPowTicketV4 = async ({
  ticketB64,
  powSecret,
  host,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  eqN,
  eqK,
  nowSeconds,
}) => {
  const normalizedNowSeconds = parseStrictDecimalInt(nowSeconds, 1);
  if (normalizedNowSeconds === null) {
    return { ok: false, reason: "invalid_now" };
  }
  const normalizedEqN = parseStrictDecimalInt(eqN, 1);
  const normalizedEqK = parseStrictDecimalInt(eqK, 1);
  if (!isValidEquihashParams(normalizedEqN, normalizedEqK)) {
    return { ok: false, reason: "invalid_eq_params" };
  }
  const ticket = parsePowTicketV4(ticketB64);
  if (!ticket) return { ok: false, reason: "bad_ticket" };
  if (isExpired(ticket.e, normalizedNowSeconds)) return { ok: false, reason: "expired" };
  const binding = makeTicketV4BindingString({
    ticket,
    host,
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint,
    eqN: normalizedEqN,
    eqK: normalizedEqK,
  });
  const expectedMac = await hmacSha256Base64UrlNoPad(powSecret, binding);
  if (!timingSafeEqual(expectedMac, ticket.mac)) return { ok: false, reason: "binding_mismatch" };
  return { ok: true, ticket };
};

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const handlePowVerify = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;

  const body = await readJsonBody(request);
  const parsed = parseVerifyBody(body);
  if (!parsed.ok) return denyApi(parsed.reason);

  const eq = normalizeEquihashParams(config?.POW_EQ_N, config?.POW_EQ_K);
  const eqN = eq.n;
  const eqK = eq.k;
  const ticket = parsePowTicketV4(parsed.ticketB64);
  if (!ticket) return denyStale();

  const bindingValues = await getPowBindingValuesWithPathHash(parsed.pathHash, config, derived);
  if (!bindingValues) return denyStale();
  if (ticket.cfgId !== cfgId) return denyStale();
  if (isExpired(ticket.e, nowSeconds)) return denyStale();

  const ticketBinding = makeTicketV4BindingString({
    ticket,
    host: url.hostname,
    pathHash: bindingValues.pathHash,
    ipScope: bindingValues.ipScope,
    country: bindingValues.country,
    asn: bindingValues.asn,
    tlsFingerprint: bindingValues.tlsFingerprint,
    eqN,
    eqK,
  });
  const expectedTicketMac = await hmacSha256Base64UrlNoPad(powSecret, ticketBinding);
  if (!timingSafeEqual(expectedTicketMac, ticket.mac)) return denyStale();

  const needPow = config.powcheck === true;
  if (needPow) {
    if (!parsed.pow) return denyApi("pow_required");
    const decodedPow = decodePowEnvelope(parsed.pow);
    if (!decodedPow) return denyApi("bad_request");
    const powOk = verifyEquihash({
      seed: makeEquihashSeed(parsed.ticketB64, bindingValues.pathHash),
      nonce: decodedPow.nonce,
      proof: decodedPow.proof,
      n: eqN,
      k: eqK,
    });
    if (!powOk) return denyCheat();
  }

  const needTurn = config.turncheck === true;
  const needAggregator = needTurn || config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  let captchaTag = "any";
  let turnToken = "";
  if (needTurn) {
    const parsedCaptcha = parseCanonicalCaptchaTokens(parsed.captchaToken, true);
    if (!parsedCaptcha.ok) return denyApi("captcha_required");
    turnToken = parsedCaptcha.tokens.turnstile;
    captchaTag = await captchaTagV1(turnToken);
  }

  if (needAggregator) {
    const payload = {
      ticketMac: ticket.mac,
      remoteip: request.headers.get("CF-Connecting-IP") || request.headers.get("cf-connecting-ip") || "",
      token: {},
      providers: {},
      checks: {},
    };
    if (needTurn) {
      const turnSecret = config.TURNSTILE_SECRET;
      if (!turnSecret) return denyStale();
      payload.token.turnstile = turnToken;
      payload.providers.turnstile = { secret: turnSecret };
    }
    const agg = await verifyViaSiteverifyAggregator({
      config,
      payload,
      powConsume: {
        cfgId: ticket.cfgId,
        ticketMac: ticket.mac,
        expireAt: ticket.e,
      },
    });
    if (!agg || agg.reason === "invalid_aggregator_response") {
      return denyStale();
    }
    if (needTurn && agg.ok !== true) {
      return isCaptchaVerdict(agg) ? denyApi("captcha_required") : denyStale();
    }
    if (!needTurn && agg.ok !== true) {
      return denyStale();
    }
  }

  const atomicGateEnabled =
    config.ATOMIC_CONSUME === true &&
    (needTurn || (needPow && config.AGGREGATOR_POW_ATOMIC_CONSUME === true));
  const proofMask = resolveVerifyMask(config);
  const ttl = resolveVerifyTtl(ticket, config, nowSeconds);
  if (!ttl) return denyStale();

  if (atomicGateEnabled) {
    const expireAt = nowSeconds + ttl;
    const consumeMac = await makeConsumeMac(powSecret, parsed.ticketB64, expireAt, captchaTag, proofMask);
    return J({
      ok: true,
      mode: "consume",
      consume: `v2.${parsed.ticketB64}.${expireAt}.${captchaTag}.${proofMask}.${consumeMac}`,
      expireAt,
    });
  }

  const headers = new Headers();
  await issueVerifyProofCookie({
    headers,
    powSecret,
    ticketB64: parsed.ticketB64,
    nowSeconds,
    ttl,
    mask: proofMask,
  });
  return J({ ok: true, mode: "proof", proofTtlSec: ttl }, 200, headers);
};

export const handlePowApi = async (request, url, nowSeconds, innerCtx) => {
  if (request.method !== "POST") {
    return S(405);
  }
  if (!innerCtx) return S(500);
  const { config } = innerCtx;
  const path = normalizePath(url.pathname);
  if (!path || !path.startsWith(`${config.POW_API_PREFIX}/`)) {
    return S(404);
  }
  const action = path.slice(config.POW_API_PREFIX.length);
  if (action === "/verify") {
    return handlePowVerify(request, url, nowSeconds, innerCtx);
  }
  return S(404);
};

export const __testTicketV4 = {
  issueTicket: issuePowTicketV4,
  verifyTicket: verifyPowTicketV4,
  parseTicket: parsePowTicketV4,
};
