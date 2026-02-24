import { stripPowInternalHeaders } from "./internal-headers.js";
import {
  base64UrlEncodeNoPad,
  encodePowTicket,
  getPowBindingValues,
  getPowDifficultyBinding,
  hmacSha256Base64UrlNoPad,
  isBase64Url,
  makeConsumeMac,
  makePowBindingString,
  makeProofMac,
  captchaTagV1,
  parseCanonicalCaptchaTokens,
  parseConsumeToken,
  parsePowTicket,
  parseProofCookie,
  resolveCaptchaRequirements,
  timingSafeEqual,
  verifyRequiredCaptchaForTicket,
  verifyTicketMac,
  B64_HASH_MAX_LEN,
  B64_TICKET_MAX_LEN,
  CAPTCHA_TAG_LEN,
} from "./api-protocol-shared.js";

const PROOF_COOKIE = "__Host-proof";
const encoder = new TextEncoder();

const isExpired = (expire, nowSeconds) => expire > 0 && expire < nowSeconds;

const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) =>
  new Response(JSON.stringify(payload), { status, headers });
const deny = () => S(403);
const POW_HINT_HEADER = "x-pow-h";
const denyApi = (hint) => {
  const headers = new Headers();
  headers.set(POW_HINT_HEADER, hint);
  return new Response(null, { status: 403, headers });
};

const withClearedCookie = (response, name) => {
  if (!name) return response;
  const headers = new Headers(response.headers);
  clearCookie(headers, name);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

const isNavigationRequest = (request) => {
  const mode = request.headers.get("Sec-Fetch-Mode") || "";
  if (mode === "navigate") return true;
  const accept = request.headers.get("Accept") || "";
  return accept.includes("text/html");
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

const getPowSteps = (config) => {
  const base = config.POW_DIFFICULTY_BASE;
  const coeff = config.POW_DIFFICULTY_COEFF;
  const minSteps = config.POW_MIN_STEPS;
  const maxSteps = config.POW_MAX_STEPS;
  const raw =
    Number.isFinite(base) && base > 0
      ? Number.isFinite(coeff) && coeff > 0
        ? base * coeff
        : base
      : 1;
  const steps = Math.max(1, Math.round(raw));
  const minVal = Number.isFinite(minSteps) ? Math.max(1, Math.floor(minSteps)) : 1;
  const maxVal = Number.isFinite(maxSteps) ? Math.max(minVal, Math.floor(maxSteps)) : minVal;
  return Math.min(maxVal, Math.max(minVal, steps));
};

const randomBase64Url = (byteLength) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
};

const clampInt = (value, lo, hi) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return lo;
  return Math.max(lo, Math.min(hi, Math.floor(num)));
};

const parseSegmentLenSpec = (raw) => {
  if (raw === null || raw === undefined) {
    return null;
  }
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


const normalizeInnerStrategy = (snapshot) => {
  if (!snapshot || typeof snapshot !== "object") return null;
  const nav = snapshot.nav && typeof snapshot.nav === "object" ? snapshot.nav : null;
  const bypassRaw = snapshot.bypass && typeof snapshot.bypass === "object" ? snapshot.bypass : null;
  const bindRaw = snapshot.bind && typeof snapshot.bind === "object" ? snapshot.bind : null;
  const atomicRaw = snapshot.atomic && typeof snapshot.atomic === "object" ? snapshot.atomic : null;
  if (!nav || !bypassRaw || !bindRaw || !atomicRaw) return null;
  if (typeof bypassRaw.bypass !== "boolean") return null;
  if (typeof bindRaw.ok !== "boolean") return null;
  if (typeof bindRaw.code !== "string") return null;
  if (typeof bindRaw.canonicalPath !== "string") return null;
  if (typeof atomicRaw.captchaToken !== "string") return null;
  if (typeof atomicRaw.ticketB64 !== "string") return null;
  if (typeof atomicRaw.consumeToken !== "string") return null;
  if (typeof atomicRaw.fromCookie !== "boolean") return null;
  if (typeof atomicRaw.cookieName !== "string") return null;
  return {
    nav,
    bypass: { bypass: bypassRaw.bypass },
    bind: {
      ok: bindRaw.ok,
      code: bindRaw.code,
      canonicalPath: bindRaw.canonicalPath,
    },
    atomic: {
      captchaToken: atomicRaw.captchaToken,
      ticketB64: atomicRaw.ticketB64,
      consumeToken: atomicRaw.consumeToken,
      fromCookie: atomicRaw.fromCookie,
      cookieName: atomicRaw.cookieName,
    },
  };
};

const loadConfigFromInner = (inner) => {
  if (!inner || typeof inner !== "object") return null;
  const baseConfig = inner.c && typeof inner.c === "object" ? inner.c : null;
  const strategy = normalizeInnerStrategy(inner.s);
  if (!baseConfig) return null;
  if (!strategy) return null;
  return {
    config: baseConfig,
    powSecret: baseConfig.POW_TOKEN,
    derived: inner.d,
    cfgId: inner.id,
    strategy,
  };
};

const validateTicket = (ticket, config, nowSeconds) => {
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return 0;
  if (isExpired(ticket.e, nowSeconds)) return 0;
  return powVersion;
};

const verifyConsumeToken = async (consumeToken, powSecret, nowSeconds, requiredMask) => {
  const parsed = parseConsumeToken(consumeToken);
  if (!parsed) return null;
  if (isExpired(parsed.exp, nowSeconds)) return null;
  if ((parsed.m & requiredMask) !== requiredMask) return null;
  const mac = await makeConsumeMac(
    powSecret,
    parsed.ticketB64,
    parsed.exp,
    parsed.captchaTag,
    parsed.m,
  );
  if (!timingSafeEqual(mac, parsed.mac)) return null;
  return parsed;
};

const loadAtomicTicket = async (
  ticketB64,
  url,
  canonicalPath,
  config,
  powSecret,
  derived,
  cfgId,
  nowSeconds,
) => {
  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return null;
  if (ticket.cfgId !== cfgId) return null;
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return null;
  if (!validateTicket(ticket, config, nowSeconds)) return null;
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return null;
  if (!(await verifyTicketMac(ticket, url, bindingValues, config, powSecret))) return null;
  return ticket;
};

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

const clearCookie = (headers, name) => {
  setCookie(headers, name, "deleted", 0);
};

const getProofTtl = (ticket, config, nowSeconds) => {
  const proofTtl = config.PROOF_TTL_SEC || 0;
  const remaining = ticket.e - nowSeconds;
  const ttl = Math.max(1, Math.min(proofTtl, remaining));
  return Number.isFinite(ttl) && ttl > 0 ? ttl : 0;
};

const issueProofCookie = async (
  headers,
  powSecret,
  url,
  ticket,
  bindingValues,
  config,
  powVersion,
  nowSeconds,
  ttl,
  m,
) => {
  const exp = nowSeconds + ttl;
  const proofTicket = {
    v: powVersion,
    e: exp,
    L: ticket.L,
    r: randomBase64Url(16),
    cfgId: ticket.cfgId,
    issuedAt: ticket.issuedAt,
    mac: "",
  };
  const difficultyBinding = getPowDifficultyBinding(config);
  const proofBindingString = makePowBindingString(
    proofTicket,
    url.hostname,
    bindingValues.pathHash,
    bindingValues.ipScope,
    bindingValues.country,
    bindingValues.asn,
    bindingValues.tlsFingerprint,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
  );
  proofTicket.mac = await hmacSha256Base64UrlNoPad(powSecret, proofBindingString);
  const proofTicketB64 = encodePowTicket(proofTicket);
  const iat = nowSeconds;
  const last = nowSeconds;
  const n = 0;
  const proofMac = await makeProofMac(powSecret, proofTicketB64, iat, last, n, m);
  const proofValue = `v1.${proofTicketB64}.${iat}.${last}.${n}.${m}.${proofMac}`;
  setCookie(headers, PROOF_COOKIE, proofValue, ttl);
};

const verifyProofCookie = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requiredMask,
) => {
  const cookies = parseCookieHeader(request.headers.get("Cookie"));
  const raw = cookies.get(PROOF_COOKIE) || "";
  const proof = parseProofCookie(raw);
  if (!proof) return null;
  const ticket = parsePowTicket(proof.ticketB64);
  if (!ticket) return null;
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return null;
  if (!Number.isFinite(ticket.e) || ticket.e <= nowSeconds) return null;
  if (!Number.isFinite(ticket.L) || ticket.L <= 0) return null;
  if (ticket.cfgId !== cfgId) return null;
  if (proof.last > ticket.e) return null;
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return null;
  if (!(await verifyTicketMac(ticket, url, bindingValues, config, powSecret))) return null;
  const expectedProofMac = await makeProofMac(
    powSecret,
    proof.ticketB64,
    proof.iat,
    proof.last,
    proof.n,
    proof.m,
  );
  if (!timingSafeEqual(expectedProofMac, proof.mac)) return null;
  if ((proof.m & requiredMask) !== requiredMask) return null;
  return { proof, ticket, bindingValues };
};

const maybeRenewProof = async (
  request,
  url,
  nowSeconds,
  config,
  powSecret,
  cfgId,
  meta,
  response,
) => {
  if (!meta || !meta.proof || !meta.bindingValues || !response) return response;
  if (config.PROOF_RENEW_ENABLE !== true) return response;
  if (!isNavigationRequest(request)) return response;

  const proof = meta.proof;
  const renewMax = Math.max(0, Math.floor(config.PROOF_RENEW_MAX));
  if (!renewMax || proof.n >= renewMax) return response;

  const ttl = Math.max(1, Math.floor(config.PROOF_TTL_SEC));
  const window = Math.max(0, Math.floor(config.PROOF_RENEW_WINDOW_SEC));
  const minSinceLast = Math.max(0, Math.floor(config.PROOF_RENEW_MIN_SEC));
  const curExp = meta.ticket && Number.isFinite(meta.ticket.e) ? meta.ticket.e : 0;
  if (!Number.isFinite(curExp) || curExp <= 0) return response;
  if (curExp - nowSeconds > window) return response;
  if (nowSeconds - proof.last < minSinceLast) return response;

  const hardLimit = proof.iat + ttl * (renewMax + 1);
  if (!Number.isFinite(hardLimit) || hardLimit <= nowSeconds) return response;

  const newExp = Math.min(nowSeconds + ttl, hardLimit);
  if (!Number.isFinite(newExp) || newExp <= nowSeconds || newExp <= curExp) return response;

  const ticket = {
    v: meta.ticket.v,
    e: newExp,
    L: meta.ticket.L,
    r: randomBase64Url(16),
    cfgId,
    issuedAt: meta.ticket.issuedAt,
    mac: "",
  };
  const b = meta.bindingValues;
  const difficultyBinding = getPowDifficultyBinding(config);
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    b.pathHash,
    b.ipScope,
    b.country,
    b.asn,
    b.tlsFingerprint,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
  );
  ticket.mac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  const ticketB64 = encodePowTicket(ticket);

  const nextN = proof.n + 1;
  const mac = await makeProofMac(powSecret, ticketB64, proof.iat, nowSeconds, nextN, proof.m);
  const proofValue = `v1.${ticketB64}.${proof.iat}.${nowSeconds}.${nextN}.${proof.m}.${mac}`;

  const headers = new Headers(response.headers);
  setCookie(headers, PROOF_COOKIE, proofValue, newExp - nowSeconds);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

const buildPowChallengeHtml = ({
  bindingStringB64,
  steps,
  ticketB64,
  pathHash,
  hashcashBits,
  segmentLen,
  pageBytes,
  mixRounds,
  reloadUrlB64,
  apiPrefixB64,
  esmUrlB64,
  captchaCfgB64,
  glueUrl,
  atomicCfg,
}) => __HTML_TEMPLATE__
  .replace('__B__', bindingStringB64)
  .replace('__S__', String(steps))
  .replace('__T__', ticketB64)
  .replace('__P__', pathHash)
  .replace('__H__', String(hashcashBits))
  .replace('__L__', String(segmentLen))
  .replace('__Y__', String(pageBytes))
  .replace('__Z__', String(mixRounds))
  .replace('__G__', glueUrl)
  .replace('__R__', reloadUrlB64)
  .replace('__A__', apiPrefixB64)
  .replace('__E__', esmUrlB64)
  .replace('__K__', captchaCfgB64)
  .replace('__C__', atomicCfg);

const respondPowChallengeHtml = async (
  request,
  url,
  canonicalPath,
  nowSeconds,
  config,
  powSecret,
  derived,
  cfgId,
  requirements,
) => {
  const ticketTtl = config.POW_TICKET_TTL_SEC || 0;
  const exp = nowSeconds + Math.max(1, ticketTtl);
  const needPow = requirements && requirements.needPow === true;
  const needTurn = requirements && requirements.needTurn === true;
  const steps = needPow ? getPowSteps(config) : 1;
  const glueSteps = needPow ? steps : 0;
  const hashcashBits = needPow ? Math.max(0, Math.floor(config.POW_HASHCASH_BITS)) : 0;
  const segSpec = needPow
    ? parseSegmentLenSpec(config.POW_SEGMENT_LEN)
    : { mode: "fixed", fixed: 2 };
  if (needPow && !segSpec) return S(500);
  const bindingValues = await getPowBindingValues(canonicalPath, config, derived);
  if (!bindingValues) return deny();
  const { pathHash, ipScope, country, asn, tlsFingerprint } = bindingValues;
  const powVersion = config.POW_VERSION;
  const ticket = {
    v: powVersion,
    e: exp,
    L: steps,
    r: randomBase64Url(16),
    cfgId,
    issuedAt: nowSeconds,
    mac: "",
  };
  const difficultyBinding = getPowDifficultyBinding(config);
  const bindingString = makePowBindingString(
    ticket,
    url.hostname,
    pathHash,
    ipScope,
    country,
    asn,
    tlsFingerprint,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
  );
  ticket.mac = await hmacSha256Base64UrlNoPad(powSecret, bindingString);
  const ticketB64 = encodePowTicket(ticket);
  const bindingStringB64 = base64UrlEncodeNoPad(encoder.encode(bindingString));
  const reloadUrlB64 = base64UrlEncodeNoPad(encoder.encode(url.toString()));
  const apiPrefixB64 = base64UrlEncodeNoPad(encoder.encode(config.POW_API_PREFIX));
  const esmUrlB64 = needPow ? base64UrlEncodeNoPad(encoder.encode(config.POW_ESM_URL)) : "";
  const captchaCfg = {};
  if (needTurn) {
    captchaCfg.turnstile = { sitekey: config.TURNSTILE_SITEKEY };
  }
  const captchaCfgB64 = base64UrlEncodeNoPad(encoder.encode(JSON.stringify(captchaCfg)));
  const glueUrl = config.POW_GLUE_URL;
  const atomicConsume = config.ATOMIC_CONSUME === true ? "1" : "0";
  const atomicTurnQuery = config.ATOMIC_TURN_QUERY.trim();
  const atomicTicketQuery = config.ATOMIC_TICKET_QUERY.trim();
  const atomicConsumeQuery = config.ATOMIC_CONSUME_QUERY.trim();
  const atomicTurnHeader = config.ATOMIC_TURN_HEADER.trim();
  const atomicTicketHeader = config.ATOMIC_TICKET_HEADER.trim();
  const atomicConsumeHeader = config.ATOMIC_CONSUME_HEADER.trim();
  const atomicCookieName = config.ATOMIC_COOKIE_NAME.trim();
  const atomicCfg = `${atomicConsume}|${atomicTurnQuery}|${atomicTicketQuery}|${atomicConsumeQuery}|${atomicTurnHeader}|${atomicTicketHeader}|${atomicConsumeHeader}|${atomicCookieName}`;
  const segmentLenFixed = Math.max(
    2,
    Math.min(steps, Math.floor(segSpec.mode === "fixed" ? segSpec.fixed : segSpec.min)),
  );
  const html = buildPowChallengeHtml({
    bindingStringB64,
    steps: glueSteps,
    ticketB64,
    pathHash,
    hashcashBits,
    segmentLen: segmentLenFixed,
    pageBytes: difficultyBinding.pageBytes,
    mixRounds: difficultyBinding.mixRounds,
    glueUrl,
    reloadUrlB64,
    apiPrefixB64,
    esmUrlB64,
    captchaCfgB64,
    atomicCfg,
  });
  const headers = new Headers();
  headers.set("Content-Type", "text/html");
  headers.set("Cache-Control", "no-store");
  headers.set("Content-Security-Policy", "frame-ancestors 'none'");
  headers.set("X-Frame-Options", "DENY");
  return new Response(html, { status: 200, headers });
};

export const handleBusinessGate = async ({ request, url, nowSeconds, inner, forward }) => {
  if (typeof forward !== "function") return S(500);

  const innerCtx = loadConfigFromInner(inner);
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId, strategy } = innerCtx;

  const needPow = config.powcheck === true;
  const { needTurn } = resolveCaptchaRequirements(config);
  if (!needPow && !needTurn) {
    return forward(stripPowInternalHeaders(request));
  }
  if (strategy.bypass.bypass) {
    return forward(stripPowInternalHeaders(request));
  }

  const bindRes = strategy.bind;
  if (!bindRes.ok) {
    if (bindRes.code === "missing") return S(400);
    if (bindRes.code === "invalid") return S(400);
    return S(500);
  }

  if (!powSecret) return S(500);
  if (needPow && !config.POW_ESM_URL) return S(500);
  if (needTurn) {
    const sitekey = config.TURNSTILE_SITEKEY;
    const secret = config.TURNSTILE_SECRET;
    if (!sitekey || !secret) return S(500);
  }

  const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  const atomicGateEnabled = config.ATOMIC_CONSUME === true && (needTurn || (needPow && aggregatorPowAtomic));
  const allowProof = !atomicGateEnabled;
  const proofMeta = allowProof
    ? await verifyProofCookie(
        request,
        url,
        bindRes.canonicalPath,
        nowSeconds,
        config,
        powSecret,
        derived,
        cfgId,
        requiredMask,
      )
    : null;

  if (proofMeta) {
    let response = await forward(stripPowInternalHeaders(request));
    response = await maybeRenewProof(
      request,
      url,
      nowSeconds,
      config,
      powSecret,
      cfgId,
      proofMeta,
      response,
    );
    return response;
  }

  if (atomicGateEnabled) {
    const baseRequest = request;
    const baseUrl = url;
    const atomic = strategy.atomic;
    const fail = async (resp, allowChallenge = true) => {
      if (allowChallenge && isNavigationRequest(request)) {
        const challenge = await respondPowChallengeHtml(
          baseRequest,
          baseUrl,
          bindRes.canonicalPath,
          nowSeconds,
          config,
          powSecret,
          derived,
          cfgId,
          { needPow, needTurn },
        );
        return atomic.fromCookie ? withClearedCookie(challenge, atomic.cookieName) : challenge;
      }
      return atomic.fromCookie ? withClearedCookie(resp, atomic.cookieName) : resp;
    };
    const hasAtomicInput =
      atomic.captchaToken ||
      (!needTurn && needPow && aggregatorPowAtomic && atomic.consumeToken);
    if (hasAtomicInput) {
      const parsedAtomicCaptcha = parseCanonicalCaptchaTokens(atomic.captchaToken, needTurn);
      if (!parsedAtomicCaptcha.ok) {
        return fail(parsedAtomicCaptcha.malformed ? S(400) : deny(), false);
      }
      if (needPow) {
        const consume = await verifyConsumeToken(
          atomic.consumeToken,
          powSecret,
          nowSeconds,
          requiredMask,
        );
        if (!consume) {
          const parsedConsume = parseConsumeToken(atomic.consumeToken);
          if (parsedConsume && isExpired(parsedConsume.exp, nowSeconds)) {
            return fail(denyApi("stale"));
          }
          return fail(deny());
        }
        const ticket = await loadAtomicTicket(
          consume.ticketB64,
          baseUrl,
          bindRes.canonicalPath,
          config,
          powSecret,
          derived,
          cfgId,
          nowSeconds,
        );
        if (!ticket) return fail(deny());
        const bindingValues = await getPowBindingValues(bindRes.canonicalPath, config, derived);
        if (!bindingValues) return fail(deny());
        const atomicBinding = await verifyTicketMac(ticket, baseUrl, bindingValues, config, powSecret);
        if (!atomicBinding) return fail(deny());
        const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
          baseRequest,
          config,
          ticket,
          atomic.captchaToken,
          "0.0.0.0",
        );
        if (!verifiedCaptcha.ok || verifiedCaptcha.captchaTag !== consume.captchaTag) {
          if (!verifiedCaptcha.ok && verifiedCaptcha.malformed) {
            return fail(S(400), false);
          }
          return fail(deny());
        }
        const response = await forward(stripPowInternalHeaders(baseRequest));
        return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
      }
      const ticket = await loadAtomicTicket(
        atomic.ticketB64,
        baseUrl,
        bindRes.canonicalPath,
        config,
        powSecret,
        derived,
        cfgId,
        nowSeconds,
      );
      if (!ticket) return fail(deny());
      const bindingValues = await getPowBindingValues(bindRes.canonicalPath, config, derived);
      if (!bindingValues) return fail(deny());
      const atomicBinding = await verifyTicketMac(ticket, baseUrl, bindingValues, config, powSecret);
      if (!atomicBinding) return fail(deny());
      const verifiedCaptcha = await verifyRequiredCaptchaForTicket(
        baseRequest,
        config,
        ticket,
        atomic.captchaToken,
        "0.0.0.0",
      );
      if (!verifiedCaptcha.ok) {
        if (verifiedCaptcha.malformed) return fail(S(400), false);
        return fail(deny());
      }
      const response = await forward(stripPowInternalHeaders(baseRequest));
      return atomic.fromCookie ? withClearedCookie(response, atomic.cookieName) : response;
    }
  }

  if (!isNavigationRequest(request)) {
    const code = needPow ? "pow_required" : "captcha_required";
    return J({ code }, 403);
  }

  return respondPowChallengeHtml(
    request,
    url,
    bindRes.canonicalPath,
    nowSeconds,
    config,
    powSecret,
    derived,
    cfgId,
    { needPow, needTurn },
  );
};
