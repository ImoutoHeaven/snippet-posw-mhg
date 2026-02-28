import { verifyOpenBatchVector } from "../mhg/verify.js";
import {
  B64_HASH_MAX_LEN,
  B64_TICKET_MAX_LEN,
  CAPTCHA_TAG_LEN,
  NONCE_MAX_LEN,
  NONCE_MIN_LEN,
  TOKEN_MAX_LEN,
  TOKEN_MIN_LEN,
  base64UrlDecodeToBytes,
  base64UrlEncodeNoPad,
  captchaTagV1,
  computePowSampleExtraCount,
  computeSegLensForIndices,
  derivePowSeedBytes16,
  deriveSegLenSeed16,
  deriveLocalCaptchaTag,
  encodePowTicket,
  getPowBindingValuesWithPathHash,
  getPowDifficultyBinding,
  hmacSha256,
  hmacSha256Base64UrlNoPad,
  isBase64Url,
  makeXoshiro128ss,
  makeConsumeMac,
  makePowBindingString,
  makePowCommitMac,
  makePowStateToken,
  makeProofMac,
  normalizePathHash,
  parseSegmentLenSpec,
  parsePowCommitCookie,
  parsePowTicket,
  resolveCaptchaRequirements,
  sampleIndicesDeterministicV2,
  sha256Bytes,
  timingSafeEqual,
  verifyRequiredCaptchaForTicket,
  verifyTicketMac,
} from "./api-protocol-shared.js";

const PROOF_COOKIE = "__Host-proof";

const encoder = new TextEncoder();

const HASHCASH_PREFIX = encoder.encode("hashcash|v4|");

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

const isExpired = (expire, nowSeconds) => expire > 0 && expire < nowSeconds;


const concatBytes = (...chunks) => {
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

const leadingZeroBits = (bytes) => {
  let count = 0;
  for (const b of bytes || []) {
    if (b === 0) {
      count += 8;
      continue;
    }
    for (let i = 7; i >= 0; i -= 1) {
      if (b & (1 << i)) {
        return count + (7 - i);
      }
    }
  }
  return count;
};

const randomBase64Url = (byteLength) => {
  const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 16;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64UrlEncodeNoPad(bytes);
};

const derivePowSid = async (powSecret, cfgId, commitMac) => {
  const bytes = await hmacSha256(powSecret, `I|${cfgId}|${commitMac}`);
  return base64UrlEncodeNoPad(bytes.slice(0, 12));
};

const getBatchMax = (config) => Math.max(1, Math.min(256, Math.floor(config.POW_OPEN_BATCH)));

const normalizeNumberClamp = (value, fallback, min, max) => {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
};

const getPowMaxGenTimeSec = (config) =>
  Math.floor(normalizeNumberClamp(config?.POW_MAX_GEN_TIME_SEC, 300, 1, 1000000000));

const isPowAbsoluteLifecycleExpired = (ticket, config, nowSeconds) => {
  const issuedAt = Number(ticket?.issuedAt);
  const maxGen = getPowMaxGenTimeSec(config);
  const commitTtl = Math.max(1, Math.floor(Number(config?.POW_COMMIT_TTL_SEC) || 0));
  const absoluteDeadline = issuedAt + maxGen + commitTtl;
  return !Number.isFinite(issuedAt) || issuedAt <= 0 || nowSeconds > absoluteDeadline;
};


const hashcashRootLast = async (rootBytes, lastBytes) =>
  sha256Bytes(concatBytes(HASHCASH_PREFIX, rootBytes, lastBytes));

const deriveMhgGraphSeed16 = async (ticketB64, nonce) =>
  (await sha256Bytes(`mhg|graph|v4|${ticketB64}|${nonce}`)).slice(0, 16);

const deriveMhgNonce16 = async (nonce) => {
  const raw = base64UrlDecodeToBytes(nonce);
  if (!raw) return null;
  if (raw.length >= 16) return raw.slice(0, 16);
  const digest = await sha256Bytes(raw);
  return digest.slice(0, 16);
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

const ticketMatchesInner = (ticket, cfgId) =>
  Boolean(ticket && Number.isInteger(cfgId) && ticket.cfgId === cfgId);

const loadCommitFromToken = (commitToken) => {
  const commit = parsePowCommitCookie(commitToken);
  if (!commit) return null;
  const ticket = parsePowTicket(commit.ticketB64);
  if (!ticket) return null;
  return { commit, ticket };
};

const validateTicket = (ticket, config, nowSeconds) => {
  const powVersion = config.POW_VERSION;
  if (ticket.v !== powVersion) return 0;
  if (isExpired(ticket.e, nowSeconds)) return 0;
  return powVersion;
};

const verifyCommit = async (commit, ticket, config, powSecret, nowSeconds) => {
  const { needTurn } = resolveCaptchaRequirements(config);
  if (needTurn && !isBase64Url(commit.captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)) {
    return 0;
  }
  if (isExpired(commit.exp, nowSeconds)) return 0;
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return 0;
  const commitMac = await makePowCommitMac(
    powSecret,
    commit.ticketB64,
    commit.rootB64,
    commit.pathHash,
    commit.captchaTag,
    commit.nonce,
    commit.exp,
  );
  if (!timingSafeEqual(commitMac, commit.mac)) return 0;
  return powVersion;
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

const buildPowSample = async (config, powSecret, ticket, commitMac, sid) => {
  const sampleExtra = computePowSampleExtraCount(ticket.L, config.POW_SAMPLE_RATE);
  const hashcashBits = Math.max(0, Math.floor(config.POW_HASHCASH_BITS));
  const segSpec = parseSegmentLenSpec(config.POW_SEGMENT_LEN);
  if (!segSpec) return null;
  const seed16 = await derivePowSeedBytes16(powSecret, ticket.cfgId, commitMac, sid);
  const rng = makeXoshiro128ss(seed16);
  const indices = sampleIndicesDeterministicV2({
    maxIndex: ticket.L,
    extraCount: sampleExtra,
    forceEdge1: true,
    forceEdgeLast: true,
    rng,
  });
  if (!indices.length) return null;
  const segSeed16 = await deriveSegLenSeed16(powSecret, ticket.cfgId, commitMac, sid);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indices, segSpec, rngSeg);
  return { indices, segLensAll, hashcashBits };
};

const buildPowBatchResponse = async (
  indices,
  segLensAll,
  ticket,
  commit,
  powSecret,
  sid,
  cursor,
  batchLen,
  pageBytes,
  mixRounds,
) => {
  const batch = indices.slice(cursor, cursor + batchLen);
  if (!batch.length) return null;
  const segBatch = segLensAll.slice(cursor, cursor + batchLen);
  const token = await makePowStateToken(powSecret, ticket.cfgId, sid, commit.mac, cursor, batchLen);
  return {
    done: false,
    sid,
    cursor,
    indices: batch,
    segs: segBatch,
    pageBytes,
    mixRounds,
    token,
  };
};

const readJsonBody = async (request) => {
  try {
    return await request.json();
  } catch {
    return null;
  }
};

const handlePowOpen = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") {
    return S(400);
  }
  const commitToken = typeof body.commitToken === "string" ? body.commitToken : "";
  if (!commitToken) return S(400);
  const commitCtx = loadCommitFromToken(commitToken);
  if (!commitCtx) return deny();
  const { commit, ticket } = commitCtx;
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const { needTurn } = resolveCaptchaRequirements(config);
  const requiredMask = 1 | (needTurn ? 2 : 0);
  if (isExpired(ticket.e, nowSeconds) || isExpired(commit.exp, nowSeconds)) return denyStale();
  const powVersion = await verifyCommit(commit, ticket, config, powSecret, nowSeconds);
  if (!powVersion) return denyCheat();
  if (isPowAbsoluteLifecycleExpired(ticket, config, nowSeconds)) return denyStale();
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, config, powSecret))) return deny();
  const cursor = Number.parseInt(body.cursor, 10);
  const sid = typeof body.sid === "string" ? body.sid : "";
  const stateToken = typeof body.token === "string" ? body.token : "";
  const captchaToken = body.captchaToken;
  const opens = Array.isArray(body.opens) ? body.opens : null;
  if (!sid || !stateToken || !opens || !Number.isFinite(cursor) || cursor < 0) {
    return S(400);
  }
  if (!isBase64Url(stateToken, TOKEN_MIN_LEN, TOKEN_MAX_LEN)) {
    return S(400);
  }
  const batchMax = getBatchMax(config);
  if (batchMax <= 0) return S(500);
  const sidExpected = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  if (!timingSafeEqual(sid, sidExpected)) return denyCheat();
  const expectedToken = await makePowStateToken(
    powSecret,
    ticket.cfgId,
    sidExpected,
    commit.mac,
    cursor,
    batchMax,
  );
  if (!timingSafeEqual(expectedToken, stateToken)) return denyCheat();
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sidExpected);
  if (!sample) return denyCheat();
  const { indices, segLensAll, hashcashBits } = sample;
  const difficultyBinding = getPowDifficultyBinding(config);
  if (hashcashBits > 0 && !indices.includes(ticket.L)) return denyCheat();
  const expectedBatch = indices.slice(cursor, cursor + batchMax);
  if (!expectedBatch.length) return denyCheat();
  const segBatch = segLensAll.slice(cursor, cursor + batchMax);
  const batchSize = opens.length;
  if (batchSize !== expectedBatch.length) {
    return denyCheat();
  }
  for (let i = 0; i < batchSize; i += 1) {
    const open = opens[i];
    if (!open || typeof open !== "object" || Array.isArray(open)) return S(400);
    const idx = Number.parseInt(open.i, 10);
    let seg = NaN;
    if (typeof open.seg === "number" && Number.isInteger(open.seg)) {
      seg = open.seg;
    } else if (typeof open.seg === "string" && /^-?\d+$/u.test(open.seg.trim())) {
      seg = Number.parseInt(open.seg, 10);
    } else {
      return S(400);
    }
    if (!Number.isFinite(idx) || idx < 1 || idx > ticket.L) {
      return S(400);
    }
    if (!Number.isFinite(seg)) {
      return S(400);
    }
    const expectedIdx = expectedBatch[i];
    if (idx !== expectedIdx) return denyCheat();
    const segLen = segBatch[i];
    if (!Number.isFinite(segLen) || segLen <= 0) {
      return denyCheat();
    }
    if (seg !== segLen) return denyCheat();
  }

  const rootBytes = base64UrlDecodeToBytes(commit.rootB64);
  if (!rootBytes || rootBytes.length !== 32) return denyCheat();
  const graphSeed = await deriveMhgGraphSeed16(commit.ticketB64, commit.nonce);
  const nonce16 = await deriveMhgNonce16(commit.nonce);
  if (!nonce16) return denyCheat();
  const vectorVerify = await verifyOpenBatchVector({
    root: rootBytes,
    leafCount: ticket.L + 1,
    graphSeed,
    nonce: nonce16,
    pageBytes: difficultyBinding.pageBytes,
    mixRounds: difficultyBinding.mixRounds,
    opens,
  });
  if (!vectorVerify.ok) {
    if (vectorVerify.reason === "bad_vector" || vectorVerify.reason === "bad_open") {
      return S(400);
    }
    return denyCheat();
  }
  if (hashcashBits > 0 && expectedBatch.includes(ticket.L)) {
    const finalOpen = opens.find((entry) => Number.parseInt(entry && entry.i, 10) === ticket.L);
    if (!finalOpen || !finalOpen.nodes || typeof finalOpen.nodes !== "object") return denyCheat();
    const finalNode = finalOpen.nodes[String(ticket.L)] ?? finalOpen.nodes[ticket.L];
    if (!finalNode || typeof finalNode.pageB64 !== "string") return denyCheat();
    const finalPage = base64UrlDecodeToBytes(finalNode.pageB64);
    if (!(finalPage instanceof Uint8Array)) return denyCheat();
    const digest = await hashcashRootLast(rootBytes, finalPage);
    if (leadingZeroBits(digest) < hashcashBits) return denyCheat();
  }

  const nextCursor = cursor + expectedBatch.length;
  if (nextCursor < indices.length) {
    const nextResp = await buildPowBatchResponse(
      indices,
      segLensAll,
      ticket,
      commit,
      powSecret,
      sidExpected,
      nextCursor,
      batchMax,
      difficultyBinding.pageBytes,
      difficultyBinding.mixRounds,
    );
    if (!nextResp) return denyCheat();
    return J(nextResp);
  }
  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return deny();

  const atomicConsumeEnabled =
    config.ATOMIC_CONSUME === true && (needTurn || config.AGGREGATOR_POW_ATOMIC_CONSUME === true);
  if (atomicConsumeEnabled) {
    const localCaptcha = await deriveLocalCaptchaTag(config, captchaToken);
    if (!localCaptcha.ok) return localCaptcha.malformed ? S(400) : denyStale();
    if (localCaptcha.captchaTag !== commit.captchaTag) return denyCheat();
    const exp = nowSeconds + ttl;
    const mac = await makeConsumeMac(
      powSecret,
      commit.ticketB64,
      exp,
      localCaptcha.captchaTag,
      requiredMask,
    );
    const headers = new Headers();
    return J(
      {
        done: true,
        consume: `v2.${commit.ticketB64}.${exp}.${localCaptcha.captchaTag}.${requiredMask}.${mac}`,
      },
      200,
      headers,
    );
  }

  const aggregatorPowAtomic = config.AGGREGATOR_POW_ATOMIC_CONSUME === true;
  if (needTurn || aggregatorPowAtomic) {
    const verifiedCaptcha = await verifyRequiredCaptchaForTicket(request, config, ticket, captchaToken);
    if (!verifiedCaptcha.ok) return verifiedCaptcha.malformed ? S(400) : denyStale();
    if (verifiedCaptcha.captchaTag !== commit.captchaTag) return denyCheat();
  }

  const headers = new Headers();
  await issueProofCookie(
    headers,
    powSecret,
    url,
    ticket,
    bindingValues,
    config,
    powVersion,
    nowSeconds,
    ttl,
    requiredMask,
  );
  return J({ done: true }, 200, headers);
};

export const handlePowApi = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config } = innerCtx;
  const path = normalizePath(url.pathname);
  if (!path || !path.startsWith(`${config.POW_API_PREFIX}/`)) {
    return S(404);
  }
  const action = path.slice(config.POW_API_PREFIX.length);
  if (action === "/open") {
    if (request.method !== "POST") return S(405);
    return handlePowOpen(request, url, nowSeconds, innerCtx);
  }
  return S(404);
};
