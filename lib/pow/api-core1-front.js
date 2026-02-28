import {
  B64_HASH_MAX_LEN,
  B64_TICKET_MAX_LEN,
  CAPTCHA_TAG_LEN,
  NONCE_MAX_LEN,
  NONCE_MIN_LEN,
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
  makePowBindingString,
  makePowCommitMac,
  makePowStateToken,
  makeProofMac,
  normalizePathHash,
  parseSegmentLenSpec,
  parseCanonicalCaptchaTokens,
  parsePowCommitCookie,
  parsePowTicket,
  resolveCaptchaRequirements,
  sampleIndicesDeterministicV2,
  timingSafeEqual,
  verifyRequiredCaptchaForTicket,
  verifyTicketMac,
} from "./api-protocol-shared.js";

const PROOF_COOKIE = "__Host-proof";

const S = (status) => new Response(null, { status });
const J = (payload, status = 200, headers) => new Response(JSON.stringify(payload), { status, headers });
const deny = () => S(403);
const denyApi = (hint) => {
  const headers = new Headers();
  headers.set("x-pow-h", hint);
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

const setCookie = (headers, name, value, maxAge) => {
  const parts = [
    `${name}=${encodeURIComponent(String(value || ""))}`,
    "Path=/",
    "Secure",
    "SameSite=Lax",
    "HttpOnly",
  ];
  if (typeof maxAge === "number") parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  headers.append("Set-Cookie", parts.join("; "));
};

const ticketMatchesInner = (ticket, cfgId) => Boolean(ticket && Number.isInteger(cfgId) && ticket.cfgId === cfgId);

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
  if (needTurn && !isBase64Url(commit.captchaTag, CAPTCHA_TAG_LEN, CAPTCHA_TAG_LEN)) return 0;
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
  const extraCount = computePowSampleExtraCount(ticket.L, config.POW_SAMPLE_RATE);
  const segSpec = parseSegmentLenSpec(config.POW_SEGMENT_LEN);
  if (!segSpec) return null;
  const seed16 = await derivePowSeedBytes16(powSecret, ticket.cfgId, commitMac, sid);
  const rng = makeXoshiro128ss(seed16);
  const indices = sampleIndicesDeterministicV2({
    maxIndex: ticket.L,
    extraCount,
    forceEdge1: true,
    forceEdgeLast: true,
    rng,
  });
  if (!indices.length) return null;
  const segSeed16 = await deriveSegLenSeed16(powSecret, ticket.cfgId, commitMac, sid);
  const rngSeg = makeXoshiro128ss(segSeed16);
  const segLensAll = computeSegLensForIndices(indices, segSpec, rngSeg);
  return { indices, segLensAll };
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

const handlePowCommit = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") return S(400);
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const rootB64 = typeof body.rootB64 === "string" ? body.rootB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const nonce = typeof body.nonce === "string" ? body.nonce : "";
  const captchaToken = body.captchaToken;
  if (
    !isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) ||
    !isBase64Url(rootB64, 1, B64_HASH_MAX_LEN) ||
    !isBase64Url(nonce, NONCE_MIN_LEN, NONCE_MAX_LEN) ||
    pathHash.length > B64_HASH_MAX_LEN
  ) {
    return S(400);
  }
  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return denyStale();
  if (!ticketMatchesInner(ticket, cfgId)) return denyStale();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  const { needTurn } = resolveCaptchaRequirements(config);
  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return denyStale();
  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);
  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return denyStale();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, config, powSecret);
  if (!bindingString) return denyStale();
  const pageAge = nowSeconds - ticket.issuedAt;
  if (!Number.isFinite(pageAge) || pageAge < 0 || pageAge > getPowMaxGenTimeSec(config)) {
    return denyStale();
  }
  const rootBytes = base64UrlDecodeToBytes(rootB64);
  if (!rootBytes || rootBytes.length !== 32) return S(400);
  const ttl = config.POW_COMMIT_TTL_SEC || 0;
  const exp = nowSeconds + Math.max(1, ttl);
  let captchaTag = "any";
  if (needTurn) {
    const localCaptcha = await deriveLocalCaptchaTag(config, captchaToken);
    if (!localCaptcha.ok) return localCaptcha.malformed ? S(400) : deny();
    captchaTag = localCaptcha.captchaTag;
  }
  const mac = await makePowCommitMac(
    powSecret,
    ticketB64,
    rootB64,
    bindingValues.pathHash,
    captchaTag,
    nonce,
    exp,
  );
  const commitToken = `v5.${ticketB64}.${rootB64}.${bindingValues.pathHash}.${captchaTag}.${nonce}.${exp}.${mac}`;
  return J({ commitToken }, 200);
};

const handleCap = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object") return S(400);
  const ticketB64 = typeof body.ticketB64 === "string" ? body.ticketB64 : "";
  const pathHash = typeof body.pathHash === "string" ? body.pathHash : "";
  const captchaToken = body.captchaToken;
  if (!isBase64Url(ticketB64, 1, B64_TICKET_MAX_LEN) || pathHash.length > B64_HASH_MAX_LEN) return S(400);

  const ticket = parsePowTicket(ticketB64);
  if (!ticket) return deny();
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  const needPow = config.powcheck === true;
  const { needTurn } = resolveCaptchaRequirements(config);
  const requiredMask = (needPow ? 1 : 0) | (needTurn ? 2 : 0);
  if (needPow || !needTurn || config.ATOMIC_CONSUME === true) return S(404);

  const powVersion = validateTicket(ticket, config, nowSeconds);
  if (!powVersion) return deny();

  const normalizedPathHash = normalizePathHash(pathHash, config);
  if (!normalizedPathHash) return S(400);

  const bindingValues = await getPowBindingValuesWithPathHash(normalizedPathHash, config, derived);
  if (!bindingValues) return deny();
  const bindingString = await verifyTicketMac(ticket, url, bindingValues, config, powSecret);
  if (!bindingString) return deny();

  const verifiedCaptcha = await verifyRequiredCaptchaForTicket(request, config, ticket, captchaToken);
  if (!verifiedCaptcha.ok) return verifiedCaptcha.malformed ? S(400) : denyStale();

  const ttl = getProofTtl(ticket, config, nowSeconds);
  if (!ttl) return denyStale();
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
  return new Response(null, { status: 200, headers });
};

const handlePowChallenge = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config, powSecret, derived, cfgId } = innerCtx;
  const body = await readJsonBody(request);
  const commitToken = body && typeof body.commitToken === "string" ? body.commitToken : "";
  if (!commitToken) return S(400);
  const commitCtx = loadCommitFromToken(commitToken);
  if (!commitCtx) return deny();
  const { commit, ticket } = commitCtx;
  if (!ticketMatchesInner(ticket, cfgId)) return deny();
  if (!powSecret) return S(500);
  if (config.powcheck !== true) return S(500);
  if (isExpired(ticket.e, nowSeconds) || isExpired(commit.exp, nowSeconds)) return denyStale();
  if (!(await verifyCommit(commit, ticket, config, powSecret, nowSeconds))) return denyCheat();
  if (isPowAbsoluteLifecycleExpired(ticket, config, nowSeconds)) return denyStale();
  const bindingValues = await getPowBindingValuesWithPathHash(commit.pathHash, config, derived);
  if (!bindingValues) return deny();
  if (!(await verifyTicketMac(ticket, url, bindingValues, config, powSecret))) return deny();
  const sid = await derivePowSid(powSecret, ticket.cfgId, commit.mac);
  const sample = await buildPowSample(config, powSecret, ticket, commit.mac, sid);
  if (!sample) return deny();
  const { indices, segLensAll } = sample;
  const difficultyBinding = getPowDifficultyBinding(config);
  const batchLen = getBatchMax(config);
  const batchResp = await buildPowBatchResponse(
    indices,
    segLensAll,
    ticket,
    commit,
    powSecret,
    sid,
    0,
    batchLen,
    difficultyBinding.pageBytes,
    difficultyBinding.mixRounds,
  );
  if (!batchResp) return deny();
  return J(batchResp);
};

const handlePowApiFront = async (request, url, nowSeconds, innerCtx) => {
  if (!innerCtx) return S(500);
  const { config } = innerCtx;
  const path = normalizePath(url.pathname);
  if (!path || !path.startsWith(`${config.POW_API_PREFIX}/`)) return S(404);
  const action = path.slice(config.POW_API_PREFIX.length);
  if (action === "/open") return S(404);
  if (request.method !== "POST") return S(405);
  if (action === "/commit") return handlePowCommit(request, url, nowSeconds, innerCtx);
  if (action === "/challenge") return handlePowChallenge(request, url, nowSeconds, innerCtx);
  if (action === "/cap") return handleCap(request, url, nowSeconds, innerCtx);
  return S(404);
};

export {
  captchaTagV1,
  deriveLocalCaptchaTag,
  handlePowApiFront,
  parseCanonicalCaptchaTokens,
  parsePowCommitCookie,
  parsePowTicket,
  resolveCaptchaRequirements,
  verifyTicketMac,
  verifyRequiredCaptchaForTicket,
};
