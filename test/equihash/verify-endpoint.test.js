import test from "node:test";
import assert from "node:assert/strict";

import { __testTicketV4, handlePowApi } from "../../lib/pow/api-engine.js";

const nowSeconds = 1_700_000_000;

const toB64Url = (bytes) =>
  Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));

const FIXTURE = {
  n: 24,
  k: 2,
  pathHash: "eqh-fixed-seed-v1",
  ticketB64: "NC4xNzAwMDAwNjAwLjcuMTcwMDAwMDAwMC5qN3ZkOUVrbUJta1N0d3d1TDlnVmxVSXRKeGk1T1ZqQnRuLUNPUXBrVzBB",
  nonceB64: "R_PfsXHr64v1gIxJXOoCM5fudAQ2aF6n",
  proofB64: "AACq1wAAq28AAKx3AACtPQ",
  proof: fromHex("0000aad70000ab6f0000ac770000ad3d"),
};

const baseConfig = {
  POW_API_PREFIX: "/__pow",
  POW_TOKEN: "pow-secret",
  POW_EQ_N: FIXTURE.n,
  POW_EQ_K: FIXTURE.k,
  PROOF_TTL_SEC: 600,
  powcheck: false,
  turncheck: false,
  ATOMIC_CONSUME: false,
  AGGREGATOR_POW_ATOMIC_CONSUME: false,
  TURNSTILE_SECRET: "turn-secret",
  POW_BIND_PATH: true,
  POW_BIND_IPRANGE: true,
  POW_BIND_COUNTRY: true,
  POW_BIND_ASN: true,
  POW_BIND_TLS: true,
  SITEVERIFY_URLS: ["https://sv.example/siteverify"],
  SITEVERIFY_AUTH_KID: "v1",
  SITEVERIFY_AUTH_SECRET: "agg-secret",
};

const makeInnerCtx = (cfg = {}) => ({
  config: { ...baseConfig, ...cfg },
  powSecret: "pow-secret",
  derived: {
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
  },
  cfgId: 7,
  strategy: {},
});

const issueTicket = async ({ ctx, pathHash = FIXTURE.pathHash, ttl = 600 }) =>
  __testTicketV4.issueTicket({
    powSecret: ctx.powSecret,
    powVersion: 4,
    cfgId: ctx.cfgId,
    issuedAt: nowSeconds,
    expireAt: nowSeconds + ttl,
    host: "example.com",
    pathHash,
    ipScope: ctx.derived.ipScope,
    country: ctx.derived.country,
    asn: ctx.derived.asn,
    tlsFingerprint: ctx.derived.tlsFingerprint,
    eqN: ctx.config.POW_EQ_N,
    eqK: ctx.config.POW_EQ_K,
  });

const makeValidPow = () => ({
  nonceB64: FIXTURE.nonceB64,
  proofB64: FIXTURE.proofB64,
});

const callVerify = async ({ ctx, body, fetchMock }) => {
  const priorFetch = globalThis.fetch;
  if (fetchMock) {
    globalThis.fetch = fetchMock;
  }
  try {
    const req = new Request("https://example.com/__pow/verify", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.9" },
      body: JSON.stringify(body),
    });
    return await handlePowApi(req, new URL(req.url), nowSeconds, ctx);
  } finally {
    globalThis.fetch = priorFetch;
  }
};

const parseProofMask = (res) => {
  const setCookie = String(res.headers.get("set-cookie") || "");
  const raw = decodeURIComponent(setCookie.split(";")[0].split("=")[1] || "");
  const parts = raw.split(".");
  return Number.parseInt(parts[5] || "", 10);
};

test("/verify matrix preserves turnstile/atomic/aggregator semantics", { concurrency: false }, async () => {
  const noProtectionCtx = makeInnerCtx({ powcheck: false, turncheck: false });
  const noProtectionTicket = await issueTicket({ ctx: noProtectionCtx });
  const noProtectionRes = await callVerify({
    ctx: noProtectionCtx,
    body: { ticketB64: noProtectionTicket, pathHash: FIXTURE.pathHash },
  });
  assert.equal(noProtectionRes.status, 200);

  const atomicNoProtectionCtx = makeInnerCtx({ powcheck: false, turncheck: false, ATOMIC_CONSUME: true });
  const atomicNoProtectionTicket = await issueTicket({ ctx: atomicNoProtectionCtx });
  const atomicNoProtectionRes = await callVerify({
    ctx: atomicNoProtectionCtx,
    body: { ticketB64: atomicNoProtectionTicket, pathHash: FIXTURE.pathHash },
  });
  assert.equal(atomicNoProtectionRes.status, 200);

  const powOnlyCtx = makeInnerCtx({ powcheck: true, turncheck: false, ATOMIC_CONSUME: false });
  const powOnlyTicket = await issueTicket({ ctx: powOnlyCtx });
  assert.equal(powOnlyTicket, FIXTURE.ticketB64);
  const powOnlyRes = await callVerify({
    ctx: powOnlyCtx,
    body: { ticketB64: powOnlyTicket, pathHash: FIXTURE.pathHash, pow: makeValidPow() },
  });
  assert.equal(powOnlyRes.status, 200);
  assert.equal(parseProofMask(powOnlyRes), 1);

  const turnOnlyCtx = makeInnerCtx({ powcheck: false, turncheck: true, ATOMIC_CONSUME: false });
  const turnOnlyTicket = await issueTicket({ ctx: turnOnlyCtx });
  const turnOnlyFetchMock = async () =>
    new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  const turnOnlyRes = await callVerify({
    ctx: turnOnlyCtx,
    body: {
      ticketB64: turnOnlyTicket,
      pathHash: FIXTURE.pathHash,
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
    fetchMock: turnOnlyFetchMock,
  });
  assert.equal(turnOnlyRes.status, 200);
  assert.equal(parseProofMask(turnOnlyRes), 2);

  const bothCtx = makeInnerCtx({ powcheck: true, turncheck: true, ATOMIC_CONSUME: false });
  const bothTicket = await issueTicket({ ctx: bothCtx });
  const bothRes = await callVerify({
    ctx: bothCtx,
    body: {
      ticketB64: bothTicket,
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
    fetchMock: async () =>
      new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });
  assert.equal(bothRes.status, 200);
  assert.equal(parseProofMask(bothRes), 3);

  const turnAtomicCtx = makeInnerCtx({ powcheck: false, turncheck: true, ATOMIC_CONSUME: true });
  const turnAtomicTicket = await issueTicket({ ctx: turnAtomicCtx });
  const turnAtomicRes = await callVerify({
    ctx: turnAtomicCtx,
    body: {
      ticketB64: turnAtomicTicket,
      pathHash: FIXTURE.pathHash,
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
    fetchMock: async () =>
      new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });
  assert.equal(turnAtomicRes.status, 200);
  const turnAtomicBody = await turnAtomicRes.json();
  assert.equal(turnAtomicBody.mode, "consume");
  assert.equal(typeof turnAtomicBody.consume, "string");

  const powAtomicAggCtx = makeInnerCtx({
    powcheck: true,
    turncheck: false,
    ATOMIC_CONSUME: true,
    AGGREGATOR_POW_ATOMIC_CONSUME: true,
  });
  const powAtomicAggTicket = await issueTicket({ ctx: powAtomicAggCtx });
  const powAtomicAggRes = await callVerify({
    ctx: powAtomicAggCtx,
    body: {
      ticketB64: powAtomicAggTicket,
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
    },
    fetchMock: async () =>
      new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });
  assert.equal(powAtomicAggRes.status, 200);
  const powAtomicAggBody = await powAtomicAggRes.json();
  assert.equal(powAtomicAggBody.mode, "consume");

  const powAtomicNoAggCtx = makeInnerCtx({
    powcheck: true,
    turncheck: false,
    ATOMIC_CONSUME: true,
    AGGREGATOR_POW_ATOMIC_CONSUME: false,
  });
  const powAtomicNoAggTicket = await issueTicket({ ctx: powAtomicNoAggCtx });
  const powAtomicNoAggRes = await callVerify({
    ctx: powAtomicNoAggCtx,
    body: {
      ticketB64: powAtomicNoAggTicket,
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
    },
  });
  assert.equal(powAtomicNoAggRes.status, 200);
  const powAtomicNoAggBody = await powAtomicNoAggRes.json();
  assert.equal(powAtomicNoAggBody.mode, "proof");

  const powAggFailCtx = makeInnerCtx({
    powcheck: true,
    turncheck: false,
    AGGREGATOR_POW_ATOMIC_CONSUME: true,
    ATOMIC_CONSUME: false,
  });
  const powAggFailTicket = await issueTicket({ ctx: powAggFailCtx });
  const powAggFailRes = await callVerify({
    ctx: powAggFailCtx,
    body: {
      ticketB64: powAggFailTicket,
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
    },
    fetchMock: async () => new Response("nope", { status: 502 }),
  });
  assert.equal(powAggFailRes.status, 403);
  assert.equal(powAggFailRes.headers.get("x-pow-h"), "stale");

  const badCaptchaCtx = makeInnerCtx({ powcheck: false, turncheck: true, ATOMIC_CONSUME: true });
  const badCaptchaTicket = await issueTicket({ ctx: badCaptchaCtx });
  const badCaptchaRes = await callVerify({
    ctx: badCaptchaCtx,
    body: {
      ticketB64: badCaptchaTicket,
      pathHash: FIXTURE.pathHash,
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
    fetchMock: async () =>
      new Response(
        JSON.stringify({
          ok: false,
          reason: "provider_failed",
          checks: {},
          providers: { turnstile: { ok: false, normalized: { success: false } } },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });
  assert.equal(badCaptchaRes.status, 403);
  assert.equal(badCaptchaRes.headers.get("x-pow-h"), "captcha_required");

  const staleByReasonCtx = makeInnerCtx({ powcheck: false, turncheck: true, ATOMIC_CONSUME: false });
  const staleByReasonTicket = await issueTicket({ ctx: staleByReasonCtx });
  const staleByReasonRes = await callVerify({
    ctx: staleByReasonCtx,
    body: {
      ticketB64: staleByReasonTicket,
      pathHash: FIXTURE.pathHash,
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
    fetchMock: async () =>
      new Response(
        JSON.stringify({
          ok: false,
          reason: "consume_conflict",
          checks: { powConsume: { ok: false, reason: "duplicate" } },
          providers: { turnstile: { ok: true, normalized: { success: true } } },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });
  assert.equal(staleByReasonRes.status, 403);
  assert.equal(staleByReasonRes.headers.get("x-pow-h"), "stale");

  const ctx = makeInnerCtx({ powcheck: true, turncheck: true, ATOMIC_CONSUME: false });
  const ticketB64 = await issueTicket({ ctx });

  const badRequestRes = await callVerify({
    ctx,
    body: { ticketB64, pathHash: FIXTURE.pathHash, pow: { nonceB64: 1 } },
  });
  assert.equal(badRequestRes.status, 403);
  assert.equal(badRequestRes.headers.get("x-pow-h"), "bad_request");

  const staleTicketRes = await callVerify({
    ctx,
    body: { ticketB64: "bad-ticket", pathHash: FIXTURE.pathHash, pow: makeValidPow() },
  });
  assert.equal(staleTicketRes.status, 403);
  assert.equal(staleTicketRes.headers.get("x-pow-h"), "stale");

  const powRequiredRes = await callVerify({
    ctx,
    body: { ticketB64, pathHash: FIXTURE.pathHash, captchaToken: { turnstile: "turnstile-token-1234567890" } },
  });
  assert.equal(powRequiredRes.status, 403);
  assert.equal(powRequiredRes.headers.get("x-pow-h"), "pow_required");

  const cheatRes = await callVerify({
    ctx,
    body: {
      ticketB64,
      pathHash: FIXTURE.pathHash,
      pow: { nonceB64: FIXTURE.nonceB64, proofB64: toB64Url(fromHex("0000aad70000ab6f0000ac770000ad3c")) },
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
  });
  assert.equal(cheatRes.status, 403);
  assert.equal(cheatRes.headers.get("x-pow-h"), "cheat");

  const badPowEnvelopeRes = await callVerify({
    ctx,
    body: {
      ticketB64,
      pathHash: FIXTURE.pathHash,
      pow: { nonceB64: "!!!!", proofB64: "also-not-b64" },
      captchaToken: { turnstile: "turnstile-token-1234567890" },
    },
  });
  assert.equal(badPowEnvelopeRes.status, 403);
  assert.equal(badPowEnvelopeRes.headers.get("x-pow-h"), "bad_request");

  const captchaRequiredRes = await callVerify({
    ctx,
    body: { ticketB64, pathHash: FIXTURE.pathHash, pow: makeValidPow() },
  });
  assert.equal(captchaRequiredRes.status, 403);
  assert.equal(captchaRequiredRes.headers.get("x-pow-h"), "captcha_required");
});

test("/verify binds pow solution to ticket material", { concurrency: false }, async () => {
  const ctx = makeInnerCtx({ powcheck: true, turncheck: false, ATOMIC_CONSUME: false });
  const sourceTicket = await issueTicket({ ctx, ttl: 600 });
  const replayTicket = await issueTicket({ ctx, ttl: 601 });
  assert.equal(sourceTicket, FIXTURE.ticketB64);
  assert.notEqual(replayTicket, sourceTicket);

  const sourceOk = await callVerify({
    ctx,
    body: {
      ticketB64: sourceTicket,
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
    },
  });
  assert.equal(sourceOk.status, 200);

  const replayRes = await callVerify({
    ctx,
    body: {
      ticketB64: replayTicket,
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
    },
  });
  assert.equal(replayRes.status, 403);
  assert.equal(replayRes.headers.get("x-pow-h"), "cheat");
});

test("/verify validates ticket envelope before binding resolution", { concurrency: false }, async () => {
  const derived = {};
  Object.defineProperty(derived, "ipScope", {
    get() {
      throw new Error("binding-resolution-should-not-run");
    },
  });
  const ctx = {
    config: { ...baseConfig, powcheck: true, turncheck: false, POW_BIND_IPRANGE: true },
    powSecret: "pow-secret",
    derived,
    cfgId: 7,
    strategy: {},
  };

  const res = await callVerify({
    ctx,
    body: {
      ticketB64: "not-a-ticket",
      pathHash: FIXTURE.pathHash,
      pow: makeValidPow(),
    },
  });

  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-pow-h"), "stale");
});
