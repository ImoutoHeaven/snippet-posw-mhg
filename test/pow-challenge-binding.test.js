import test from "node:test";
import assert from "node:assert/strict";
import { __testTicketV4, handlePowApi } from "../lib/pow/api-engine.js";

const NOW = 1_700_000_000;

const makeCtx = (overrides = {}) => ({
  config: {
    POW_API_PREFIX: "/__pow",
    POW_TOKEN: "pow-secret",
    POW_EQ_N: 24,
    POW_EQ_K: 2,
    PROOF_TTL_SEC: 600,
    powcheck: false,
    turncheck: false,
    ATOMIC_CONSUME: false,
    AGGREGATOR_POW_ATOMIC_CONSUME: false,
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    ...overrides,
  },
  powSecret: "pow-secret",
  derived: {
    ipScope: "203.0.113.0/24",
    country: "any",
    asn: "any",
    tlsFingerprint: "any",
  },
  cfgId: 7,
  strategy: {},
});

const issueTicket = async (ctx, pathHash = "path-a") =>
  __testTicketV4.issueTicket({
    powSecret: ctx.powSecret,
    powVersion: 4,
    cfgId: ctx.cfgId,
    issuedAt: NOW,
    expireAt: NOW + 600,
    host: "example.com",
    pathHash,
    ipScope: ctx.derived.ipScope,
    country: ctx.derived.country,
    asn: ctx.derived.asn,
    tlsFingerprint: ctx.derived.tlsFingerprint,
    eqN: ctx.config.POW_EQ_N,
    eqK: ctx.config.POW_EQ_K,
  });

const callVerify = async (ctx, body) => {
  const req = new Request("https://example.com/__pow/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "CF-Connecting-IP": "203.0.113.9",
    },
    body: JSON.stringify(body),
  });
  return handlePowApi(req, new URL(req.url), NOW, ctx);
};

test("verify-only rejects ticket when path binding mismatches", async () => {
  const ctx = makeCtx();
  const ticketB64 = await issueTicket(ctx, "path-a");

  const res = await callVerify(ctx, { ticketB64, pathHash: "path-b" });
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-pow-h"), "stale");
});

test("verify-only rejects ticket when equihash params drift", async () => {
  const mintCtx = makeCtx({ POW_EQ_N: 24, POW_EQ_K: 2 });
  const ticketB64 = await issueTicket(mintCtx, "path-a");

  const verifyCtx = makeCtx({ POW_EQ_N: 90, POW_EQ_K: 5 });
  const res = await callVerify(verifyCtx, { ticketB64, pathHash: "path-a" });
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("x-pow-h"), "stale");
});
