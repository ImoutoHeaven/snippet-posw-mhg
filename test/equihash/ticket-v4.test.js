import test from "node:test";
import assert from "node:assert/strict";

import { __testTicketV4 } from "../../lib/pow/api-engine.js";
import { __testTicketV4 as __testBusinessTicketV4 } from "../../lib/pow/business-gate.js";

const toB64Url = (raw) =>
  Buffer.from(raw, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

test("ticket v4 binds host/path/context and equihash parameters", async () => {
  const now = Math.floor(Date.now() / 1000);
  const ticketB64 = await __testTicketV4.issueTicket({
    powSecret: "pow-secret",
    powVersion: 4,
    cfgId: 9,
    issuedAt: now,
    expireAt: now + 600,
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: 5,
  });

  const good = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: 5,
    nowSeconds: now,
  });
  assert.equal(good.ok, true);

  const eqMismatch = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 72,
    eqK: 4,
    nowSeconds: now,
  });
  assert.equal(eqMismatch.ok, false);

  const hostMismatch = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "other.example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: 5,
    nowSeconds: now,
  });
  assert.equal(hostMismatch.ok, false);
});

test("ticket v4 parse rejects non-canonical numeric suffixes", () => {
  const suffixExp = toB64Url("4.1700000000x.9.1700000001.sig");
  const suffixIat = toB64Url("4.1700000000.9.1700000001x.sig");
  const wrongVersion = toB64Url("3.1700000000.9.1700000001.sig");

  assert.equal(__testTicketV4.parseTicket(suffixExp), null);
  assert.equal(__testTicketV4.parseTicket(suffixIat), null);
  assert.equal(__testTicketV4.parseTicket(wrongVersion), null);
});

test("ticket v4 verify fails closed for invalid nowSeconds and eq params", async () => {
  const now = Math.floor(Date.now() / 1000);
  const ticketB64 = await __testTicketV4.issueTicket({
    powSecret: "pow-secret",
    powVersion: 4,
    cfgId: 9,
    issuedAt: now,
    expireAt: now + 600,
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: 5,
  });

  const missingNow = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: 5,
  });
  assert.equal(missingNow.ok, false);
  assert.equal(missingNow.reason, "invalid_now");

  const nanNow = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: 5,
    nowSeconds: Number.NaN,
  });
  assert.equal(nanNow.ok, false);
  assert.equal(nanNow.reason, "invalid_now");

  const badEqN = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: "90x",
    eqK: 5,
    nowSeconds: now,
  });
  assert.equal(badEqN.ok, false);
  assert.equal(badEqN.reason, "invalid_eq_params");

  const badEqK = await __testTicketV4.verifyTicket({
    ticketB64,
    powSecret: "pow-secret",
    host: "example.com",
    pathHash: "abc123",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "AS64500",
    tlsFingerprint: "ja4:test",
    eqN: 90,
    eqK: "5x",
    nowSeconds: now,
  });
  assert.equal(badEqK.ok, false);
  assert.equal(badEqK.reason, "invalid_eq_params");
});

test("ticket v4 issue rejects non-v4 versions", async () => {
  await assert.rejects(
    __testTicketV4.issueTicket({
      powSecret: "pow-secret",
      powVersion: 3,
      cfgId: 9,
      issuedAt: 1700000000,
      expireAt: 1700000600,
      host: "example.com",
      pathHash: "abc123",
      ipScope: "203.0.113.0/24",
      country: "US",
      asn: "AS64500",
      tlsFingerprint: "ja4:test",
      eqN: 90,
      eqK: 5,
    }),
    /invalid ticket version/u,
  );
});

test("ticket v4 issue rejects invalid equihash parameter pairs", async () => {
  await assert.rejects(
    __testTicketV4.issueTicket({
      powSecret: "pow-secret",
      powVersion: 4,
      cfgId: 9,
      issuedAt: 1700000000,
      expireAt: 1700000600,
      host: "example.com",
      pathHash: "abc123",
      ipScope: "203.0.113.0/24",
      country: "US",
      asn: "AS64500",
      tlsFingerprint: "ja4:test",
      eqN: 96,
      eqK: 8,
    }),
    /invalid equihash params/u,
  );
});

test("business-gate and api-engine share ticket v4 codec", async () => {
  const now = Math.floor(Date.now() / 1000);
  const ticketB64 = await __testTicketV4.issueTicket({
    powSecret: "pow-secret",
    powVersion: 4,
    cfgId: 1,
    issuedAt: now,
    expireAt: now + 300,
    host: "example.com",
    pathHash: "path-hash",
    ipScope: "203.0.113.0/24",
    country: "US",
    asn: "64500",
    tlsFingerprint: "any",
    eqN: 90,
    eqK: 5,
  });

  const parsed = __testBusinessTicketV4.parseTicket(ticketB64);
  assert.ok(parsed);
  assert.equal(parsed.v, 4);
  assert.equal(parsed.cfgId, 1);
});
