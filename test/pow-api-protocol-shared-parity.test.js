import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  encodePowTicket,
  parsePowTicket,
  makePowBindingString,
  hmacSha256Base64UrlNoPad,
  makePowCommitMac,
  makePowStateToken,
  verifyTicketMac,
} from "../lib/pow/api-protocol-shared.js";

const ensureGlobals = () => {
  const priorCrypto = globalThis.crypto;
  const priorBtoa = globalThis.btoa;
  const priorAtob = globalThis.atob;
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  const canAssignCrypto =
    !cryptoDescriptor || cryptoDescriptor.writable || typeof cryptoDescriptor.set === "function";
  const didSetCrypto = !globalThis.crypto && canAssignCrypto;
  const didSetBtoa = !globalThis.btoa;
  const didSetAtob = !globalThis.atob;

  if (didSetCrypto) globalThis.crypto = crypto.webcrypto;
  if (didSetBtoa) globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  if (didSetAtob) globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");

  return () => {
    if (didSetCrypto) {
      if (typeof priorCrypto === "undefined") delete globalThis.crypto;
      else globalThis.crypto = priorCrypto;
    }
    if (didSetBtoa) {
      if (typeof priorBtoa === "undefined") delete globalThis.btoa;
      else globalThis.btoa = priorBtoa;
    }
    if (didSetAtob) {
      if (typeof priorAtob === "undefined") delete globalThis.atob;
      else globalThis.atob = priorAtob;
    }
  };
};

const FIXTURE_SECRET = "pow-secret-1";
const FIXTURE_TICKET = {
  v: 3,
  e: 1700000200,
  L: 20,
  r: "AQIDBAUGBwgJCgsMDQ4PEA",
  cfgId: 7,
  issuedAt: 1700000000,
  mac: "g5PnZuLbDgNBiDG4RnJC5LSvAo2bOjoOWF6RRz6D0Qg",
};
const FIXTURE_BINDING =
  "3|1700000200|20|AQIDBAUGBwgJCgsMDQ4PEA|7|example.com|p_hash_123|1.2.3.4/32|US|12345|tlsv1|16384|2|1700000000";
const FIXTURE_TICKET_B64 =
  "My4xNzAwMDAwMjAwLjIwLkFRSURCQVVHQndnSkNnc01EUTRQRUEuNy4xNzAwMDAwMDAwLmc1UG5adUxiRGdOQmlERzRSbkpDNUxTdkFvMmJPam9PV0Y2UlJ6NkQwUWc";
const FIXTURE_BINDING_MAC = "g5PnZuLbDgNBiDG4RnJC5LSvAo2bOjoOWF6RRz6D0Qg";
const FIXTURE_COMMIT_MAC = "t5a06Qzz2AYWrtkE8T1Ssmnu2kC47mhUPuzjs55bPUo";
const FIXTURE_STATE_TOKEN = "x1YZ_CISsKC1ZPmcGvTZePxR55JPrBngQ3CXRROhdFc";

test("ticket encode/parse round-trip and rejection vectors", () => {
  const encoded = encodePowTicket(FIXTURE_TICKET);
  assert.equal(encoded, FIXTURE_TICKET_B64);
  assert.deepEqual(parsePowTicket(encoded), FIXTURE_TICKET);

  assert.equal(parsePowTicket(""), null);
  assert.equal(parsePowTicket("###"), null);
  assert.equal(
    parsePowTicket("MS4xLjEuYS4xLjEuYS4x"),
    null,
    "rejects malformed ticket with wrong field count",
  );
});

test("binding canonicalization and HMAC vectors stay stable", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const binding = makePowBindingString(
      FIXTURE_TICKET,
      "Example.COM",
      "p_hash_123",
      "1.2.3.4/32",
      "US",
      "12345",
      "tlsv1",
      16384,
      2,
    );
    assert.equal(binding, FIXTURE_BINDING);
    const mac = await hmacSha256Base64UrlNoPad(FIXTURE_SECRET, binding);
    assert.equal(mac, FIXTURE_BINDING_MAC);
  } finally {
    restoreGlobals();
  }
});

test("commit and state-token MAC vectors are deterministic", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const commitMac = await makePowCommitMac(
      FIXTURE_SECRET,
      FIXTURE_TICKET_B64,
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "p_hash_123",
      "any",
      "BBBBBBBBBBBBBBBBBBBBBB",
      1700000100,
    );
    assert.equal(commitMac, FIXTURE_COMMIT_MAC);

    const stateToken = await makePowStateToken(FIXTURE_SECRET, 7, "sid_abc", commitMac, 0, 4);
    assert.equal(stateToken, FIXTURE_STATE_TOKEN);
  } finally {
    restoreGlobals();
  }
});

test("mutation negatives break verification expectations", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const config = { POW_PAGE_BYTES: 16384, POW_MIX_ROUNDS: 2 };
    const url = new URL("https://example.com/__pow/challenge");
    const bindingValues = {
      pathHash: "p_hash_123",
      ipScope: "1.2.3.4/32",
      country: "US",
      asn: "12345",
      tlsFingerprint: "tlsv1",
    };
    const verified = await verifyTicketMac(FIXTURE_TICKET, url, bindingValues, config, FIXTURE_SECRET);
    assert.equal(verified, FIXTURE_BINDING);

    const badBindingValues = { ...bindingValues, pathHash: "p_hash_mutated" };
    assert.equal(await verifyTicketMac(FIXTURE_TICKET, url, badBindingValues, config, FIXTURE_SECRET), "");

    const mutatedCaptchaMac = await makePowCommitMac(
      FIXTURE_SECRET,
      FIXTURE_TICKET_B64,
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "p_hash_123",
      "BBBBBBBBBBBBBBBB",
      "BBBBBBBBBBBBBBBBBBBBBB",
      1700000100,
    );
    assert.notEqual(mutatedCaptchaMac, FIXTURE_COMMIT_MAC);

    const mutatedCursor = await makePowStateToken(FIXTURE_SECRET, 7, "sid_abc", FIXTURE_COMMIT_MAC, 1, 4);
    const mutatedBatchLen = await makePowStateToken(FIXTURE_SECRET, 7, "sid_abc", FIXTURE_COMMIT_MAC, 0, 5);
    assert.notEqual(mutatedCursor, FIXTURE_STATE_TOKEN);
    assert.notEqual(mutatedBatchLen, FIXTURE_STATE_TOKEN);
  } finally {
    restoreGlobals();
  }
});
