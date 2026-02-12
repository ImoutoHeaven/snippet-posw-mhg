import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { verifyViaSiteverifyAggregator } from "../lib/pow/siteverify-client.js";

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

  if (didSetCrypto) {
    globalThis.crypto = crypto.webcrypto;
  }
  if (didSetBtoa) {
    globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  }
  if (didSetAtob) {
    globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  }

  return () => {
    if (didSetCrypto) {
      if (typeof priorCrypto === "undefined") {
        delete globalThis.crypto;
      } else {
        globalThis.crypto = priorCrypto;
      }
    }

    if (didSetBtoa) {
      if (typeof priorBtoa === "undefined") {
        delete globalThis.btoa;
      } else {
        globalThis.btoa = priorBtoa;
      }
    }

    if (didSetAtob) {
      if (typeof priorAtob === "undefined") {
        delete globalThis.atob;
      } else {
        globalThis.atob = priorAtob;
      }
    }
  };
};

const sha256Hex = (value) => crypto.createHash("sha256").update(value).digest("hex");
const hmacSha256Hex = (secret, value) =>
  crypto.createHmac("sha256", secret).update(value).digest("hex");

const baseConfig = {
  SITEVERIFY_URL: "https://sv.example/siteverify",
  SITEVERIFY_AUTH_KID: "v1",
  SITEVERIFY_AUTH_SECRET: "siteverify-secret",
};

const basePayload = {
  ticketMac: "ticket-mac",
  token: {
    turnstile: "turnstile-token",
  },
  providers: {
    turnstile: {
      secret: "turnstile-secret",
    },
  },
  checks: {},
};

test("client sends SV1 authorization and body hash headers", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  let capturedRequest = null;
  let capturedBody = "";

  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    capturedRequest = request;
    capturedBody = await request.text();
    return new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    );
  };

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });

    assert.equal(result.ok, true);
    assert.ok(capturedRequest, "captures outbound request");
    assert.equal(capturedRequest.method, "POST");
    assert.equal(capturedRequest.url, baseConfig.SITEVERIFY_URL);

    const authHeader = capturedRequest.headers.get("authorization") || "";
    const bodyHashHeader = capturedRequest.headers.get("x-sv-body-sha256") || "";

    assert.match(authHeader, /^SV1 /u);
    assert.equal(bodyHashHeader, sha256Hex(capturedBody));

    const authKv = Object.fromEntries(
      authHeader
        .slice(4)
        .split(",")
        .map((entry) => {
          const separator = entry.indexOf("=");
          return [entry.slice(0, separator).trim(), entry.slice(separator + 1).trim()];
        }),
    );

    assert.equal(authKv.kid, baseConfig.SITEVERIFY_AUTH_KID);
    assert.ok(/^\d+$/u.test(authKv.exp));
    assert.ok(typeof authKv.nonce === "string" && authKv.nonce.length > 0);
    assert.ok(/^[a-f0-9]{64}$/u.test(authKv.sig));

    const canonical = [
      "SV1",
      "POST",
      new URL(baseConfig.SITEVERIFY_URL).pathname,
      authKv.kid,
      authKv.exp,
      authKv.nonce,
      bodyHashHeader,
    ].join("\n");

    assert.equal(authKv.sig, hmacSha256Hex(baseConfig.SITEVERIFY_AUTH_SECRET, canonical));
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client rejects non-json or malformed response", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  const responses = [
    new Response("not json", {
      status: 200,
      headers: { "content-type": "text/plain" },
    }),
    new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
      }),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      },
    ),
  ];

  globalThis.fetch = async () => responses.shift();

  try {
    const nonJson = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.deepEqual(nonJson, {
      ok: false,
      reason: "invalid_aggregator_response",
    });

    const malformed = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.deepEqual(malformed, {
      ok: false,
      reason: "invalid_aggregator_response",
    });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("client rejects non-200 response", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        ok: true,
        reason: "ok",
        checks: {},
        providers: {},
      }),
      {
        status: 502,
        headers: { "content-type": "application/json" },
      },
    );

  try {
    const result = await verifyViaSiteverifyAggregator({
      config: baseConfig,
      payload: basePayload,
    });
    assert.deepEqual(result, {
      ok: false,
      reason: "invalid_aggregator_response",
    });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
