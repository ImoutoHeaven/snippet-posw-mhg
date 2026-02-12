import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

const KID = "v1";
const SHARED_SECRET = "replace-me";
const MAX_BODY_BYTES = 256 * 1024;
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RECAPTCHA_SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
const testEncoder = new TextEncoder();

const toHex = (bytes) =>
  Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const sha256Hex = async (value) => {
  const bytes = typeof value === "string" ? testEncoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return toHex(new Uint8Array(digest));
};

const hmacSha256Hex = async (secret, message) => {
  const key = await crypto.subtle.importKey(
    "raw",
    testEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, testEncoder.encode(message));
  return toHex(new Uint8Array(sig));
};

const buildCanonical = ({ method, path, kid, exp, nonce, bodySha256 }) =>
  ["SV1", method, path, kid, String(exp), nonce, bodySha256].join("\n");

const buildAuthorizedRequest = async ({
  body = JSON.stringify({ token: "test-token" }),
  bodyForHash = body,
  bodyInit = body,
  exp = Math.floor(Date.now() / 1000) + 5,
  nonce = "nonce-1",
  sig,
} = {}) => {
  const method = "POST";
  const path = "/siteverify";
  const bodySha256 = await sha256Hex(bodyForHash);
  const canonical = buildCanonical({ method, path, kid: KID, exp, nonce, bodySha256 });
  const signature = sig ?? (await hmacSha256Hex(SHARED_SECRET, canonical));
  const requestInit = {
    method,
    headers: {
      authorization: `SV1 kid=${KID},exp=${exp},nonce=${nonce},sig=${signature}`,
      "x-sv-body-sha256": bodySha256,
      "content-type": "application/json",
    },
    body: bodyInit,
  };

  if (typeof ReadableStream !== "undefined" && bodyInit instanceof ReadableStream) {
    requestInit.duplex = "half";
  }

  return new Request(`https://sv.example${path}`, requestInit);
};

const createDeferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

const buildProviderPayload = () => ({
  token: {
    turnstile: "turn-token",
    recaptcha_v3: "recaptcha-token",
  },
  remoteip: "203.0.113.10",
  checks: {
    recaptchaAction: "submit",
    recaptchaMinScore: 0.5,
  },
  ticketMac: "ticket-mac",
  providers: {
    turnstile: {
      secret: "turn-secret",
    },
    recaptcha_v3: {
      pairs: [
        { secret: "recaptcha-secret-0", sitekey: "recaptcha-sitekey-0" },
        { secret: "recaptcha-secret-1", sitekey: "recaptcha-sitekey-1" },
      ],
    },
  },
});

const jsonFetchResponse = (payload, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json",
    },
  });

test("worker returns 404 for missing authorization", async () => {
  const res = await worker.fetch(
    new Request("https://sv.example/siteverify", {
      method: "POST",
      body: "{}",
    })
  );

  assert.equal(res.status, 404);
});

test("valid SV1 authorization is accepted", async () => {
  const req = await buildAuthorizedRequest();
  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /application\/json/u);
  const payload = await res.json();
  assert.equal(payload.ok, false);
  assert.equal(payload.reason, "provider_failed");
  assert.deepEqual(payload.providers, {});
});

test("invalid signature returns 404", async () => {
  const req = await buildAuthorizedRequest({ sig: "f".repeat(64) });
  const res = await worker.fetch(req);

  assert.equal(res.status, 404);
});

test("invalid signature is rejected before consuming stream body", async () => {
  const streamBody = new ReadableStream({
    pull() {
      throw new Error("stream should not be read for invalid signature");
    },
  });

  const req = await buildAuthorizedRequest({
    bodyForHash: JSON.stringify({ token: "stream-test" }),
    bodyInit: streamBody,
    sig: "f".repeat(64),
  });

  const res = await worker.fetch(req);
  assert.equal(res.status, 404);
});

test("oversized body with invalid signature still returns 404", async () => {
  const oversizedBody = JSON.stringify({ token: "c".repeat(256 * 1024) });
  assert.ok(testEncoder.encode(oversizedBody).byteLength > MAX_BODY_BYTES);

  const req = await buildAuthorizedRequest({
    body: oversizedBody,
    sig: "f".repeat(64),
  });
  const res = await worker.fetch(req);

  assert.equal(res.status, 404);
});

test("body > 256KB returns bad_request payload", async () => {
  const oversizedBody = JSON.stringify({ token: "a".repeat(256 * 1024) });
  assert.ok(testEncoder.encode(oversizedBody).byteLength > MAX_BODY_BYTES);

  const req = await buildAuthorizedRequest({ body: oversizedBody });
  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: false, reason: "bad_request" });
});

test("oversized stream is rejected before reading further chunks", async () => {
  const oversizedBody = JSON.stringify({ token: "b".repeat(256 * 1024) });
  const firstChunk = testEncoder.encode(oversizedBody);
  assert.ok(firstChunk.byteLength > MAX_BODY_BYTES);

  let emittedFirstChunk = false;
  const streamBody = new ReadableStream({
    pull(controller) {
      if (!emittedFirstChunk) {
        emittedFirstChunk = true;
        controller.enqueue(firstChunk);
        return;
      }

      throw new Error("stream consumed past limit");
    },
  });

  const req = await buildAuthorizedRequest({
    bodyForHash: oversizedBody,
    bodyInit: streamBody,
  });

  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: false, reason: "bad_request" });
});

test("invalid json under size limit returns bad_request payload", async () => {
  const invalidJsonBody = "{\"token\":";
  assert.ok(testEncoder.encode(invalidJsonBody).byteLength < MAX_BODY_BYTES);

  const req = await buildAuthorizedRequest({ body: invalidJsonBody });
  const res = await worker.fetch(req);

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: false, reason: "bad_request" });
});

test("runs turnstile and recaptcha in parallel and returns provider results", async () => {
  const payload = buildProviderPayload();
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const turnstileDeferred = createDeferred();
  const recaptchaDeferred = createDeferred();
  const fetchCalls = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    fetchCalls.push(reqUrl);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) return turnstileDeferred.promise;
    if (reqUrl === RECAPTCHA_SITEVERIFY_URL) return recaptchaDeferred.promise;
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const responsePromise = worker.fetch(req);

    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(
      fetchCalls.filter((entry) => entry === TURNSTILE_SITEVERIFY_URL).length,
      1,
    );
    assert.equal(
      fetchCalls.filter((entry) => entry === RECAPTCHA_SITEVERIFY_URL).length,
      1,
    );

    turnstileDeferred.resolve(
      jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      }),
    );
    recaptchaDeferred.resolve(
      jsonFetchResponse({
        success: true,
        action: payload.checks.recaptchaAction,
        score: payload.checks.recaptchaMinScore + 0.1,
      }),
    );

    const res = await responsePromise;
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.providers.turnstile.rawResponse.success, true);
    assert.equal(body.providers.recaptcha_v3.rawResponse.success, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("provider network failure maps provider httpStatus=502", async () => {
  const payload = buildProviderPayload();
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      throw new Error("turnstile network down");
    }
    if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        action: payload.checks.recaptchaAction,
        score: payload.checks.recaptchaMinScore + 0.1,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.providers.turnstile.httpStatus, 502);
    assert.equal(typeof body.providers.turnstile.rawResponse, "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recaptcha returns pickedPairIndex", async () => {
  const payload = buildProviderPayload();
  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === TURNSTILE_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        cdata: payload.ticketMac,
      });
    }
    if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        action: payload.checks.recaptchaAction,
        score: payload.checks.recaptchaMinScore + 0.1,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.providers.recaptcha_v3.pickedPairIndex, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recaptcha missing checks fails closed", async () => {
  const payload = buildProviderPayload();
  delete payload.providers.turnstile;
  delete payload.token.turnstile;
  delete payload.checks;

  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        action: "unexpected",
        score: 0.01,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.ok, false);
    assert.equal(body.reason, "provider_failed");
    assert.equal(body.providers.recaptcha_v3.ok, false);
    assert.equal(body.providers.recaptcha_v3.httpStatus, 400);
    assert.equal(typeof body.providers.recaptcha_v3.rawResponse, "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recaptcha invalid checks fails closed", async () => {
  const payload = buildProviderPayload();
  delete payload.providers.turnstile;
  delete payload.token.turnstile;
  payload.checks = {
    recaptchaAction: 123,
    recaptchaMinScore: "bad",
  };

  const req = await buildAuthorizedRequest({ body: JSON.stringify(payload) });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (url) => {
    const reqUrl = String(url);
    if (reqUrl === RECAPTCHA_SITEVERIFY_URL) {
      return jsonFetchResponse({
        success: true,
        action: "unexpected",
        score: 0.99,
      });
    }
    throw new Error(`unexpected url: ${reqUrl}`);
  };

  try {
    const res = await worker.fetch(req);
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.ok, false);
    assert.equal(body.reason, "provider_failed");
    assert.equal(body.providers.recaptcha_v3.ok, false);
    assert.equal(body.providers.recaptcha_v3.httpStatus, 400);
    assert.equal(typeof body.providers.recaptcha_v3.rawResponse, "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
