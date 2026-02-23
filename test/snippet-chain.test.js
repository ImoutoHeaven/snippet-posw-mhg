import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { __testTicketV4 } from "../lib/pow/api-engine.js";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const ensureGlobals = () => {
  const priorBtoa = globalThis.btoa;
  const priorAtob = globalThis.atob;
  if (!globalThis.btoa) {
    globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  }
  if (!globalThis.atob) {
    globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  }
  return () => {
    if (typeof priorBtoa === "undefined") delete globalThis.btoa;
    else globalThis.btoa = priorBtoa;
    if (typeof priorAtob === "undefined") delete globalThis.atob;
    else globalThis.atob = priorAtob;
  };
};

const buildCoreModules = async (secret = "config-secret") => {
  const [core1SourceRaw, core2SourceRaw] = await Promise.all([
    readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
  ]);
  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-core-chain-v7-"));
  await mkdir(join(tmpDir, "lib"), { recursive: true });
  await cp(join(repoRoot, "lib", "pow"), join(tmpDir, "lib", "pow"), { recursive: true });
  await cp(join(repoRoot, "lib", "equihash"), join(tmpDir, "lib", "equihash"), { recursive: true });

  await Promise.all([
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
  ]);

  const nonce = `${Date.now()}-${Math.random()}`;
  const [core1Module, core2Module] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${nonce}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${nonce}`),
  ]);

  return {
    core1Fetch: core1Module.default.fetch,
    core2Fetch: core2Module.default.fetch,
  };
};

const buildInnerHeaders = (payloadObj, secret = "config-secret") => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + 3;
  const macInput = `${payload}.${exp}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
  };
};

const makeInnerPayload = (overrides = {}) => ({
  v: 1,
  id: 7,
  c: {
    POW_TOKEN: "pow-secret",
    POW_API_PREFIX: "/__pow",
    POW_EQ_N: 24,
    POW_EQ_K: 2,
    PROOF_TTL_SEC: 600,
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    powcheck: false,
    turncheck: false,
    ATOMIC_CONSUME: false,
    AGGREGATOR_POW_ATOMIC_CONSUME: false,
    ...overrides,
  },
  d: {
    ipScope: "203.0.113.0/24",
    country: "any",
    asn: "any",
    tlsFingerprint: "any",
  },
  s: {
    nav: {},
    bypass: { bypass: false },
    bind: { ok: true, code: "", canonicalPath: "/protected" },
    atomic: {
      captchaToken: "",
      ticketB64: "",
      consumeToken: "",
      fromCookie: false,
      cookieName: "__Secure-pow_a",
    },
  },
});

const issueTicket = async (innerPayload, pathHash = "path-hash") =>
  __testTicketV4.issueTicket({
    powSecret: innerPayload.c.POW_TOKEN,
    powVersion: 4,
    cfgId: innerPayload.id,
    issuedAt: Math.floor(Date.now() / 1000),
    expireAt: Math.floor(Date.now() / 1000) + 300,
    host: "example.com",
    pathHash,
    ipScope: innerPayload.d.ipScope,
    country: innerPayload.d.country,
    asn: innerPayload.d.asn,
    tlsFingerprint: innerPayload.d.tlsFingerprint,
    eqN: innerPayload.c.POW_EQ_N,
    eqK: innerPayload.c.POW_EQ_K,
  });

test("split chain accepts verify-only request", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules();
    const innerPayload = makeInnerPayload();
    const ticketB64 = await issueTicket(innerPayload);
    const innerHeaders = buildInnerHeaders(innerPayload);

    let core2Calls = 0;
    let originCalls = 0;
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        core2Calls += 1;
        return core2Fetch(request);
      }
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };

    const res = await core1Fetch(
      new Request("https://example.com/__pow/verify", {
        method: "POST",
        headers: {
          ...innerHeaders,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ticketB64, pathHash: "path-hash" }),
      }),
    );

    assert.equal(res.status, 200);
    assert.equal(core2Calls, 1);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split chain rejects non-verify api variant", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules();
    const innerPayload = makeInnerPayload();
    const innerHeaders = buildInnerHeaders(innerPayload);

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      return new Response("origin", { status: 200 });
    };

    const res = await core1Fetch(
      new Request("https://example.com/__pow/verifyx", {
        method: "POST",
        headers: {
          ...innerHeaders,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      }),
    );

    assert.equal(res.status, 500);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split chain enforces POST for verify endpoint", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules();
    const innerPayload = makeInnerPayload();
    const innerHeaders = buildInnerHeaders(innerPayload);

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      return new Response("origin", { status: 200 });
    };

    const res = await core1Fetch(
      new Request("https://example.com/__pow/verify", {
        method: "GET",
        headers: {
          ...innerHeaders,
        },
      }),
    );

    assert.equal(res.status, 405);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
