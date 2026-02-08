import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const buildInnerHeaders = (payloadObj, secret, expOverride) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Number.isFinite(expOverride)
    ? expOverride
    : Math.floor(Date.now() / 1000) + 3;
  const macInput = `${payload}.${exp}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return { payload, mac, exp };
};

const buildPowModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-chain-"));
  const tmpPath = join(tmpDir, "pow.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const buildConfigModule = async (secret = "config-secret", options = {}) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powConfigSource = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const gluePadding = options.longGlue ? "x".repeat(12000) : "";
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: false,
        turncheck: false,
        POW_BIND_TLS: false,
        POW_BIND_COUNTRY: false,
        POW_BIND_ASN: false,
        POW_GLUE_URL: `https://example.com/glue${gluePadding}`,
      },
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-chain-"));
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

test("pow-config -> pow.js strips inner headers before origin fetch", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const configPath = await buildConfigModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return powHandler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const clientIp = "1.2.3.4";
    const res = await configHandler(
      new Request("https://example.com/protected", {
        headers: {
          "CF-Connecting-IP": clientIp,
        },
      })
    );
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to pow.js");
    const innerPayload = innerRequest.headers.get("X-Pow-Inner");
    const innerCount = innerRequest.headers.get("X-Pow-Inner-Count");
    assert.ok(innerPayload || innerCount, "inner header set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Mac"), "inner mac set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Expire"), "inner expire set");
    assert.equal(innerRequest.headers.get("CF-Connecting-IP"), clientIp);
    assert.ok(originRequest, "origin fetch called");
    assert.equal(originRequest.headers.get("X-Pow-Inner"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Mac"), null);
    assert.equal(originRequest.headers.get("X-Pow-Inner-Expire"), null);
    assert.equal(originRequest.headers.get("CF-Connecting-IP"), clientIp);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config -> pow.js strips chunked inner headers", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const configPath = await buildConfigModule("config-secret", { longGlue: true });
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return powHandler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const res = await configHandler(new Request("https://example.com/protected"));
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to pow.js");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Count"), "chunked headers set");
    assert.ok(innerRequest.headers.get("X-Pow-Inner-Expire"), "inner expire set");
    assert.equal(innerRequest.headers.get("X-Pow-Inner"), null);
    assert.ok(originRequest, "origin fetch called");
    for (const key of originRequest.headers.keys()) {
      assert.ok(!key.toLowerCase().startsWith("x-pow-inner"), `origin strips ${key}`);
    }
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow-config strips atomic query/header before pow.js handoff", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const configPath = await buildConfigModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;
  const configHandler = configMod.default.fetch;

  let innerRequest = null;
  let originRequest = null;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Inner") || request.headers.has("X-Pow-Inner-Count")) {
        innerRequest = request;
        return powHandler(request);
      }
      originRequest = request;
      return new Response("ok", { status: 200 });
    };

    const res = await configHandler(
      new Request("https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1&keep=1", {
        headers: {
          "x-turnstile": "h-turn",
          "x-ticket": "h-ticket",
          "x-consume": "1",
        },
      })
    );
    assert.equal(res.status, 200);
    assert.ok(innerRequest, "pow-config forwards to pow.js");
    assert.equal(innerRequest.headers.get("x-turnstile"), null);
    assert.equal(innerRequest.headers.get("x-ticket"), null);
    assert.equal(innerRequest.headers.get("x-consume"), null);
    const innerUrl = new URL(innerRequest.url);
    assert.equal(innerUrl.searchParams.get("__ts"), null);
    assert.equal(innerUrl.searchParams.get("__tt"), null);
    assert.equal(innerUrl.searchParams.get("__ct"), null);
    assert.equal(innerUrl.searchParams.get("keep"), "1");
    assert.ok(originRequest, "origin fetch called");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("pow.js consumes atomic only from inner.s (no request fallback)", async () => {
  const restoreGlobals = ensureGlobals();
  const powPath = await buildPowModule();
  const powMod = await import(`${pathToFileURL(powPath).href}?v=${Date.now()}`);
  const powHandler = powMod.default.fetch;

  const config = {
    powcheck: false,
    turncheck: true,
    bindPathMode: "none",
    bindPathQueryName: "path",
    bindPathHeaderName: "",
    stripBindPathHeader: false,
    POW_VERSION: 3,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 8192,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 1,
    POW_MAX_STEPS: 8192,
    POW_HASHCASH_BITS: 0,
    POW_SEGMENT_LEN: 32,
    POW_SAMPLE_K: 1,
    POW_SPINE_K: 0,
    POW_CHAL_ROUNDS: 1,
    POW_OPEN_BATCH: 1,
    POW_FORCE_EDGE_1: true,
    POW_FORCE_EDGE_LAST: true,
    POW_COMMIT_TTL_SEC: 120,
    POW_TICKET_TTL_SEC: 600,
    PROOF_TTL_SEC: 600,
    PROOF_RENEW_ENABLE: false,
    PROOF_RENEW_MAX: 2,
    PROOF_RENEW_WINDOW_SEC: 90,
    PROOF_RENEW_MIN_SEC: 30,
    ATOMIC_CONSUME: true,
    ATOMIC_TURN_QUERY: "__ts",
    ATOMIC_TICKET_QUERY: "__tt",
    ATOMIC_CONSUME_QUERY: "__ct",
    ATOMIC_TURN_HEADER: "x-turnstile",
    ATOMIC_TICKET_HEADER: "x-ticket",
    ATOMIC_CONSUME_HEADER: "x-consume",
    ATOMIC_COOKIE_NAME: "__Secure-pow_a",
    STRIP_ATOMIC_QUERY: true,
    STRIP_ATOMIC_HEADERS: true,
    INNER_AUTH_QUERY_NAME: "",
    INNER_AUTH_QUERY_VALUE: "",
    INNER_AUTH_HEADER_NAME: "",
    INNER_AUTH_HEADER_VALUE: "",
    stripInnerAuthQuery: false,
    stripInnerAuthHeader: false,
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    POW_TOKEN: "pow-secret",
    TURNSTILE_SITEKEY: "sitekey",
    TURNSTILE_SECRET: "turn-secret",
    POW_COMMIT_COOKIE: "__Host-pow_commit",
    POW_ESM_URL: "https://example.com/esm",
    POW_GLUE_URL: "https://example.com/glue",
  };

  const { payload, mac, exp } = buildInnerHeaders(
    {
      v: 1,
      id: 7,
      c: config,
      d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
      s: {
        nav: {},
        bypass: { bypass: false },
        bind: { ok: true, code: "", canonicalPath: "/protected" },
        atomic: {
          turnToken: "",
          ticketB64: "",
          consumeToken: "",
          fromCookie: false,
          cookieName: "__Secure-pow_a",
        },
      },
    },
    "config-secret"
  );

  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const res = await powHandler(
      new Request("https://example.com/protected?__ts=q-turn&__tt=q-ticket&__ct=1", {
        headers: {
          Accept: "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          "x-turnstile": "header-turn-token",
          "x-ticket": "header-ticket",
          "x-consume": "1",
          Cookie: "__Secure-pow_a=1%7Ct%7Ccookie-turn%7Ccookie-ticket",
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": String(exp),
        },
      })
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "turn_required" });
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
