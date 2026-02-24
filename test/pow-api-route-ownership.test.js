import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "./helpers/pow-runtime-fixture.js";

const TEST_SECRET = "config-secret";

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

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const buildInnerHeaders = ({ secret = TEST_SECRET, apiPrefix = "/__pow" } = {}) => {
  const exp = Math.floor(Date.now() / 1000) + 3;
  const payloadObj = {
    v: 1,
    id: 1,
    c: {
      POW_API_PREFIX: normalizeApiPrefix(apiPrefix),
      POW_TOKEN: "pow-secret",
      POW_VERSION: 3,
      POW_COMMIT_COOKIE: "__Host-pow_commit",
      POW_OPEN_BATCH: 1,
      POW_CHAL_ROUNDS: 1,
      POW_SAMPLE_K: 0,
      POW_SEGMENT_LEN: 1,
      POW_PAGE_BYTES: 64,
      POW_MIX_ROUNDS: 2,
      POW_HASHCASH_BITS: 0,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      POW_COMMIT_TTL_SEC: 120,
      POW_TICKET_TTL_SEC: 600,
      PROOF_TTL_SEC: 600,
      powcheck: true,
      turncheck: true,
      TURNSTILE_SECRET: "turn-secret",
    },
    d: { ipScope: "1.2.3.4/32", country: "any", asn: "any", tlsFingerprint: "any" },
    s: {
      nav: {},
      bypass: { bypass: false },
      bind: { ok: true, code: "", canonicalPath: "/protected" },
      atomic: { captchaToken: "", ticketB64: "", consumeToken: "", fromCookie: false, cookieName: "" },
    },
  };
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
  };
};

const makeTransitMac = ({ secret, exp, kind, method, pathname, apiPrefix }) => {
  const macInput = `v1|${exp}|${kind}|${method.toUpperCase()}|${pathname}|${normalizeApiPrefix(apiPrefix)}`;
  return base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
};

const buildTransitHeaders = ({
  secret = TEST_SECRET,
  kind = "api",
  method,
  pathname,
  apiPrefix = "/__pow",
  exp = Math.floor(Date.now() / 1000) + 3,
  tamperedMac = false,
}) => {
  const mac = makeTransitMac({ secret, exp, kind, method, pathname, apiPrefix });
  const transitMac = tamperedMac ? `${mac.slice(0, -1)}${mac.endsWith("A") ? "B" : "A"}` : mac;
  return {
    "X-Pow-Transit": kind,
    "X-Pow-Transit-Mac": transitMac,
    "X-Pow-Transit-Expire": String(exp),
    "X-Pow-Transit-Api-Prefix": normalizeApiPrefix(apiPrefix),
  };
};

const buildCoreModules = async () => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret: TEST_SECRET,
    tmpPrefix: "pow-route-ownership-",
  });
  const nonce = `${Date.now()}-${Math.random()}`;
  const [core1Module, core2Module] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${nonce}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${nonce}`),
  ]);
  return { core1Fetch: core1Module.default.fetch, core2Fetch: core2Module.default.fetch };
};

test("core1 keeps /commit,/cap,/challenge local and only transits /open", async () => {
  const restoreGlobals = ensureGlobals();
  const { core1Fetch } = await buildCoreModules();
  const originalFetch = globalThis.fetch;
  const downstream = [];

  try {
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      downstream.push(request);
      return new Response("downstream", { status: 599 });
    };

    const innerHeaders = buildInnerHeaders();
    for (const action of ["commit", "cap", "challenge"]) {
      downstream.length = 0;
      const response = await core1Fetch(
        new Request(`https://example.com/__pow/${action}`, {
          method: "POST",
          headers: innerHeaders,
          body: JSON.stringify({}),
        })
      );
      assert.notEqual(response.status, 599, `core1 must not transit /${action}`);
      assert.equal(downstream.length, 0, `core1 must keep /${action} local`);
    }

    downstream.length = 0;
    const openResponse = await core1Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: innerHeaders,
        body: JSON.stringify({}),
      })
    );
    assert.equal(downstream.length, 1, "core1 must transit /open exactly once");
    assert.equal(openResponse.status, 599);
    assert.equal(downstream[0].headers.get("X-Pow-Transit"), "api");
    assert.ok(downstream[0].headers.get("X-Pow-Transit-Mac"));
    assert.ok(downstream[0].headers.get("X-Pow-Transit-Expire"));
    assert.equal(downstream[0].headers.get("X-Pow-Transit-Api-Prefix"), "/__pow");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 hard-cutoff returns 404 for removed actions for all methods", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2Fetch } = await buildCoreModules();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;
  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };

    for (const method of ["GET", "POST"]) {
      for (const action of ["commit", "cap", "challenge"]) {
        const response = await core2Fetch(
          new Request(`https://example.com/__pow/${action}`, {
            method,
            headers: buildInnerHeaders(),
          })
        );
        assert.equal(response.status, 404, `core2 must 404 ${method} /${action}`);
      }
    }

    for (const method of ["GET", "POST"]) {
      const response = await core2Fetch(
        new Request("https://example.com/__pow/unknown", {
          method,
          headers: buildInnerHeaders(),
        })
      );
      assert.equal(response.status, 404, `core2 must 404 ${method} /unknown`);
    }

    assert.equal(originCalls, 0, "removed or unknown core2 actions must not reach origin");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 /open keeps method semantics and transit trust boundaries", async () => {
  const restoreGlobals = ensureGlobals();
  const { core2Fetch } = await buildCoreModules();
  const originalFetch = globalThis.fetch;
  let originCalls = 0;

  try {
    globalThis.fetch = async () => {
      originCalls += 1;
      return new Response("origin", { status: 200 });
    };

    const method405 = await core2Fetch(
      new Request("https://example.com/__pow/open", {
        method: "GET",
        headers: {
          ...buildInnerHeaders(),
          ...buildTransitHeaders({ method: "GET", pathname: "/__pow/open" }),
        },
      })
    );
    assert.equal(method405.status, 405);

    const openPost = await core2Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...buildInnerHeaders(),
          ...buildTransitHeaders({ method: "POST", pathname: "/__pow/open" }),
        },
        body: JSON.stringify({}),
      })
    );
    assert.notEqual(openPost.status, 405);

    const noTransit = await core2Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: buildInnerHeaders(),
        body: JSON.stringify({}),
      })
    );
    assert.equal(noTransit.status, 500);

    const tamperedMac = await core2Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...buildInnerHeaders(),
          ...buildTransitHeaders({ method: "POST", pathname: "/__pow/open", tamperedMac: true }),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(tamperedMac.status, 500);

    const expiredTransit = await core2Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...buildInnerHeaders(),
          ...buildTransitHeaders({
            method: "POST",
            pathname: "/__pow/open",
            exp: Math.floor(Date.now() / 1000) - 1,
          }),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(expiredTransit.status, 500);

    const wrongKind = await core2Fetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...buildInnerHeaders(),
          ...buildTransitHeaders({ method: "POST", pathname: "/__pow/open", kind: "biz" }),
        },
        body: JSON.stringify({}),
      })
    );
    assert.equal(wrongKind.status, 500);
    assert.equal(originCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("core2 source excludes removed handlers and routes", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const source = await readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");

  assert.doesNotMatch(source, /const handlePowCommit = async \(/u);
  assert.doesNotMatch(source, /const handleCap = async \(/u);
  assert.doesNotMatch(source, /const handlePowChallenge = async \(/u);
  assert.doesNotMatch(source, /action === "\/commit"/u);
  assert.doesNotMatch(source, /action === "\/cap"/u);
  assert.doesNotMatch(source, /action === "\/challenge"/u);
  assert.match(source, /action === "\/open"/u);
});

test("segment spec clamps use hard minimum 2 across pow entrypoints", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [businessGateSource, frontSource, engineSource] = await Promise.all([
    readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-core1-front.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
  ]);

  for (const source of [businessGateSource, frontSource, engineSource]) {
    assert.match(source, /clampInt\(raw,\s*2,\s*16\)/u);
    assert.match(source, /clampInt\(match\[1\],\s*2,\s*16\)/u);
    assert.match(source, /clampInt\(match\[2\],\s*2,\s*16\)/u);
  }
});
