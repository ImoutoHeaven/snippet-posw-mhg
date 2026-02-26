import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { __testNormalizeConfig } from "../pow-config.js";
import { createPowRuntimeFixture } from "./helpers/pow-runtime-fixture.js";

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

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const FULL_CONFIG = {
  powcheck: false,
  turncheck: false,
  bindPathMode: "none",
  bindPathQueryName: "path",
  bindPathHeaderName: "",
  stripBindPathHeader: false,
  POW_VERSION: 3,
  POW_API_PREFIX: "/__pow",
  POW_DIFFICULTY_BASE: 8192,
  POW_DIFFICULTY_COEFF: 1.0,
  POW_MIN_STEPS: 512,
  POW_MAX_STEPS: 8192,
  POW_HASHCASH_BITS: 3,
  POW_PAGE_BYTES: 16384,
  POW_MIX_ROUNDS: 2,
  POW_SEGMENT_LEN: 2,
  POW_SAMPLE_RATE: 0.01,
  POW_OPEN_BATCH: 15,
  POW_COMMIT_TTL_SEC: 120,
  POW_MAX_GEN_TIME_SEC: 300,
  POW_TICKET_TTL_SEC: 600,
  PROOF_TTL_SEC: 600,
  PROOF_RENEW_ENABLE: false,
  PROOF_RENEW_MAX: 2,
  PROOF_RENEW_WINDOW_SEC: 90,
  PROOF_RENEW_MIN_SEC: 30,
  ATOMIC_CONSUME: false,
  AGGREGATOR_POW_ATOMIC_CONSUME: false,
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
  POW_BIND_TLS: true,
  IPV4_PREFIX: 32,
  IPV6_PREFIX: 64,
  POW_COMMIT_COOKIE: "__Host-pow_commit",
  POW_ESM_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/esm/esm.js",
  POW_GLUE_URL:
    "https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@412f7fcc71c319b62a614e4252280f2bb3d7302b/glue.js",
};

const FULL_STRATEGY = {
  nav: {},
  bypass: { bypass: false },
  bind: { ok: true, code: "", canonicalPath: "/path" },
  atomic: {
    captchaToken: "",
    ticketB64: "",
    consumeToken: "",
    fromCookie: false,
    cookieName: "__Secure-pow_a",
  },
};

const LEGACY_SAMPLE_K = ["POW", "SAMPLE", "K"].join("_");
const LEGACY_CHAL_ROUNDS = ["POW", "CHAL", "ROUNDS"].join("_");

test("normalizeConfig includes siteverify aggregator keys", () => {
  const cfg = __testNormalizeConfig({});
  assert.equal("SITEVERIFY_URL" in cfg, false);
  assert.equal(Array.isArray(cfg.SITEVERIFY_URLS), true);
  assert.equal(typeof cfg.SITEVERIFY_AUTH_KID, "string");
  assert.equal(typeof cfg.SITEVERIFY_AUTH_SECRET, "string");
});

test("normalizeConfig keeps valid siteverify aggregator URL shards", () => {
  const cfg = __testNormalizeConfig({
    SITEVERIFY_URLS: [
      "https://sv-1.example/siteverify",
      "  https://sv-2.example/siteverify  ",
      "",
      null,
      123,
    ],
  });

  assert.equal("SITEVERIFY_URL" in cfg, false);
  assert.deepEqual(cfg.SITEVERIFY_URLS, [
    "https://sv-1.example/siteverify",
    "https://sv-2.example/siteverify",
  ]);
});

test("normalizeConfig exposes turnstile-only captcha surface", () => {
  const cfg = __testNormalizeConfig({});
  assert.equal("recaptchaEnabled" in cfg, false);
  assert.equal("RECAPTCHA_PAIRS" in cfg, false);
  assert.equal("RECAPTCHA_ACTION" in cfg, false);
  assert.equal("RECAPTCHA_MIN_SCORE" in cfg, false);
  assert.equal(cfg.AGGREGATOR_POW_ATOMIC_CONSUME, false);
});

test("normalizeConfig hard-cuts POW_VERSION to 4 regardless input", () => {
  const cases = [undefined, 3, 4, 5, "3", "4", "9", -1, 100, "oops"];
  for (const value of cases) {
    const cfg = __testNormalizeConfig({ POW_VERSION: value });
    assert.equal(cfg.POW_VERSION, 4);
  }
});

test("normalizeConfig clamps POW_SEGMENT_LEN fixed values to 2..16", () => {
  assert.equal(__testNormalizeConfig({ POW_SEGMENT_LEN: 1 }).POW_SEGMENT_LEN, 2);
  assert.equal(__testNormalizeConfig({ POW_SEGMENT_LEN: 2 }).POW_SEGMENT_LEN, 2);
  assert.equal(__testNormalizeConfig({ POW_SEGMENT_LEN: 16 }).POW_SEGMENT_LEN, 16);
  assert.equal(__testNormalizeConfig({ POW_SEGMENT_LEN: 32 }).POW_SEGMENT_LEN, 16);
  assert.equal(__testNormalizeConfig({ POW_SEGMENT_LEN: "1" }).POW_SEGMENT_LEN, 2);
});

test("normalizeConfig never emits segment length 1", () => {
  const numeric = __testNormalizeConfig({ POW_SEGMENT_LEN: 1 }).POW_SEGMENT_LEN;
  const numericString = __testNormalizeConfig({ POW_SEGMENT_LEN: "1" }).POW_SEGMENT_LEN;
  const range = __testNormalizeConfig({ POW_SEGMENT_LEN: "1-1" }).POW_SEGMENT_LEN;
  assert.notEqual(numeric, 1);
  assert.notEqual(numericString, 1);
  assert.notEqual(range, "1-1");
  assert.equal(range, "2-2");
});

test("normalizeConfig removes legacy sampling knobs", () => {
  const cfgDefault = __testNormalizeConfig({});
  assert.equal(LEGACY_SAMPLE_K in cfgDefault, false);
  assert.equal(LEGACY_CHAL_ROUNDS in cfgDefault, false);
  assert.equal(typeof cfgDefault.POW_SAMPLE_RATE, "number");

  const cfgLegacyInput = __testNormalizeConfig({
    [LEGACY_SAMPLE_K]: 7,
    [LEGACY_CHAL_ROUNDS]: 3,
  });
  assert.equal(LEGACY_SAMPLE_K in cfgLegacyInput, false);
  assert.equal(LEGACY_CHAL_ROUNDS in cfgLegacyInput, false);
  assert.equal(typeof cfgLegacyInput.POW_SAMPLE_RATE, "number");
});

test("normalizeConfig clamps POW_SAMPLE_RATE into (0,1] with fallback", () => {
  assert.equal(__testNormalizeConfig({ POW_SAMPLE_RATE: 0.25 }).POW_SAMPLE_RATE, 0.25);
  assert.equal(__testNormalizeConfig({ POW_SAMPLE_RATE: 1.2 }).POW_SAMPLE_RATE, 1);
  assert.equal(__testNormalizeConfig({ POW_SAMPLE_RATE: 0 }).POW_SAMPLE_RATE, 0.01);
  assert.equal(__testNormalizeConfig({ POW_SAMPLE_RATE: -3 }).POW_SAMPLE_RATE, 0.01);
  assert.equal(__testNormalizeConfig({ POW_SAMPLE_RATE: "oops" }).POW_SAMPLE_RATE, 0.01);
});

test("normalizeConfig keeps POW_OPEN_BATCH clamp up to 256", () => {
  assert.equal(__testNormalizeConfig({ POW_OPEN_BATCH: 999 }).POW_OPEN_BATCH, 256);
});

const buildInnerHeaders = (payloadObj, secret, expOverride) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Number.isFinite(expOverride)
    ? expOverride
    : Math.floor(Date.now() / 1000) + 3;
  const macInput = `${payload}.${exp}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return { payload, mac, exp };
};

const readPowSource = async (fileName) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  try {
    return await readFile(join(repoRoot, "lib", "pow", fileName), "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return "";
    throw error;
  }
};

const buildTestModule = async (secret = "config-secret") => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret,
    tmpPrefix: "pow-split-test-",
  });

  const secretLiteral = JSON.stringify(secret);
const bridgeSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";
import { issueTransit } from "./lib/pow/transit-auth.js";

const CONFIG_SECRET = ${secretLiteral};
const API_PREFIX = "/__pow";

const apiAction = (pathname) => {
  const normalized = typeof pathname === "string" ? pathname : "/";
  if (!normalized.startsWith(API_PREFIX + "/")) return "";
  const suffix = normalized.slice(API_PREFIX.length + 1);
  return suffix.split("/")[0] || "";
};

const handledByCore1 = (action) =>
  action === "commit" || action === "cap" || action === "challenge";

const stripPowHeaders = (request) => {
  const headers = new Headers(request.headers);
  for (const key of Array.from(headers.keys())) {
    const lower = key.toLowerCase();
    if (lower.startsWith("x-pow-inner") || lower.startsWith("x-pow-transit")) {
      headers.delete(key);
    }
  }
  return new Request(request, { headers });
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const action = apiAction(url.pathname);
    if (handledByCore1(action)) {
      return core1.fetch(request, env, ctx);
    }
    if (action === "open") {
      const transit = await issueTransit({
        secret: CONFIG_SECRET,
        method: request.method,
        pathname: url.pathname,
        kind: "api",
        apiPrefix: API_PREFIX,
      });
      if (!transit) return new Response(null, { status: 500 });
      const headers = new Headers(request.headers);
      for (const [key, value] of Object.entries(transit.headers)) headers.set(key, value);
      return core2.fetch(new Request(request, { headers }), env, ctx);
    }

    const upstreamFetch = globalThis.fetch;
    try {
      globalThis.fetch = async (input, init) => {
        const req = input instanceof Request ? input : new Request(input, init);
        if (req.headers.has("X-Pow-Transit")) {
          return core2.fetch(req, env, ctx);
        }
        if (typeof upstreamFetch === "function") return upstreamFetch(stripPowHeaders(req), init);
        return new Response(null, { status: 500 });
      };
      return await core1.fetch(request, env, ctx);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};
`;
  await writeFile(join(tmpDir, "pow-test.js"), bridgeSource);

  return join(tmpDir, "pow-test.js");
};

test("split core bridge fails closed without inner header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });

    const res = await handler(new Request("https://example.com/protected"));
    assert.equal(res.status, 500);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge rejects placeholder CONFIG_SECRET", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule("replace-me");
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "replace-me"
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("valid inner header passes through", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "config-secret"
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 200);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge rejects expired inner header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const now = Math.floor(Date.now() / 1000);
    const expiredExp = now - 10;
    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "config-secret",
      expiredExp
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge rejects future inner header", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const now = Math.floor(Date.now() / 1000);
    const futureExp = now + 10;
    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: FULL_STRATEGY,
      },
      "config-secret",
      futureExp
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge fails closed when inner strategy snapshot is missing", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
      },
      "config-secret"
    );

    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge fails closed when inner strategy is malformed", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          ...FULL_STRATEGY,
          bind: { ok: "true", code: "", canonicalPath: "/path" },
        },
      },
      "config-secret"
    );

    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 500);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge fail-closes bind missing/invalid from inner.s with 400", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    for (const code of ["missing", "invalid"]) {
      const { payload, mac, exp } = buildInnerHeaders(
        {
          v: 1,
          id: 0,
          c: { ...FULL_CONFIG, powcheck: true, POW_BIND_TLS: false, POW_TOKEN: "test" },
          d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
          s: {
            ...FULL_STRATEGY,
            bind: { ok: false, code, canonicalPath: "/path" },
          },
        },
        "config-secret"
      );

      const res = await handler(
        new Request("https://no-match.test/path", {
          headers: {
            "X-Pow-Inner": payload,
            "X-Pow-Inner-Mac": mac,
            "X-Pow-Inner-Expire": exp.toString(10),
          },
        })
      );
      assert.equal(res.status, 400);
    }

    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core bridge bypasses directly when inner.s.bypass.bypass is true", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  let calls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      return new Response("ok", { status: 200 });
    };

    const { payload, mac, exp } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { ...FULL_CONFIG, powcheck: true, POW_BIND_TLS: false, POW_TOKEN: "test" },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
        s: {
          ...FULL_STRATEGY,
          bypass: { bypass: true },
          bind: { ok: false, code: "missing", canonicalPath: "/path" },
        },
      },
      "config-secret"
    );

    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
          "X-Pow-Inner-Expire": exp.toString(10),
        },
      })
    );
    assert.equal(res.status, 200);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("requiredMask only uses pow+turn bits", async () => {
  const core1FrontSource = await readPowSource("api-core1-front.js");
  assert.match(core1FrontSource, /const requiredMask = \(needPow \? 1 : 0\) \| \(needTurn \? 2 : 0\);/u);
  assert.doesNotMatch(core1FrontSource, /needRecaptcha/u);
  assert.doesNotMatch(core1FrontSource, /const providersRaw = typeof config\.providers === "string"/u);
});

test("core2 api engine is open-only while core1-front owns cap", async () => {
  const apiEngineSource = await readPowSource("api-engine.js");
  const core1FrontSource = await readPowSource("api-core1-front.js");

  assert.match(apiEngineSource, /if \(action === "\/open"\)/u);
  assert.doesNotMatch(apiEngineSource, /if \(action === "\/commit"\)/u);
  assert.doesNotMatch(apiEngineSource, /if \(action === "\/challenge"\)/u);
  assert.doesNotMatch(apiEngineSource, /if \(action === "\/cap"\)/u);
  assert.doesNotMatch(apiEngineSource, /const handlePowCommit = async \(/u);
  assert.doesNotMatch(apiEngineSource, /const handlePowChallenge = async \(/u);
  assert.doesNotMatch(apiEngineSource, /const handleCap = async \(/u);

  assert.match(core1FrontSource, /const handleCap = async \(/u);
  assert.match(core1FrontSource, /const requiredMask = \(needPow \? 1 : 0\) \| \(needTurn \? 2 : 0\);/u);
  assert.match(core1FrontSource, /if \(needPow \|\| !needTurn \|\| config\.ATOMIC_CONSUME === true\) return S\(404\);/u);
  assert.match(core1FrontSource, /await issueProofCookie\([\s\S]*requiredMask/u);
  assert.doesNotMatch(
    core1FrontSource,
    /const handleCap = async \([\s\S]*?await issueProofCookie\([\s\S]*?\n\s*2\s*\n\s*\);/u
  );
});

test("mask enforcement keeps bitwise AND semantics", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const businessGateSource = await readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8");
  assert.match(businessGateSource, /if \(\(parsed\.m & requiredMask\) !== requiredMask\) return null;/u);
  assert.match(businessGateSource, /if \(\(proof\.m & requiredMask\) !== requiredMask\) return null;/u);
});
