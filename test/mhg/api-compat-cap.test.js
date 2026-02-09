import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const CONFIG_SECRET = "config-secret";

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildPowModule = async (secret = CONFIG_SECRET) => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-mhg-cap-test-"));
  const tmpPath = join(tmpDir, "pow-cap-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const makeInnerPayload = ({ powcheck, atomic, recaptchaEnabled, providers = "" }) => ({
  v: 1,
  id: 11,
  c: {
    POW_TOKEN: "pow-secret",
    powcheck,
    turncheck: false,
    recaptchaEnabled,
    providers,
    RECAPTCHA_ACTION: "submit",
    RECAPTCHA_MIN_SCORE: 0.5,
    RECAPTCHA_PAIRS: [{ sitekey: "site", secret: "recaptcha-secret" }],
    POW_VERSION: 3,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 16,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 4,
    POW_MAX_STEPS: 8,
    POW_CHAL_ROUNDS: 2,
    POW_SAMPLE_K: 2,
    POW_OPEN_BATCH: 2,
    POW_HASHCASH_BITS: 0,
    POW_SEGMENT_LEN: 2,
    POW_COMMIT_TTL_SEC: 120,
    POW_TICKET_TTL_SEC: 180,
    POW_COMMIT_COOKIE: "__Host-pow_commit",
    POW_BIND_PATH: true,
    POW_BIND_IPRANGE: true,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_BIND_TLS: false,
    PROOF_TTL_SEC: 300,
    ATOMIC_CONSUME: atomic,
    ATOMIC_TURN_QUERY: "__ts",
    ATOMIC_TICKET_QUERY: "__tt",
    ATOMIC_CONSUME_QUERY: "__ct",
    ATOMIC_TURN_HEADER: "x-turnstile",
    ATOMIC_TICKET_HEADER: "x-ticket",
    ATOMIC_CONSUME_HEADER: "x-consume",
    ATOMIC_COOKIE_NAME: "__Secure-pow_a",
    POW_ESM_URL: "https://cdn.example/esm.js",
    POW_GLUE_URL: "https://cdn.example/glue.js",
  },
  d: {
    ipScope: "1.2.3.4/32",
    country: "",
    asn: "",
    tlsFingerprint: "",
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
      cookieName: "",
      turnstilePreflight: null,
    },
  },
});

const makeInnerHeaders = (payloadObj, secret = CONFIG_SECRET, expireOffsetSec = 2) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + expireOffsetSec;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
  };
};

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return { ticketB64: match[3], pathHash: match[4] };
};

const makeCapRequest = async (handler, payload, captchaToken) => {
  const challengePage = await handler(
    new Request("https://example.com/protected", {
      method: "GET",
      headers: {
        ...makeInnerHeaders(payload),
        Accept: "text/html",
        "CF-Connecting-IP": "1.2.3.4",
      },
    }),
    {},
    {}
  );
  assert.equal(challengePage.status, 200);
  const args = extractChallengeArgs(await challengePage.text());
  assert.ok(args);
  return new Request("https://example.com/__pow/cap", {
    method: "POST",
    headers: {
      ...makeInnerHeaders(payload),
      "Content-Type": "application/json",
      "CF-Connecting-IP": "1.2.3.4",
    },
    body: JSON.stringify({
      ticketB64: args.ticketB64,
      pathHash: args.pathHash,
      captchaToken,
    }),
  });
};

test("/cap keeps cap-only/combined/malformed semantics", async () => {
  const restoreGlobals = ensureGlobals();
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.url;
    if (String(url).includes("www.google.com/recaptcha/api/siteverify")) {
      return new Response(
        JSON.stringify({
          success: true,
          hostname: "example.com",
          remoteip: "1.2.3.4",
          action: "submit",
          score: 0.9,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    throw new Error("unexpected outbound fetch in test");
  };

  try {
    const capOnlyPayload = makeInnerPayload({
      powcheck: false,
      atomic: false,
      recaptchaEnabled: false,
      providers: "recaptcha",
    });
    const capOnlyReq = await makeCapRequest(mod.default.fetch, capOnlyPayload, {
      recaptcha_v3: "r".repeat(64),
    });
    const capOnlyRes = await mod.default.fetch(capOnlyReq, {}, {});
    assert.equal(capOnlyRes.status, 200);
    assert.match(String(capOnlyRes.headers.get("set-cookie") || ""), /__Host-proof=/u);

    const combinedPayload = makeInnerPayload({ powcheck: true, atomic: false, recaptchaEnabled: true });
    const combinedReq = await makeCapRequest(mod.default.fetch, combinedPayload, {
      recaptcha_v3: "r".repeat(64),
    });
    const combinedRes = await mod.default.fetch(combinedReq, {}, {});
    assert.equal(combinedRes.status, 404);

    const malformedPayload = makeInnerPayload({ powcheck: false, atomic: false, recaptchaEnabled: true });
    const malformedReq = await makeCapRequest(mod.default.fetch, malformedPayload, { recaptcha_v3: 1 });
    const malformedRes = await mod.default.fetch(malformedReq, {}, {});
    assert.equal(malformedRes.status, 400);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
