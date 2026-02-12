import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
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

const buildCore1Module = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [
    core1SourceRaw,
    core2SourceRaw,
    transitSource,
    innerAuthSource,
    internalHeadersSource,
    apiEngineSource,
    siteverifyClientSource,
    businessGateSource,
    templateSource,
    mhgGraphSource,
    mhgHashSource,
    mhgMixSource,
    mhgMerkleSource,
    mhgVerifySource,
    mhgConstantsSource,
  ] = await Promise.all([
    readFile(join(repoRoot, "pow-core-1.js"), "utf8"),
    readFile(join(repoRoot, "pow-core-2.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "transit-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "inner-auth.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "internal-headers.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "siteverify-client.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8"),
    readFile(join(repoRoot, "template.html"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "graph.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "hash.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "mix-aes.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "merkle.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "verify.js"), "utf8"),
    readFile(join(repoRoot, "lib", "mhg", "constants.js"), "utf8"),
  ]);

  const core1Source = replaceConfigSecret(core1SourceRaw, secret);
  const core2Source = replaceConfigSecret(core2SourceRaw, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-provider-test-"));
  await mkdir(join(tmpDir, "lib", "pow"), { recursive: true });
  await mkdir(join(tmpDir, "lib", "mhg"), { recursive: true });
  const businessGateInjected = businessGateSource
    .replace(
    /__HTML_TEMPLATE__/gu,
    JSON.stringify(templateSource)
    )
    .concat(
      "\nexport const __captchaTesting = { pickRecaptchaPair, captchaTagV1, verifyRequiredCaptchaForTicket };\n"
    );
  const writes = [
    writeFile(join(tmpDir, "pow-core-1.js"), core1Source),
    writeFile(join(tmpDir, "pow-core-2.js"), core2Source),
    writeFile(join(tmpDir, "lib", "pow", "transit-auth.js"), transitSource),
    writeFile(join(tmpDir, "lib", "pow", "inner-auth.js"), innerAuthSource),
    writeFile(join(tmpDir, "lib", "pow", "internal-headers.js"), internalHeadersSource),
    writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineSource),
    writeFile(join(tmpDir, "lib", "pow", "siteverify-client.js"), siteverifyClientSource),
    writeFile(join(tmpDir, "lib", "pow", "business-gate.js"), businessGateInjected),
    writeFile(join(tmpDir, "lib", "mhg", "graph.js"), mhgGraphSource),
    writeFile(join(tmpDir, "lib", "mhg", "hash.js"), mhgHashSource),
    writeFile(join(tmpDir, "lib", "mhg", "mix-aes.js"), mhgMixSource),
    writeFile(join(tmpDir, "lib", "mhg", "merkle.js"), mhgMerkleSource),
    writeFile(join(tmpDir, "lib", "mhg", "verify.js"), mhgVerifySource),
    writeFile(join(tmpDir, "lib", "mhg", "constants.js"), mhgConstantsSource),
  ];

  const harnessSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";
import * as businessGate from "./lib/pow/business-gate.js";

const toRequest = (input, init) =>
  input instanceof Request ? input : new Request(input, init);

const isTransitRequest = (request) =>
  request.headers.has("X-Pow-Transit");

export default {
  async fetch(request) {
    const upstreamFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const nextRequest = toRequest(input, init);
      if (isTransitRequest(nextRequest)) {
        return core2.fetch(nextRequest);
      }
      return upstreamFetch(input, init);
    };
    try {
      return await core1.fetch(request);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  },
};

export const __captchaTesting = {
  pickRecaptchaPair: businessGate.__captchaTesting.pickRecaptchaPair,
  captchaTagV1: businessGate.__captchaTesting.captchaTagV1,
  verifyRequiredCaptchaForTicket: businessGate.__captchaTesting.verifyRequiredCaptchaForTicket,
};
`;
  const tmpPath = join(tmpDir, "pow-provider-test.js");
  writes.push(writeFile(tmpPath, harnessSource));

  await Promise.all(writes);
  return tmpPath;
};

const loadTestingApi = async () => {
  const modulePath = await buildCore1Module();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  assert.equal(typeof mod.default?.fetch, "function");
  return mod.__captchaTesting;
};

test("deterministically selects recaptcha pair from ticket.mac", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    const pairs = [
      { sitekey: "rk-1", secret: "rs-1" },
      { sitekey: "rk-2", secret: "rs-2" },
      { sitekey: "rk-3", secret: "rs-3" },
    ];

    const first = await testing.pickRecaptchaPair("ticket-mac-1", pairs);
    const second = await testing.pickRecaptchaPair("ticket-mac-1", pairs);
    assert.equal(first.kid, second.kid);
    assert.deepEqual(first.pair, second.pair);
    assert.ok(first.kid >= 0 && first.kid < pairs.length);
  } finally {
    restoreGlobals();
  }
});

test("captcha testing API does not expose recaptcha action derivation helper", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    assert.equal("makeRecaptchaAction" in testing, false);
  } finally {
    restoreGlobals();
  }
});

test("captchaTag(v1) binds turnstile and recaptcha tokens", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    const turn = "turn-token-1234567890";
    const recaptcha = "recaptcha-token-1234567890";
    const dual = await testing.captchaTagV1(turn, recaptcha);
    const onlyTurn = await testing.captchaTagV1(turn, "");
    const onlyRecaptcha = await testing.captchaTagV1("", recaptcha);

    const expected = Buffer.from(
      await crypto.webcrypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`ctag|v1|t=${turn}|r=${recaptcha}`)
      )
    )
      .subarray(0, 12)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/u, "");

    assert.equal(dual, expected);
    assert.match(dual, /^[A-Za-z0-9_-]{16}$/u);
    assert.notEqual(dual, onlyTurn);
    assert.notEqual(dual, onlyRecaptcha);
  } finally {
    restoreGlobals();
  }
});

test("verifyRequiredCaptchaForTicket routes recaptcha through aggregator", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const testing = await loadTestingApi();
    let calledUrl = "";
    let body = "";
    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });
    globalThis.fetch = async (url, init) => {
      calledUrl = String(url);
      body = init && typeof init.body === "string" ? init.body : "";
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
        status: 200,
      });
    };

    const result = await testing.verifyRequiredCaptchaForTicket(
      request,
      {
        recaptchaEnabled: true,
        RECAPTCHA_PAIRS: [
          { sitekey: "rk-1", secret: "rs-1" },
          { sitekey: "rk-2", secret: "rs-2" },
        ],
        RECAPTCHA_ACTION: "submit",
        RECAPTCHA_MIN_SCORE: 0.7,
        SITEVERIFY_URL: "https://sv.example/siteverify",
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "shared-secret",
      },
      { mac: "ticket-mac-1" },
      JSON.stringify({ recaptcha_v3: "recaptcha-token-123456" }),
    );

    assert.equal(result.ok, true);
    assert.equal(calledUrl, "https://sv.example/siteverify");
    const payload = JSON.parse(body);
    assert.equal(payload.ticketMac, "ticket-mac-1");
    assert.equal(payload.remoteip, "1.2.3.4");
    assert.equal(payload.token.recaptcha_v3, "recaptcha-token-123456");
    assert.equal(payload.checks.recaptchaAction, "submit");
    assert.equal(payload.checks.recaptchaMinScore, 0.7);
    assert.deepEqual(payload.providers.recaptcha_v3.pairs, [
      { sitekey: "rk-1", secret: "rs-1" },
      { sitekey: "rk-2", secret: "rs-2" },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("verifyRequiredCaptchaForTicket rejects malformed turnstile envelope", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const testing = await loadTestingApi();
    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), {
        status: 200,
      });
    };

    const result = await testing.verifyRequiredCaptchaForTicket(
      request,
      {
        turncheck: true,
        TURNSTILE_SECRET: "turn-secret",
        SITEVERIFY_URL: "https://sv.example/siteverify",
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "shared-secret",
      },
      { mac: "ticket-mac-1" },
      JSON.stringify({ recaptcha_v3: "wrong-key" }),
    );

    assert.equal(result.ok, false);
    assert.equal(result.malformed, true);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
