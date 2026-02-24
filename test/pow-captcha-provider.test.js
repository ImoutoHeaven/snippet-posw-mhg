import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
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

const buildCore1FrontTestModule = async () => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret: "config-secret",
    tmpPrefix: "pow-core1-front-test-",
  });
  const core1FrontPath = join(tmpDir, "lib", "pow", "api-core1-front.js");
  const core1FrontSource = await readFile(core1FrontPath, "utf8");
  const core1FrontInjected = `${core1FrontSource}\nexport const __captchaTesting = { verifyRequiredCaptchaForTicket, captchaTagV1 };\n`;
  await writeFile(core1FrontPath, core1FrontInjected);
  return core1FrontPath;
};

const loadCaptchaTesting = async () => {
  const modulePath = await buildCore1FrontTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  return mod.__captchaTesting;
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

test("cap endpoint is turnstile-only and non-atomic", async () => {
  const source = await readPowSource("api-core1-front.js");
  assert.match(source, /if \(needPow \|\| !needTurn \|\| config\.ATOMIC_CONSUME === true\) return S\(404\);/u);
});

test("canonical captcha parser only accepts turnstile token", async () => {
  const sharedSource = await readPowSource("api-protocol-shared.js");
  const apiEngineSource = await readPowSource("api-engine.js");

  assert.match(sharedSource, /const resolveCaptchaRequirements = \(config\) => \{\s*const needTurn = config\.turncheck === true;\s*return \{ needTurn \};\s*\};/u);
  assert.match(sharedSource, /const parseCanonicalCaptchaTokens = \(captchaToken, needTurn\) =>/u);
  assert.match(sharedSource, /if \(!needTurn\) \{\s*return \{ ok: true, malformed: false, tokens: \{ turnstile: "" \} \};/u);
  assert.doesNotMatch(sharedSource, /recaptcha_v3/u);
  assert.doesNotMatch(sharedSource, /needRecaptcha/u);
  assert.doesNotMatch(sharedSource, /const providersRaw = typeof config\.providers === "string"/u);

  assert.doesNotMatch(apiEngineSource, /const parseCanonicalCaptchaTokens = \(captchaToken, needTurn\) =>/u);
});

test("turnstile-required flow rejects malformed envelope before aggregator call", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  let called = false;

  try {
    const testing = await loadCaptchaTesting();
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };

    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    const result = await testing.verifyRequiredCaptchaForTicket(
      request,
      {
        turncheck: true,
        TURNSTILE_SECRET: "turn-secret",
        SITEVERIFY_URLS: ["https://sv.example/siteverify"],
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "shared-secret",
      },
      { mac: "ticket-mac-1" },
      JSON.stringify({ wrong: "key" }),
    );

    assert.equal(result.ok, false);
    assert.equal(result.malformed, true);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("valid turnstile envelope reaches aggregator with turnstile payload", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  let calledUrl = "";
  let body = "";

  try {
    const testing = await loadCaptchaTesting();
    globalThis.fetch = async (url, init) => {
      calledUrl = String(url);
      body = init && typeof init.body === "string" ? init.body : "";
      return new Response(JSON.stringify({ ok: true, reason: "ok", checks: {}, providers: {} }), { status: 200 });
    };

    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    const turnstileToken = "turnstile-token-1234567890";
    const result = await testing.verifyRequiredCaptchaForTicket(
      request,
      {
        turncheck: true,
        TURNSTILE_SECRET: "turn-secret",
        SITEVERIFY_URLS: ["https://sv.example/siteverify"],
        SITEVERIFY_AUTH_KID: "v1",
        SITEVERIFY_AUTH_SECRET: "shared-secret",
      },
      { mac: "ticket-mac-1" },
      JSON.stringify({ turnstile: turnstileToken }),
    );

    assert.equal(result.ok, true);
    assert.equal(calledUrl, "https://sv.example/siteverify");
    const payload = JSON.parse(body);
    assert.equal(payload.token.turnstile, turnstileToken);
    assert.equal(payload.providers.turnstile.secret, "turn-secret");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("captchaTagV1 is deterministic for turnstile-only input", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadCaptchaTesting();
    const token = "turnstile-token-1234567890";
    const first = await testing.captchaTagV1(token);
    const second = await testing.captchaTagV1(token);
    const different = await testing.captchaTagV1("turnstile-token-0000000000");

    assert.equal(first, second);
    assert.notEqual(first, different);
    assert.match(first, /^[A-Za-z0-9_-]{16}$/u);
  } finally {
    restoreGlobals();
  }
});
