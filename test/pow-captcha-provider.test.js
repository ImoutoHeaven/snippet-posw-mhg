import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { cp, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
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

const buildApiEngineTestModule = async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const apiEngineSource = await readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");

  const tmpDir = await mkdtemp(join(tmpdir(), "pow-api-engine-test-"));
  await mkdir(join(tmpDir, "lib"), { recursive: true });
  await Promise.all([
    cp(join(repoRoot, "lib", "pow"), join(tmpDir, "lib", "pow"), { recursive: true }),
    cp(join(repoRoot, "lib", "equihash"), join(tmpDir, "lib", "equihash"), { recursive: true }),
  ]);

  const apiEngineInjected = `${apiEngineSource}\nexport const __captchaTesting = { parseCanonicalCaptchaTokens, captchaTagV1 };\n`;

  await Promise.all([
    writeFile(join(tmpDir, "lib", "pow", "api-engine.js"), apiEngineInjected),
  ]);

  return join(tmpDir, "lib", "pow", "api-engine.js");
};

const loadCaptchaTesting = async () => {
  const modulePath = await buildApiEngineTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  return mod.__captchaTesting;
};

const getApiEngineSource = async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  return readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");
};

test("verify-only flow has no cap handler", async () => {
  const source = await getApiEngineSource();
  assert.doesNotMatch(source, /const handleCap = async \(/u);
  assert.match(source, /const handlePowVerify = async \(/u);
});

test("canonical captcha parser only accepts turnstile token", async () => {
  const source = await getApiEngineSource();
  assert.match(source, /const parseCanonicalCaptchaTokens = \(captchaToken, needTurn\) =>/u);
  assert.match(source, /if \(!needTurn\) \{\s*return \{ ok: true, malformed: false, tokens: \{ turnstile: "" \} \};/u);
  assert.doesNotMatch(source, /recaptcha_v3/u);
  assert.doesNotMatch(source, /needRecaptcha/u);
  assert.doesNotMatch(source, /const providersRaw = typeof config\.providers === "string"/u);
});

test("turnstile parser rejects malformed envelope", async () => {
  const restoreGlobals = ensureGlobals();

  try {
    const testing = await loadCaptchaTesting();
    const result = testing.parseCanonicalCaptchaTokens(JSON.stringify({ wrong: "key" }), true);

    assert.equal(result.ok, false);
    assert.equal(result.malformed, true);
  } finally {
    restoreGlobals();
  }
});

test("verify handler sends turnstile payload to aggregator when required", async () => {
  const source = await getApiEngineSource();
  assert.match(source, /payload\.token\.turnstile = turnToken;/u);
  assert.match(source, /payload\.providers\.turnstile = \{ secret: turnSecret \};/u);
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
