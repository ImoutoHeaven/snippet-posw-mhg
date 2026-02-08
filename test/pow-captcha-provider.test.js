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

const buildPowModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const injected = powSource.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template));
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-provider-test-"));
  const tmpPath = join(tmpDir, "pow-provider-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const loadTestingApi = async () => {
  const modulePath = await buildPowModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
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

test("recaptcha action binding derives deterministic p_ hex prefix", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const testing = await loadTestingApi();
    const first = await testing.makeRecaptchaAction("bind:example", 2);
    const second = await testing.makeRecaptchaAction("bind:example", 2);
    const changedKid = await testing.makeRecaptchaAction("bind:example", 1);

    assert.match(first, /^p_[0-9a-f]{20}$/u);
    assert.equal(first, second);
    assert.notEqual(first, changedKid);
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

test("recaptcha verify requires hostname score action remoteip", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const testing = await loadTestingApi();
    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    const runCase = async (payload) => {
      let calledUrl = "";
      globalThis.fetch = async (url) => {
        calledUrl = String(url);
        return new Response(JSON.stringify(payload), { status: 200 });
      };
      const bindingString = "bind:example";
      const kid = 2;
      const ok = await testing.verifyCaptchaForTicket(request, {
        provider: "recaptcha_v3",
        secret: "recaptcha-secret",
        token: "recaptcha-token",
        ticketMac: "unused-for-recaptcha",
        bindingString,
        kid,
        minScore: 0.7,
      });
      return { ok, calledUrl };
    };

    const expectedAction = await testing.makeRecaptchaAction("bind:example", 2);

    const pass = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "1.2.3.4",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(pass.ok, true);
    assert.equal(pass.calledUrl, "https://www.google.com/recaptcha/api/siteverify");

    const noHostname = await runCase({
      success: true,
      remoteip: "1.2.3.4",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(noHostname.ok, false);

    const badScore = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "1.2.3.4",
      score: 0.5,
      action: expectedAction,
    });
    assert.equal(badScore.ok, false);

    const noRemoteIp = await runCase({
      success: true,
      hostname: "example.com",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(noRemoteIp.ok, true);

    const badAction = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "1.2.3.4",
      score: 0.9,
      action: "wrong-action",
    });
    assert.equal(badAction.ok, false);

    const badRemoteIp = await runCase({
      success: true,
      hostname: "example.com",
      remoteip: "9.9.9.9",
      score: 0.9,
      action: expectedAction,
    });
    assert.equal(badRemoteIp.ok, false);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("turnstile verify still requires cdata binding", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const testing = await loadTestingApi();
    const request = new Request("https://example.com/protected", {
      headers: { "CF-Connecting-IP": "1.2.3.4" },
    });

    let calledUrl = "";
    globalThis.fetch = async (url) => {
      calledUrl = String(url);
      return new Response(JSON.stringify({ success: true, cdata: "mismatch" }), { status: 200 });
    };
    const mismatch = await testing.verifyCaptchaForTicket(request, {
      provider: "turnstile",
      secret: "turnstile-secret",
      token: "turnstile-token-value",
      ticketMac: "expected-mac",
    });
    assert.equal(mismatch, false);
    assert.equal(calledUrl, "https://challenges.cloudflare.com/turnstile/v0/siteverify");

    globalThis.fetch = async () =>
      new Response(JSON.stringify({ success: true, cdata: "expected-mac" }), { status: 200 });
    const match = await testing.verifyCaptchaForTicket(request, {
      provider: "turnstile",
      secret: "turnstile-secret",
      token: "turnstile-token-value",
      ticketMac: "expected-mac",
    });
    assert.equal(match, true);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
