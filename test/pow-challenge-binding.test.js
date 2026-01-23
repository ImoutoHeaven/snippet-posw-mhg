import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ensureGlobals = () => {
  if (!globalThis.crypto) {
    globalThis.crypto = crypto.webcrypto;
  }
  if (!globalThis.btoa) {
    globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  }
  if (!globalThis.atob) {
    globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  }
};

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const buildTestModule = async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: "test-secret",
        powcheck: true,
        POW_BIND_TLS: false,
        POW_BIND_COUNTRY: false,
        POW_BIND_ASN: false,
        POW_DIFFICULTY_BASE: 64,
        POW_MIN_STEPS: 16,
        POW_MAX_STEPS: 64,
        POW_CHAL_ROUNDS: 2,
        POW_SAMPLE_K: 1,
        POW_OPEN_BATCH: 4,
        POW_HASHCASH_BITS: 0,
        POW_SEGMENT_LEN: 4,
      },
    },
  ]);
  const injected = powSource
    .replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template))
    .replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, injected);
  return tmpPath;
};

const extractChallengeArgs = (html) => {
  const match = html.match(/g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)"/u);
  if (!match) return null;
  return {
    bindingB64: match[1],
    steps: Number.parseInt(match[2], 10),
    ticketB64: match[3],
    pathHash: match[4],
  };
};

test("challenge rejects binding mismatch after commit", async () => {
  ensureGlobals();
  const modulePath = await buildTestModule();
  const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;

  const ipPrimary = "1.2.3.4";
  const pageRes = await handler(
    new Request("https://example.com/protected", {
      method: "GET",
      headers: {
        Accept: "text/html",
        "CF-Connecting-IP": ipPrimary,
      },
    })
  );
  assert.equal(pageRes.status, 200);
  const html = await pageRes.text();
  const args = extractChallengeArgs(html);
  assert.ok(args, "challenge html includes args");

  const rootB64 = base64Url(crypto.randomBytes(32));
  const nonce = base64Url(crypto.randomBytes(12));
  const commitRes = await handler(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": ipPrimary,
      },
      body: JSON.stringify({
        ticketB64: args.ticketB64,
        rootB64,
        pathHash: args.pathHash,
        nonce,
      }),
    })
  );
  assert.equal(commitRes.status, 200);
  const setCookie = commitRes.headers.get("Set-Cookie");
  assert.ok(setCookie, "commit sets cookie");
  const commitCookie = setCookie.split(";")[0];

  const ipSecondary = "5.6.7.8";
  const challengeRes = await handler(
    new Request("https://example.com/__pow/challenge", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": ipSecondary,
        Cookie: commitCookie,
      },
      body: JSON.stringify({}),
    })
  );
  assert.equal(challengeRes.status, 403);
});
