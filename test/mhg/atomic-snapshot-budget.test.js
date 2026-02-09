import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildConfigModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const source = await readFile(join(repoRoot, "pow-config.js"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: true,
        turncheck: true,
        recaptchaEnabled: true,
        RECAPTCHA_PAIRS: [{ sitekey: "rk", secret: "rs" }],
        TURNSTILE_SITEKEY: "turn-site",
        TURNSTILE_SECRET: "turn-secret",
        ATOMIC_CONSUME: true,
      },
    },
  ]);
  const injected = source.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-atomic-budget-"));
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const runAtomicSnapshotBoundaryCase = async ({ oversize }) => {
  const mod = await import(`${pathToFileURL(await buildConfigModule()).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const url = oversize
    ? `https://example.com/protected?__ts=${"t".repeat(8193)}`
    : `https://example.com/protected?__ts=${"t".repeat(8192)}`;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });
    const res = await handler(
      new Request(url, {
        headers: { "CF-Connecting-IP": "1.2.3.4" },
      })
    );
    return { status: res.status, body: await res.text() };
  } finally {
    globalThis.fetch = originalFetch;
  }
};

const runAtomicSnapshotMalformedCase = async () => {
  const mod = await import(`${pathToFileURL(await buildConfigModule()).href}?v=${Date.now()}`);
  const handler = mod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });
    const res = await handler(
      new Request("https://example.com/protected?__tt=bad*ticket", {
        headers: { "CF-Connecting-IP": "1.2.3.4" },
      })
    );
    return { status: res.status, body: await res.text() };
  } finally {
    globalThis.fetch = originalFetch;
  }
};

test("atomic snapshot boundary stays fail-closed", async () => {
  const ok = await runAtomicSnapshotBoundaryCase({ oversize: false });
  assert.equal(ok.status, 200);

  const oversize = await runAtomicSnapshotBoundaryCase({ oversize: true });
  assert.equal(oversize.status, 431);
  assert.equal(oversize.body, "");

  const malformed = await runAtomicSnapshotMalformedCase();
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body, "");
});
