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

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const buildInnerHeaders = (payloadObj, secret) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const mac = base64Url(crypto.createHmac("sha256", secret).update(payload).digest());
  return { payload, mac };
};

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildTestModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const powSource = await readFile(join(repoRoot, "pow.js"), "utf8");
  const template = await readFile(join(repoRoot, "template.html"), "utf8");
  const compiledConfig = JSON.stringify([
    {
      host: { s: "^example\\.com$", f: "" },
      path: null,
      config: { POW_TOKEN: "test", powcheck: true, POW_BIND_TLS: false },
    },
  ]);
  const injected = powSource
    .replace(/__HTML_TEMPLATE__/gu, JSON.stringify(template))
    .replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-test-"));
  const tmpPath = join(tmpDir, "pow-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

test("pow.js fails closed without inner header", async () => {
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

test("pow.js rejects placeholder CONFIG_SECRET", async () => {
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

    const { payload, mac } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { powcheck: false, turncheck: false },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
      },
      "replace-me"
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
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

    const { payload, mac } = buildInnerHeaders(
      {
        v: 1,
        id: 0,
        c: { powcheck: false, turncheck: false },
        d: { ipScope: "any", country: "any", asn: "any", tlsFingerprint: "any" },
      },
      "config-secret"
    );
    const res = await handler(
      new Request("https://no-match.test/path", {
        headers: {
          "X-Pow-Inner": payload,
          "X-Pow-Inner-Mac": mac,
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
