import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "../helpers/pow-runtime-fixture.js";

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const readOptionalFile = async (filePath) => {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
};

const buildSplitCoreHarnessModule = async (secret = "config-secret") => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret,
    tmpPrefix: "pow-atomic-snapshot-split-",
  });

const harnessSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";
import { issueTransit } from "./lib/pow/transit-auth.js";

const API_PREFIX = "/__pow";

const apiAction = (pathname) => {
  const normalized = typeof pathname === "string" ? pathname : "/";
  if (!normalized.startsWith(API_PREFIX + "/")) return "";
  const suffix = normalized.slice(API_PREFIX.length + 1);
  return suffix.split("/")[0] || "";
};

const handledByCore1 = (action) =>
  action === "commit" || action === "cap" || action === "challenge";

const toRequest = (input, init) =>
  input instanceof Request ? input : new Request(input, init);

const isTransitRequest = (request) =>
  request.headers.has("X-Pow-Transit");

const splitTrace = {
  core1Calls: 0,
  core2Calls: 0,
  originCalls: 0,
};

export default {
  async fetch(request) {
    const runCore1WithTransitBridge = async () => {
      const upstreamFetch = globalThis.fetch;
      globalThis.fetch = async (input, init) => {
        const nextRequest = toRequest(input, init);
        if (isTransitRequest(nextRequest)) {
          splitTrace.core2Calls += 1;
          return core2.fetch(nextRequest);
        }
        splitTrace.originCalls += 1;
        return upstreamFetch(input, init);
      };
      try {
        splitTrace.core1Calls += 1;
        return await core1.fetch(request);
      } finally {
        globalThis.fetch = upstreamFetch;
      }
    };

    const url = new URL(request.url);
    const action = apiAction(url.pathname);
    if (handledByCore1(action)) {
      return runCore1WithTransitBridge();
    }
    if (action === "open") {
      const transit = await issueTransit({
        secret: ${JSON.stringify(secret)},
        method: request.method,
        pathname: url.pathname,
        kind: "api",
        apiPrefix: API_PREFIX,
      });
      if (!transit) return new Response(null, { status: 500 });
      const headers = new Headers(request.headers);
      for (const [key, value] of Object.entries(transit.headers)) headers.set(key, value);
      splitTrace.core2Calls += 1;
      return core2.fetch(new Request(request, { headers }));
    }

    return runCore1WithTransitBridge();
  },
};

export const __splitTrace = splitTrace;
`;
  const harnessPath = join(tmpDir, "split-core-harness.js");
  await writeFile(harnessPath, harnessSource);
  return harnessPath;
};

const buildConfigModule = async (secret = "config-secret") => {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const [source, runtimeSource, pathGlobSource, lruCacheSource] = await Promise.all([
    readFile(join(repoRoot, "pow-config.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "runtime.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "path-glob.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "lru-cache.js"), "utf8"),
  ]);
  const compiledConfig = JSON.stringify([
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      config: {
        POW_TOKEN: "pow-secret",
        powcheck: false,
        turncheck: false,
        TURNSTILE_SITEKEY: "turn-site",
        TURNSTILE_SECRET: "turn-secret",
        ATOMIC_CONSUME: true,
      },
    },
  ]);
  const injected = source.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-atomic-budget-"));
  await mkdir(join(tmpDir, "lib", "rule-engine"), { recursive: true });
  await writeFile(join(tmpDir, "lib", "rule-engine", "runtime.js"), runtimeSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "path-glob.js"), pathGlobSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "lru-cache.js"), lruCacheSource);
  const tmpPath = join(tmpDir, "pow-config.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

const runConfigThroughSplitRoute = async (request) => {
  const [harnessPath, configPath] = await Promise.all([
    buildSplitCoreHarnessModule(),
    buildConfigModule(),
  ]);
  const [harnessMod, configMod] = await Promise.all([
    import(`${pathToFileURL(harnessPath).href}?v=${Date.now()}`),
    import(`${pathToFileURL(configPath).href}?v=${Date.now()}`),
  ]);
  const harnessHandler = harnessMod.default.fetch;
  const configHandler = configMod.default.fetch;

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input, init) => {
      const nextRequest = input instanceof Request ? input : new Request(input, init);
      if (nextRequest.headers.has("X-Pow-Inner") || nextRequest.headers.has("X-Pow-Inner-Count")) {
        return harnessHandler(nextRequest);
      }
      return new Response("ok", { status: 200 });
    };
    const response = await configHandler(request);
    return {
      status: response.status,
      body: await response.text(),
      trace: { ...harnessMod.__splitTrace },
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
};

const runAtomicSnapshotBoundaryCase = async ({ oversize }) => {
  const url = oversize
    ? `https://example.com/protected?__ts=${"t".repeat(8193)}`
    : `https://example.com/protected?__ts=${"t".repeat(8192)}`;
  return runConfigThroughSplitRoute(
    new Request(url, {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
        Accept: "application/json",
      },
    })
  );
};

const runAtomicSnapshotMalformedCase = async () => {
  return runConfigThroughSplitRoute(
    new Request("https://example.com/protected?__tt=bad*ticket", {
      headers: {
        "CF-Connecting-IP": "1.2.3.4",
        Accept: "application/json",
      },
    })
  );
};

test("atomic snapshot boundary stays fail-closed", async () => {
  const ok = await runAtomicSnapshotBoundaryCase({ oversize: false });
  assert.equal(ok.status, 200);
  assert.equal(ok.trace.core1Calls, 1);
  assert.equal(ok.trace.core2Calls, 1);
  assert.equal(ok.trace.originCalls, 1);

  const oversize = await runAtomicSnapshotBoundaryCase({ oversize: true });
  assert.equal(oversize.status, 431);
  assert.equal(oversize.body, "");
  assert.equal(oversize.trace.core1Calls, 0);
  assert.equal(oversize.trace.core2Calls, 0);
  assert.equal(oversize.trace.originCalls, 0);

  const malformed = await runAtomicSnapshotMalformedCase();
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body, "");
  assert.equal(malformed.trace.core1Calls, 0);
  assert.equal(malformed.trace.core2Calls, 0);
  assert.equal(malformed.trace.originCalls, 0);
});
