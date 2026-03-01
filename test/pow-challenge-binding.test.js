import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "./helpers/pow-runtime-fixture.js";
import { resolveParentsV4 } from "./mhg/helpers/resolve-parents-v4.js";

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

const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const buildSplitHarnessModule = async (secret = "config-secret") => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret,
    tmpPrefix: "pow-test-",
  });

const harnessSource = `
import core1 from "./pow-core-1.js";
import core2 from "./pow-core-2.js";

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
  },
};

export const __splitTrace = splitTrace;
`;
  const splitHarnessPath = join(tmpDir, "split-core-harness.js");
  await writeFile(splitHarnessPath, harnessSource);
  return splitHarnessPath;
};

const buildConfigModule = async (secret = "config-secret", configOverrides = null) => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [powConfigSource, runtimeSource, pathGlobSource, lruCacheSource] = await Promise.all([
    readFile(join(repoRoot, "pow-config.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "runtime.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "path-glob.js"), "utf8"),
    readFile(join(repoRoot, "lib", "rule-engine", "lru-cache.js"), "utf8"),
  ]);
  const baseConfig = {
    POW_TOKEN: "test-secret",
    powcheck: true,
    POW_BIND_TLS: false,
    POW_BIND_COUNTRY: false,
    POW_BIND_ASN: false,
    POW_DIFFICULTY_BASE: 64,
    POW_MIN_STEPS: 16,
    POW_MAX_STEPS: 64,
    POW_SAMPLE_RATE: 0.01,
    POW_OPEN_BATCH: 4,
    POW_HASHCASH_X: 1,
    POW_PAGE_BYTES: 16384,
    POW_MIX_ROUNDS: 2,
    POW_SEGMENT_LEN: 4,
  };
  const effectiveConfig = {
    ...baseConfig,
    ...(configOverrides && typeof configOverrides === "object" ? configOverrides : {}),
  };
  const compiledConfig = JSON.stringify([
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      config: effectiveConfig,
    },
  ]);
  const injected = powConfigSource.replace(/__COMPILED_CONFIG__/gu, compiledConfig);
  const withSecret = replaceConfigSecret(injected, secret);
  const tmpDir = await mkdtemp(join(tmpdir(), "pow-config-test-"));
  await mkdir(join(tmpDir, "lib", "rule-engine"), { recursive: true });
  await writeFile(join(tmpDir, "lib", "rule-engine", "runtime.js"), runtimeSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "path-glob.js"), pathGlobSource);
  await writeFile(join(tmpDir, "lib", "rule-engine", "lru-cache.js"), lruCacheSource);
  const tmpPath = join(tmpDir, "pow-config-test.js");
  await writeFile(tmpPath, withSecret);
  return tmpPath;
};

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

const buildCore2Module = async (secret = "config-secret") => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret,
    tmpPrefix: "pow-core2-binding-test-",
  });

  const core2Mod = await import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${Date.now()}`);
  return core2Mod.default.fetch;
};

const normalizeApiPrefix = (value) => {
  if (typeof value !== "string") return "/__pow";
  const trimmed = value.trim();
  if (!trimmed) return "/__pow";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  const normalized = withSlash.replace(/\/+$/u, "");
  return normalized || "/__pow";
};

const makeTransitHeaders = ({ secret, exp, kind, method, pathname, apiPrefix }) => {
  const normalizedMethod = typeof method === "string" && method ? method.toUpperCase() : "GET";
  const normalizedPath =
    typeof pathname === "string" && pathname
      ? pathname.startsWith("/")
        ? pathname
        : `/${pathname}`
      : "/";
  const normalizedApiPrefix = normalizeApiPrefix(apiPrefix);
  const macInput = `v1|${exp}|${kind}|${normalizedMethod}|${normalizedPath}|${normalizedApiPrefix}`;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
  return {
    "X-Pow-Transit": kind,
    "X-Pow-Transit-Mac": mac,
    "X-Pow-Transit-Expire": String(exp),
    "X-Pow-Transit-Api-Prefix": normalizedApiPrefix,
  };
};

const sha256Base64Url = (value) =>
  base64Url(crypto.createHash("sha256").update(String(value || "")).digest());

const makePowBindingString = (
  ticket,
  hostname,
  pathHash,
  ipScope,
  country,
  asn,
  tlsFingerprint,
  pageBytes,
  mixRounds,
) => {
  const host = typeof hostname === "string" ? hostname.toLowerCase() : "";
  return `${ticket.v}|${ticket.e}|${ticket.L}|${ticket.r}|${ticket.cfgId}|${host}|${pathHash}|${ipScope}|${country}|${asn}|${tlsFingerprint}|${pageBytes}|${mixRounds}|${ticket.issuedAt}`;
};

const resolveBindingValues = (payloadObj, pathHash) => ({
  pathHash: payloadObj.c.POW_BIND_PATH === false ? "any" : pathHash,
  ipScope: payloadObj.c.POW_BIND_IPRANGE === false ? "any" : payloadObj.d.ipScope,
  country: payloadObj.c.POW_BIND_COUNTRY === true ? payloadObj.d.country : "any",
  asn: payloadObj.c.POW_BIND_ASN === true ? payloadObj.d.asn : "any",
  tlsFingerprint: payloadObj.c.POW_BIND_TLS === true ? payloadObj.d.tlsFingerprint : "any",
});

const makeTicketFromPayload = ({ payloadObj, pathHash, host = "example.com" }) => {
  const ticket = {
    v: payloadObj.c.POW_VERSION,
    e: Math.floor(Date.now() / 1000) + 300,
    L: 20,
    r: base64Url(crypto.randomBytes(16)),
    cfgId: payloadObj.id,
    issuedAt: Math.floor(Date.now() / 1000),
    mac: "",
  };
  const binding = resolveBindingValues(payloadObj, pathHash);
  const pageBytes = Math.max(1, Math.floor(Number(payloadObj.c.POW_PAGE_BYTES) || 0));
  const mixRounds = Math.max(1, Math.floor(Number(payloadObj.c.POW_MIX_ROUNDS) || 0));
  const bindingString = makePowBindingString(
    ticket,
    host,
    binding.pathHash,
    binding.ipScope,
    binding.country,
    binding.asn,
    binding.tlsFingerprint,
    pageBytes,
    mixRounds,
  );
  ticket.mac = base64Url(crypto.createHmac("sha256", payloadObj.c.POW_TOKEN).update(bindingString).digest());
  const ticketB64 = base64Url(
    Buffer.from(
      `${ticket.v}.${ticket.e}.${ticket.L}.${ticket.r}.${ticket.cfgId}.${ticket.issuedAt}.${ticket.mac}`,
      "utf8",
    ),
  );
  return { ticket, ticketB64 };
};

const makeInnerHeaders = (payloadObj, secret = "config-secret", expireOffsetSec = 2) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + expireOffsetSec;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return { payload, mac, exp };
};

const makeSplitApiHeaders = ({ payloadObj, configSecret, method, pathname, apiPrefix }) => {
  const { payload, mac, exp } = makeInnerHeaders(payloadObj, configSecret);
  const transitExp = Math.floor(Date.now() / 1000) + 3;
  const transit = makeTransitHeaders({
    secret: configSecret,
    exp: transitExp,
    kind: "api",
    method,
    pathname,
    apiPrefix,
  });
  const headers = new Headers();
  headers.set("X-Pow-Inner", payload);
  headers.set("X-Pow-Inner-Mac", mac);
  headers.set("X-Pow-Inner-Expire", String(exp));
  for (const [key, value] of Object.entries(transit)) {
    headers.set(key, value);
  }
  return headers;
};

const fromBase64Url = (value) => {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
};

const decodeTicket = (ticketB64) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  const issuedAt = Number.parseInt(parts[5], 10);
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  return {
    v: Number.parseInt(parts[0], 10),
    e: Number.parseInt(parts[1], 10),
    L: Number.parseInt(parts[2], 10),
    r: parts[3] || "",
    cfgId: Number.parseInt(parts[4], 10),
    issuedAt,
    mac: parts[6] || "",
  };
};

const deriveMhgGraphSeed16 = (ticketB64, nonce) =>
  crypto.createHash("sha256").update(`mhg|graph|v4|${ticketB64}|${nonce}`).digest().subarray(0, 16);

const deriveMhgNonce16 = (nonce) => {
  const raw = fromBase64Url(nonce);
  if (raw.length >= 16) return raw.subarray(0, 16);
  return crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
};

const buildMhgWitnessBundle = async ({ ticketB64, nonce, pageBytes = 64 }) => {
  const ticket = decodeTicket(ticketB64);
  if (!ticket) throw new Error("invalid ticket");
  const { makeGenesisPage, mixPage } = await import("../lib/mhg/mix-aes.js");
  const { buildMerkle, buildProof } = await import("../lib/mhg/merkle.js");

  const graphSeed = deriveMhgGraphSeed16(ticketB64, nonce);
  const nonce16 = deriveMhgNonce16(nonce);
  const pages = new Array(ticket.L + 1);
  pages[0] = await makeGenesisPage({ graphSeed, nonce: nonce16, pageBytes });

  const parentByIndex = new Map();
  for (let i = 1; i <= ticket.L; i += 1) {
    const parents = await resolveParentsV4({ i, graphSeed, pageBytes, pages });
    parentByIndex.set(i, parents);
    pages[i] = await mixPage({
      i,
      p0: pages[parents.p0],
      p1: pages[parents.p1],
      p2: pages[parents.p2],
      graphSeed,
      nonce: nonce16,
      pageBytes,
    });
  }

  const tree = await buildMerkle(pages);
  const witnessByIndex = new Map();
  for (let i = 0; i <= ticket.L; i += 1) {
    witnessByIndex.set(i, {
      pageB64: base64Url(pages[i]),
      proof: buildProof(tree, i).map((sib) => base64Url(sib)),
    });
  }

  return {
    rootB64: base64Url(tree.root),
    witnessByIndex,
    parentByIndex,
    finalPageB64: base64Url(pages[ticket.L]),
  };
};

const buildEqSet = (index, seg) => {
  const out = [];
  const start = Math.max(1, index - seg + 1);
  for (let i = start; i <= index; i += 1) out.push(i);
  return out;
};

const buildNeedSet = (eqSet, parentByIndex) => {
  const out = new Set();
  for (const i of eqSet) {
    const edge = parentByIndex.get(i);
    if (!edge) throw new Error(`missing parents for index ${i}`);
    out.add(i);
    out.add(edge.p0);
    out.add(edge.p1);
    out.add(edge.p2);
  }
  return out;
};

const buildMhgOpensForChallenge = ({ indices, segs, witnessByIndex, parentByIndex }) => {
  if (!Array.isArray(indices) || !Array.isArray(segs) || indices.length !== segs.length) {
    throw new Error("challenge shape mismatch");
  }
  return indices.map((index, pos) => {
    const seg = Number.parseInt(segs[pos], 10);
    if (!Number.isInteger(seg) || seg <= 0) throw new Error(`invalid seg at ${pos}`);
    const eqSet = buildEqSet(index, seg);
    const need = buildNeedSet(eqSet, parentByIndex);
    const nodes = {};
    for (const needIdx of need) {
      const witness = witnessByIndex.get(needIdx);
      if (!witness) throw new Error(`missing witness for index ${needIdx}`);
      nodes[String(needIdx)] = { pageB64: witness.pageB64, proof: witness.proof };
    }
    return { i: index, seg, nodes };
  });
};

const HASHCASH_PREFIX_BYTES = Buffer.from("hashcash|v4|", "utf8");

const hashcashPrefixU32 = (bytes) =>
  (((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0);

const hashcashPrefixU32ForRootLast = (rootB64, lastPageB64) => {
  const digest = crypto
    .createHash("sha256")
    .update(Buffer.concat([HASHCASH_PREFIX_BYTES, fromBase64Url(rootB64), fromBase64Url(lastPageB64)]))
    .digest();
  return hashcashPrefixU32(digest);
};

const runChallengeOpenFlow = async ({
  configHandler,
  ip,
  ticketB64,
  pathHash,
  rootB64,
  nonce,
  witnessByIndex,
  parentByIndex,
}) => {
  const commitRes = await configHandler(
    new Request("https://example.com/__pow/commit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": ip,
      },
      body: JSON.stringify({ ticketB64, rootB64, pathHash, nonce }),
    }),
  );
  assert.equal(commitRes.status, 200, "commit succeeds for valid witness bundle");
  const commitPayload = await commitRes.json();
  const commitToken = commitPayload && typeof commitPayload.commitToken === "string"
    ? commitPayload.commitToken
    : "";
  assert.ok(commitToken, "commit token issued");

  const challengeRes = await configHandler(
    new Request("https://example.com/__pow/challenge", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": ip,
      },
      body: JSON.stringify({ commitToken }),
    }),
  );
  assert.equal(challengeRes.status, 200, "challenge succeeds for committed root");
  const challengePayload = await challengeRes.json();
  const opens = buildMhgOpensForChallenge({
    indices: challengePayload.indices,
    segs: challengePayload.segs,
    witnessByIndex,
    parentByIndex,
  });

  const openRes = await configHandler(
    new Request("https://example.com/__pow/open", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": ip,
      },
      body: JSON.stringify({
        commitToken,
        sid: challengePayload.sid,
        cursor: challengePayload.cursor,
        token: challengePayload.token,
        opens,
      }),
    }),
  );

  return { openRes, challengePayload };
};

const extractChallengeArgs = (html) => {
  const match = html.match(
    /g\("([^"]+)",\s*(\d+),\s*"([^"]+)",\s*"([^"]+)",\s*([0-9]+(?:\.[0-9]+)?),\s*(\d+)/u,
  );
  if (!match) return null;
  const hashcashX = Number.parseFloat(match[5]);
  if (!Number.isFinite(hashcashX)) return null;
  return {
    bindingB64: match[1],
    steps: Number.parseInt(match[2], 10),
    ticketB64: match[3],
    pathHash: match[4],
    hashcashX,
    segmentLen: Number.parseInt(match[6], 10),
  };
};

test("challenge parser accepts float hashcashX argument", () => {
  const args = extractChallengeArgs('<script>g("bind", 20, "ticket", "path", 3.5, 4)</script>');
  assert.ok(args, "challenge parser extracts args");
  assert.equal(typeof args.hashcashX, "number");
  assert.equal(args.hashcashX, 3.5);
});

test("commit returns commitToken payload; challenge requires payload token", async () => {
  const restoreGlobals = ensureGlobals();
  const core1ModulePath = await buildSplitHarnessModule();
  const configModulePath = await buildConfigModule();
  const core1Mod = await import(`${pathToFileURL(core1ModulePath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      const hasInner = Array.from(request.headers.keys()).some((key) =>
        key.toLowerCase().startsWith("x-pow-inner")
      );
      if (hasInner) {
        return core1Handler(request);
      }
      return new Response("ok", { status: 200 });
    };

    const pageRes = await configHandler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
    );
    assert.equal(pageRes.status, 200);
    const html = await pageRes.text();
    const args = extractChallengeArgs(html);
    assert.ok(args, "challenge html includes args");

    const rootB64 = base64Url(crypto.randomBytes(32));
    const nonce = base64Url(crypto.randomBytes(12));
    const commitRes = await configHandler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
        }),
      }),
    );

    assert.equal(commitRes.status, 200);
    assert.equal(commitRes.headers.get("Set-Cookie"), null);
    const commitPayload = await commitRes.json();
    assert.equal(typeof commitPayload.commitToken, "string");
    assert.ok(commitPayload.commitToken.length > 0);

    const challengeRes = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
        body: JSON.stringify({ commitToken: commitPayload.commitToken }),
      }),
    );
    assert.equal(challengeRes.status, 200);

    const legacyCookieOnly = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
          Cookie: `__Host-pow_commit=${encodeURIComponent(commitPayload.commitToken)}`,
        },
        body: JSON.stringify({}),
      }),
    );
    assert.equal(legacyCookieOnly.status, 400);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("challenge rejects binding mismatch after commit via split core harness", async () => {
  const restoreGlobals = ensureGlobals();
  const core1ModulePath = await buildSplitHarnessModule();
  const configModulePath = await buildConfigModule();
  const core1Mod = await import(`${pathToFileURL(core1ModulePath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      const hasInner = Array.from(request.headers.keys()).some((key) =>
        key.toLowerCase().startsWith("x-pow-inner")
      );
      if (hasInner) {
        return core1Handler(request);
      }
      return new Response("ok", { status: 200 });
    };

    const ipPrimary = "1.2.3.4";
    const pageRes = await configHandler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": ipPrimary,
        },
      })
    );
    assert.equal(pageRes.status, 200);
    const cspHeader = pageRes.headers.get("Content-Security-Policy");
    assert.ok(
      cspHeader && cspHeader.includes("frame-ancestors 'none'"),
      "challenge page sets frame-ancestors to none"
    );
    assert.equal(pageRes.headers.get("X-Frame-Options"), "DENY");
    const html = await pageRes.text();
    const args = extractChallengeArgs(html);
    assert.ok(args, "challenge html includes args");
    assert.ok(args.segmentLen >= 2 && args.segmentLen <= 16, "challenge html clamps segment length to 2..16");
    const ticketRaw = Buffer.from(
      String(args.ticketB64).replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    const ticketParts = ticketRaw.split(".");
    assert.equal(ticketParts.length, 7);
    const issuedAt = Number.parseInt(ticketParts[5], 10);
    assert.ok(Number.isFinite(issuedAt) && issuedAt > 0);
    const bindingRaw = Buffer.from(
      String(args.bindingB64).replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    assert.match(bindingRaw, new RegExp(`\\|${issuedAt}$`, "u"));

    const rootB64 = base64Url(crypto.randomBytes(32));
    const nonce = base64Url(crypto.randomBytes(12));
    const commitRes = await configHandler(
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
    const commitPayload = await commitRes.json();
    assert.equal(typeof commitPayload.commitToken, "string");
    assert.ok(commitPayload.commitToken.length > 0);
    const challengeResPrimary = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipPrimary,
        },
        body: JSON.stringify({ commitToken: commitPayload.commitToken }),
      })
    );
    assert.equal(challengeResPrimary.status, 200);
    const challengePayload = await challengeResPrimary.json();
    assert.equal(challengePayload.done, false);
    assert.equal(challengePayload.cursor, 0);
    assert.ok(Array.isArray(challengePayload.indices));
    assert.ok(challengePayload.indices.length > 0);
    assert.ok(challengePayload.indices.every((value) => Number.isInteger(value)));
    assert.ok(Array.isArray(challengePayload.segs));
    assert.equal(challengePayload.segs.length, challengePayload.indices.length);
    assert.ok(challengePayload.segs.every((value) => Number.isInteger(value)));
    assert.ok(challengePayload.segs.every((value) => value >= 2 && value <= 16));
    assert.equal(challengePayload.segs.includes(1), false);
    assert.ok(typeof challengePayload.token === "string");
    assert.ok(challengePayload.token.length > 0);
    assert.ok(typeof challengePayload.sid === "string");
    assert.ok(challengePayload.sid.length > 0);
    assert.equal(Object.hasOwn(challengePayload, "spinePos"), false);

    const malformedOpens = challengePayload.indices.map((indexValue, idx) => ({
      i: indexValue,
      seg: idx === 0 ? `${challengePayload.segs[idx]}.5` : challengePayload.segs[idx],
      nodes: {},
    }));
    const malformedOpenRes = await configHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipPrimary,
        },
        body: JSON.stringify({
          commitToken: commitPayload.commitToken,
          sid: challengePayload.sid,
          cursor: challengePayload.cursor,
          token: challengePayload.token,
          opens: malformedOpens,
        }),
      }),
    );
    assert.equal(malformedOpenRes.status, 400);

    const staleContractOpens = challengePayload.indices.map((indexValue, idx) => ({
      i: indexValue,
      seg: idx === 0 ? 1 : challengePayload.segs[idx],
      nodes: {},
    }));
    const staleContractRes = await configHandler(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipPrimary,
        },
        body: JSON.stringify({
          commitToken: commitPayload.commitToken,
          sid: challengePayload.sid,
          cursor: challengePayload.cursor,
          token: challengePayload.token,
          opens: staleContractOpens,
        }),
      }),
    );
    assert.equal(staleContractRes.status, 403);
    assert.equal(staleContractRes.headers.get("x-pow-h"), "cheat");

    const ipSecondary = "5.6.7.8";
    const challengeRes = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": ipSecondary,
        },
        body: JSON.stringify({ commitToken: commitPayload.commitToken }),
      })
    );
    assert.equal(challengeRes.status, 403);
    assert.ok(core1Mod.__splitTrace, "split trace is exposed");
    assert.ok(core1Mod.__splitTrace.core1Calls >= 4);
    assert.ok(core1Mod.__splitTrace.core2Calls >= 1);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("challenge sampling count follows ceil(L*POW_SAMPLE_RATE)", async () => {
  const restoreGlobals = ensureGlobals();
  const core1ModulePath = await buildSplitHarnessModule();
  const configModulePath = await buildConfigModule("config-secret", {
    POW_SAMPLE_RATE: 0.5,
    POW_OPEN_BATCH: 256,
    POW_MIN_STEPS: 20,
    POW_MAX_STEPS: 20,
  });
  const core1Mod = await import(`${pathToFileURL(core1ModulePath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      const hasInner = Array.from(request.headers.keys()).some((key) =>
        key.toLowerCase().startsWith("x-pow-inner")
      );
      if (hasInner) return core1Handler(request);
      return new Response("ok", { status: 200 });
    };

    const pageRes = await configHandler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
    );
    assert.equal(pageRes.status, 200);
    const html = await pageRes.text();
    const args = extractChallengeArgs(html);
    assert.ok(args, "challenge html includes args");
    assert.equal(args.steps, 20);

    const rootB64 = base64Url(crypto.randomBytes(32));
    const nonce = base64Url(crypto.randomBytes(12));
    const commitRes = await configHandler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64,
          pathHash: args.pathHash,
          nonce,
        }),
      }),
    );
    assert.equal(commitRes.status, 200);
    const commitPayload = await commitRes.json();
    assert.equal(typeof commitPayload.commitToken, "string");
    assert.ok(commitPayload.commitToken.length > 0);

    const challengeRes = await configHandler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
        body: JSON.stringify({ commitToken: commitPayload.commitToken }),
      }),
    );
    assert.equal(challengeRes.status, 200);
    const challengePayload = await challengeRes.json();
    assert.equal(challengePayload.indices.length, 10);
    assert.equal(challengePayload.indices[0], 1);
    assert.equal(challengePayload.indices[1], args.steps);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split core-2 open enforces hashcashX threshold with hashcash(root,lastPage)", async () => {
  const restoreGlobals = ensureGlobals();
  const core1ModulePath = await buildSplitHarnessModule();
  const hashcashX = 3.5;
  const configModulePath = await buildConfigModule("config-secret", {
    POW_HASHCASH_X: hashcashX,
    POW_MIN_STEPS: 20,
    POW_MAX_STEPS: 20,
    POW_SAMPLE_RATE: 0.5,
    POW_OPEN_BATCH: 256,
    POW_PAGE_BYTES: 64,
    POW_MIX_ROUNDS: 2,
  });
  const core1Mod = await import(`${pathToFileURL(core1ModulePath).href}?v=${Date.now()}`);
  const configMod = await import(`${pathToFileURL(configModulePath).href}?v=${Date.now()}`);
  const core1Handler = core1Mod.default.fetch;
  const configHandler = configMod.default.fetch;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (request) => {
      const hasInner = Array.from(request.headers.keys()).some((key) =>
        key.toLowerCase().startsWith("x-pow-inner")
      );
      if (hasInner) return core1Handler(request);
      return new Response("ok", { status: 200 });
    };

    const threshold = Math.floor(0x1_0000_0000 / hashcashX);
    const ip = "1.2.3.4";
    const pageRes = await configHandler(
      new Request("https://example.com/protected", {
        method: "GET",
        headers: {
          Accept: "text/html",
          "CF-Connecting-IP": ip,
        },
      }),
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args, "challenge html includes args");
    assert.equal(typeof args.hashcashX, "number");
    assert.equal(args.hashcashX, hashcashX);

    let passing = null;
    let failing = null;
    for (let attempt = 0; attempt < 48 && (!passing || !failing); attempt += 1) {
      const nonce = base64Url(crypto.randomBytes(12));
      const witness = await buildMhgWitnessBundle({
        ticketB64: args.ticketB64,
        nonce,
        pageBytes: 64,
      });
      const u = hashcashPrefixU32ForRootLast(witness.rootB64, witness.finalPageB64);
      const candidate = {
        nonce,
        rootB64: witness.rootB64,
        witnessByIndex: witness.witnessByIndex,
        parentByIndex: witness.parentByIndex,
        u,
      };
      if (!passing && u < threshold) passing = candidate;
      if (!failing && u >= threshold) failing = candidate;
    }

    assert.ok(passing, "found witness with u < floor(2^32 / x)");
    assert.ok(failing, "found witness with u >= floor(2^32 / x)");
    assert.ok(passing.u < threshold, "passing witness is below threshold");
    assert.ok(failing.u >= threshold, "failing witness meets or exceeds threshold");

    const passingFlow = await runChallengeOpenFlow({
      configHandler,
      ip,
      ticketB64: args.ticketB64,
      pathHash: args.pathHash,
      rootB64: passing.rootB64,
      nonce: passing.nonce,
      witnessByIndex: passing.witnessByIndex,
      parentByIndex: passing.parentByIndex,
    });
    assert.equal(passingFlow.openRes.status, 200);
    const passingPayload = await passingFlow.openRes.json();
    assert.equal(passingPayload.done, true);

    const failingFlow = await runChallengeOpenFlow({
      configHandler,
      ip,
      ticketB64: args.ticketB64,
      pathHash: args.pathHash,
      rootB64: failing.rootB64,
      nonce: failing.nonce,
      witnessByIndex: failing.witnessByIndex,
      parentByIndex: failing.parentByIndex,
    });
    assert.equal(failingFlow.openRes.status, 403);
    assert.equal(failingFlow.openRes.headers.get("x-pow-h"), "cheat");
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("split runtime uses captchaTag naming", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const [businessGateSource, apiEngineSource] = await Promise.all([
    readFile(join(repoRoot, "lib", "pow", "business-gate.js"), "utf8"),
    readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8"),
  ]);
  for (const source of [businessGateSource, apiEngineSource]) {
    assert.match(source, /CAPTCHA_TAG_LEN/u);
    assert.match(source, /captchaTagV1/u);
    assert.doesNotMatch(source, /\bTB_LEN\b/u);
    assert.doesNotMatch(source, /\btbFromToken\b/u);
  }
});

test("core-2 open final step uses provider-aware captcha verification", async () => {
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const apiEngineSource = await readFile(join(repoRoot, "lib", "pow", "api-engine.js"), "utf8");
  const openBlockMatch = apiEngineSource.match(
    /const handlePowOpen = async[\s\S]+?export const handlePowApi = async/u,
  );
  assert.ok(openBlockMatch, "handlePowOpen block exists");
  const openBlock = openBlockMatch[0];
  assert.match(openBlock, /verifyRequiredCaptchaForTicket\(/u);
  assert.doesNotMatch(openBlock, /verifyTurnstileForTicket\(/u);
});

test("split core-2 hard-cutoff rejects removed API routes", async () => {
  const restoreGlobals = ensureGlobals();
  const core2Fetch = await buildCore2Module();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("ok", { status: 200 });

    const config = {
      POW_TOKEN: "test-secret",
      powcheck: true,
      turncheck: false,
      POW_VERSION: 3,
      POW_API_PREFIX: "/__pow",
      POW_DIFFICULTY_BASE: 64,
      POW_MIN_STEPS: 16,
      POW_MAX_STEPS: 64,
      POW_SAMPLE_RATE: 0.01,
      POW_OPEN_BATCH: 4,
      POW_HASHCASH_X: 1,
      POW_PAGE_BYTES: 16384,
      POW_MIX_ROUNDS: 2,
      POW_SEGMENT_LEN: 4,
      POW_COMMIT_TTL_SEC: 120,
      POW_BIND_PATH: true,
      POW_BIND_IPRANGE: true,
      POW_BIND_COUNTRY: false,
      POW_BIND_ASN: false,
      POW_BIND_TLS: false,
      PROOF_TTL_SEC: 300,
      ATOMIC_CONSUME: false,
      POW_TICKET_TTL_SEC: 180,
    };
    const payloadObj = {
      v: 1,
      id: 7,
      c: config,
      d: {
        ipScope: "1.2.3.4/32",
        country: "any",
        asn: "any",
        tlsFingerprint: "any",
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
    };
    const commitHeaders = makeSplitApiHeaders({
      payloadObj,
      configSecret: "config-secret",
      method: "POST",
      pathname: "/__pow/commit",
      apiPrefix: config.POW_API_PREFIX,
    });
    commitHeaders.set("Content-Type", "application/json");
    const commitRes = await core2Fetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: commitHeaders,
        body: JSON.stringify({}),
      }),
    );
    assert.equal(commitRes.status, 404);

    const challengeHeadersPrimary = makeSplitApiHeaders({
      payloadObj,
      configSecret: "config-secret",
      method: "POST",
      pathname: "/__pow/challenge",
      apiPrefix: config.POW_API_PREFIX,
    });
    challengeHeadersPrimary.set("Content-Type", "application/json");
    const challengeResPrimary = await core2Fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: challengeHeadersPrimary,
        body: JSON.stringify({}),
      }),
    );
    assert.equal(challengeResPrimary.status, 404);

    const challengeHeadersSecondary = makeSplitApiHeaders({
      payloadObj,
      configSecret: "config-secret",
      method: "POST",
      pathname: "/__pow/challenge",
      apiPrefix: config.POW_API_PREFIX,
    });
    challengeHeadersSecondary.set("Content-Type", "application/json");
    const challengeResSecondary = await core2Fetch(
      new Request("https://example.com/__pow/challenge", {
        method: "GET",
        headers: challengeHeadersSecondary,
      }),
    );
    assert.equal(challengeResSecondary.status, 404);
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});
