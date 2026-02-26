import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPowRuntimeFixture } from "../helpers/pow-runtime-fixture.js";
import { __testNormalizeConfig as normalizePowConfig } from "../../pow-config.js";
import { verifyOpenBatchVector } from "../../lib/mhg/verify.js";
import { resolveParentsV4 } from "./helpers/resolve-parents-v4.js";

const CONFIG_SECRET = "config-secret";
const POW_SECRET = "pow-secret";
const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

const base64Url = (buffer) =>
  Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

const fromBase64Url = (value) => {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, "base64");
};

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

const buildSplitBridgeFetch = async (secret = CONFIG_SECRET) => {
  const { core1Fetch, core2Fetch } = await buildCoreModules(secret);
  const apiPrefix = "/__pow";
  const stripPowHeaders = (request) => {
    const headers = new Headers(request.headers);
    for (const key of Array.from(headers.keys())) {
      const lower = key.toLowerCase();
      if (lower.startsWith("x-pow-inner") || lower.startsWith("x-pow-transit")) {
        headers.delete(key);
      }
    }
    return new Request(request, { headers });
  };
  const runCore1WithTransitBridge = async (request, env, ctx) => {
    const upstreamFetch = globalThis.fetch;
    try {
      globalThis.fetch = async (input, init) => {
        const req = input instanceof Request ? input : new Request(input, init);
        if (req.headers.has("X-Pow-Transit")) return core2Fetch(req, env, ctx);
        if (typeof upstreamFetch === "function") return upstreamFetch(stripPowHeaders(req), init);
        return new Response(null, { status: 500 });
      };
      return core1Fetch(request, env, ctx);
    } finally {
      globalThis.fetch = upstreamFetch;
    }
  };
  return async (request, env = {}, ctx = {}) => {
    const url = new URL(request.url);
    if (url.pathname.startsWith(`${apiPrefix}/`)) {
      const decodedPath = (() => {
        try {
          return decodeURIComponent(url.pathname);
        } catch {
          return null;
        }
      })();
      if (!decodedPath || !decodedPath.startsWith(`${apiPrefix}/`)) {
        return new Response(null, { status: 400 });
      }
      const action = decodedPath.slice(apiPrefix.length);
      if (action !== "/open") {
        return runCore1WithTransitBridge(request, env, ctx);
      }
      const exp = Math.floor(Date.now() / 1000) + 3;
      const macInput = `v1|${exp}|api|${request.method.toUpperCase()}|${decodedPath}|${apiPrefix}`;
      const mac = base64Url(crypto.createHmac("sha256", secret).update(macInput).digest());
      const headers = new Headers(request.headers);
      headers.set("X-Pow-Transit", "api");
      headers.set("X-Pow-Transit-Mac", mac);
      headers.set("X-Pow-Transit-Expire", String(exp));
      headers.set("X-Pow-Transit-Api-Prefix", apiPrefix);
      return core2Fetch(new Request(request, { headers }), env, ctx);
    }
    return runCore1WithTransitBridge(request, env, ctx);
  };
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

const buildCoreModules = async (secret = CONFIG_SECRET) => {
  const { tmpDir } = await createPowRuntimeFixture({
    secret,
    tmpPrefix: "pow-split-fail-closed-",
  });

  const nonce = `${Date.now()}-${Math.random()}`;
  const [core1Module, core2Module] = await Promise.all([
    import(`${pathToFileURL(join(tmpDir, "pow-core-1.js")).href}?v=${nonce}`),
    import(`${pathToFileURL(join(tmpDir, "pow-core-2.js")).href}?v=${nonce}`),
  ]);
  return { core1Fetch: core1Module.default.fetch, core2Fetch: core2Module.default.fetch };
};

const makeSplitInnerHeaders = (payloadObj, secret = CONFIG_SECRET, expireOffsetSec = 2) => {
  const payload = base64Url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const exp = Math.floor(Date.now() / 1000) + expireOffsetSec;
  const mac = base64Url(crypto.createHmac("sha256", secret).update(`${payload}.${exp}`).digest());
  return {
    "X-Pow-Inner": payload,
    "X-Pow-Inner-Mac": mac,
    "X-Pow-Inner-Expire": String(exp),
  };
};

const parseTicket = (ticketB64) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  if (parts.length !== 7) return null;
  const v = Number.parseInt(parts[0], 10);
  const issuedAt = Number.parseInt(parts[5], 10);
  if (!Number.isFinite(v) || v <= 0) return null;
  if (!Number.isFinite(issuedAt) || issuedAt <= 0) return null;
  return {
    v,
    L: Number.parseInt(parts[2], 10),
    cfgId: Number.parseInt(parts[4], 10),
    issuedAt,
    mac: parts[6],
  };
};

const rewriteTicketVersion = (ticketB64, nextVersion) => {
  const raw = fromBase64Url(ticketB64).toString("utf8");
  const parts = raw.split(".");
  if (parts.length !== 7) throw new Error("invalid ticket parts");
  parts[0] = String(nextVersion);
  return base64Url(Buffer.from(parts.join("."), "utf8"));
};

const makeInnerPayload = ({ atomic = false, turncheck = true, powVersion = 4 } = {}) => ({
  v: 1,
  id: 77,
  c: normalizePowConfig({
    POW_TOKEN: POW_SECRET,
    powcheck: true,
    turncheck,
    recaptchaEnabled: false,
    POW_VERSION: powVersion,
    POW_API_PREFIX: "/__pow",
    POW_DIFFICULTY_BASE: 16,
    POW_DIFFICULTY_COEFF: 1,
    POW_MIN_STEPS: 4,
    POW_MAX_STEPS: 8,
    POW_SAMPLE_RATE: 0.01,
    POW_OPEN_BATCH: 2,
    POW_HASHCASH_BITS: 0,
    POW_PAGE_BYTES: 64,
    POW_MIX_ROUNDS: 2,
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
    TURNSTILE_SITEKEY: "turn-site",
    TURNSTILE_SECRET: "turn-secret",
    POW_ESM_URL: "https://cdn.example/esm.js",
    POW_GLUE_URL: "https://cdn.example/glue.js",
  }),
  d: { ipScope: "1.2.3.4/32", country: "", asn: "", tlsFingerprint: "" },
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

const deriveMhgGraphSeed = (ticketB64, nonce, graphLabel = "v4") =>
  crypto.createHash("sha256").update(`mhg|graph|${graphLabel}|${ticketB64}|${nonce}`).digest().subarray(0, 16);

const deriveMhgNonce16 = (nonce) => {
  const raw = fromBase64Url(nonce);
  if (raw.length >= 16) return raw.subarray(0, 16);
  return crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
};

const buildMhgWitnessBundle = async ({ ticketB64, nonce, graphLabel = "v4" }) => {
  const { makeGenesisPage, mixPage } = await import("../../lib/mhg/mix-aes.js");
  const { buildMerkle, buildProof } = await import("../../lib/mhg/merkle.js");
  const ticket = parseTicket(ticketB64);
  if (!ticket) throw new Error("invalid ticket");
  const graphSeed = deriveMhgGraphSeed(ticketB64, nonce, graphLabel);
  const nonce16 = deriveMhgNonce16(nonce);
  const pageBytes = 64;
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

  const makeOpenEntry = (index, seg) => {
    const start = Math.max(1, index - seg + 1);
    const needed = new Set();
    for (let i = start; i <= index; i += 1) {
      const parents = parentByIndex.get(i);
      needed.add(i);
      needed.add(parents.p0);
      needed.add(parents.p1);
      needed.add(parents.p2);
    }
    const nodes = {};
    for (const needIdx of needed) {
      nodes[needIdx] = witnessByIndex.get(needIdx);
    }
    return { i: index, seg, nodes };
  };

  return { rootB64: base64Url(tree.root), makeOpenEntry };
};

const runInnerFailClosedCases = async (handler) => {
  const payload = makeInnerPayload();
  const good = makeInnerHeaders(payload);
  const missingInner = await handler(new Request("https://example.com/protected", { headers: {} }), {}, {});
  const badMac = await handler(
    new Request("https://example.com/protected", {
      headers: { ...good, "X-Pow-Inner-Mac": "bad" },
    }),
    {},
    {}
  );
  const expired = await handler(
    new Request("https://example.com/protected", {
      headers: makeInnerHeaders(payload, CONFIG_SECRET, -10),
    }),
    {},
    {}
  );
  return { missingInner: missingInner.status, badMac: badMac.status, expired: expired.status };
};

const runForbiddenVerifyPointCases = async (handler) => {
  const payload = makeInnerPayload({ atomic: true });
  const headers = makeInnerHeaders(payload);
  const tokenEnvelope = JSON.stringify({ turnstile: "turnstile-token-value-1234567890" });
  let siteverifyCalls = 0;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input) => {
      const req = input instanceof Request ? input : new Request(input);
      if (String(req.url) === TURNSTILE_SITEVERIFY_URL) {
        siteverifyCalls += 1;
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return new Response("ok", { status: 200 });
    };

    const pageRes = await handler(
      new Request("https://example.com/protected", {
        headers: { ...headers, Accept: "text/html", "CF-Connecting-IP": "1.2.3.4" },
      }),
      {},
      {}
    );
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);
    const nonce = base64Url(crypto.randomBytes(16));
    const witness = await buildMhgWitnessBundle({ ticketB64: args.ticketB64, nonce });

    const commitRes = await handler(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: witness.rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: tokenEnvelope,
        }),
      }),
      {},
      {}
    );
    const commitSiteverifyCalls = siteverifyCalls;
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];

    const challengeRes = await handler(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json", Cookie: commitCookie },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );
    const challengeSiteverifyCalls = siteverifyCalls - commitSiteverifyCalls;
    assert.equal(challengeRes.status, 200);
    let state = await challengeRes.json();
    let nonFinalOpenSiteverifyCalls = 0;
    let atomicFinalOpenSiteverifyCalls = 0;
    while (state.done === false) {
      const opens = state.indices.map((idx, pos) => witness.makeOpenEntry(idx, state.segs[pos]));
      const before = siteverifyCalls;
      const openRes = await handler(
        new Request("https://example.com/__pow/open", {
          method: "POST",
          headers: { ...headers, "Content-Type": "application/json", Cookie: commitCookie },
          body: JSON.stringify({
            sid: state.sid,
            cursor: state.cursor,
            token: state.token,
            captchaToken: tokenEnvelope,
            opens,
          }),
        }),
        {},
        {}
      );
      assert.equal(openRes.status, 200);
      const body = await openRes.json();
      const delta = siteverifyCalls - before;
      if (body.done === false) {
        nonFinalOpenSiteverifyCalls += delta;
      } else {
        atomicFinalOpenSiteverifyCalls += delta;
      }
      state = body;
    }

    return {
      commitSiteverifyCalls,
      challengeSiteverifyCalls,
      nonFinalOpenSiteverifyCalls,
      atomicFinalOpenSiteverifyCalls,
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
};

const runAtomicProofBypassCase = async (handler) => {
  const payload = makeInnerPayload({ atomic: true });
  const res = await handler(
    new Request("https://example.com/protected", {
      headers: {
        ...makeInnerHeaders(payload),
        Accept: "application/json",
        Cookie: "__Host-proof=v1.fake.fake.fake.fake.fake.fake",
      },
    }),
    {},
    {}
  );
  return { allowed: res.status === 200 };
};

test("split core bridge fails closed when inner header is missing/invalid/expired", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const out = await runInnerFailClosedCases(bridgeFetch);
    assert.equal(out.missingInner, 500);
    assert.equal(out.badMac, 500);
    assert.equal(out.expired, 500);
  } finally {
    restoreGlobals();
  }
});

test("forbidden nodes never trigger provider siteverify", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const out = await runForbiddenVerifyPointCases(bridgeFetch);
    assert.equal(out.commitSiteverifyCalls, 0);
    assert.equal(out.challengeSiteverifyCalls, 0);
    assert.equal(out.nonFinalOpenSiteverifyCalls, 0);
    assert.equal(out.atomicFinalOpenSiteverifyCalls, 0);
  } finally {
    restoreGlobals();
  }
});

test("atomic captcha path cannot be bypassed by proof cookie", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const out = await runAtomicProofBypassCase(bridgeFetch);
    assert.equal(out.allowed, false);
  } finally {
    restoreGlobals();
  }
});

test("split core1 denies unauthorized non-navigation fail-closed", async () => {
  const restoreGlobals = ensureGlobals();
  const originalFetch = globalThis.fetch;
  try {
    const { core1Fetch, core2Fetch } = await buildCoreModules();
    const payload = makeInnerPayload();

    globalThis.fetch = async (request) => {
      if (request.headers.has("X-Pow-Transit")) {
        return core2Fetch(request);
      }
      return new Response("origin should not be reached", { status: 599 });
    };

    const res = await core1Fetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeSplitInnerHeaders(payload),
          Accept: "application/json",
        },
      }),
      {},
      {}
    );

    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { code: "pow_required" });
  } finally {
    globalThis.fetch = originalFetch;
    restoreGlobals();
  }
});

test("challenge issues only POW_VERSION=4 tickets", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const payload = makeInnerPayload();
    const res = await bridgeFetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(res.status, 200);
    const args = extractChallengeArgs(await res.text());
    assert.ok(args);
    const ticket = parseTicket(args.ticketB64);
    assert.ok(ticket);
    assert.equal(ticket.v, 4);
  } finally {
    restoreGlobals();
  }
});

test("challenge ignores non-4 POW_VERSION config input", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const payload = makeInnerPayload({ powVersion: 9 });
    const res = await bridgeFetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(res.status, 200);
    const args = extractChallengeArgs(await res.text());
    assert.ok(args);
    const ticket = parseTicket(args.ticketB64);
    assert.ok(ticket);
    assert.equal(ticket.v, 4);
  } finally {
    restoreGlobals();
  }
});

test("old-version tickets are rejected fail-closed", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const payload = makeInnerPayload({ turncheck: false });
    const pageRes = await bridgeFetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);
    const staleTicketB64 = rewriteTicketVersion(args.ticketB64, 3);

    const commitRes = await bridgeFetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ticketB64: staleTicketB64,
          rootB64: base64Url(crypto.randomBytes(32)),
          pathHash: args.pathHash,
          nonce: base64Url(crypto.randomBytes(16)),
          captchaToken: "",
        }),
      }),
      {},
      {}
    );

    assert.equal(commitRes.status, 403);
    assert.equal(commitRes.headers.get("x-pow-h"), "stale");
    assert.equal(await commitRes.text(), "");
  } finally {
    restoreGlobals();
  }
});

test("v3-derived vector no longer verifies under v4 graph seed contract", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const payload = makeInnerPayload({ turncheck: false });
    const pageRes = await bridgeFetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nonce = base64Url(crypto.randomBytes(16));
    const ticket = parseTicket(args.ticketB64);
    assert.ok(ticket);
    const witness = await buildMhgWitnessBundle({ ticketB64: args.ticketB64, nonce, graphLabel: "v3" });
    const graphSeedV4 = deriveMhgGraphSeed(args.ticketB64, nonce, "v4");
    const nonce16 = deriveMhgNonce16(nonce);
    const index = Math.min(ticket.L, 3);
    const open = witness.makeOpenEntry(index, 2);

    const verified = await verifyOpenBatchVector({
      rootB64: witness.rootB64,
      leafCount: ticket.L + 1,
      graphSeed: graphSeedV4,
      nonce: nonce16,
      pageBytes: 64,
      mixRounds: 2,
      opens: [open],
    });
    assert.equal(verified.ok, false);
    assert.equal(verified.reason, "equation_failed");
  } finally {
    restoreGlobals();
  }
});

test("/__pow/open rejects v3-derived vectors with cheat hint", async () => {
  const restoreGlobals = ensureGlobals();
  try {
    const bridgeFetch = await buildSplitBridgeFetch();
    const payload = makeInnerPayload({ turncheck: false });
    const pageRes = await bridgeFetch(
      new Request("https://example.com/protected", {
        headers: {
          ...makeInnerHeaders(payload),
          Accept: "text/html",
          "CF-Connecting-IP": "1.2.3.4",
        },
      }),
      {},
      {}
    );
    assert.equal(pageRes.status, 200);
    const args = extractChallengeArgs(await pageRes.text());
    assert.ok(args);

    const nonce = base64Url(crypto.randomBytes(16));
    const witness = await buildMhgWitnessBundle({ ticketB64: args.ticketB64, nonce, graphLabel: "v3" });

    const commitRes = await bridgeFetch(
      new Request("https://example.com/__pow/commit", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          "CF-Connecting-IP": "1.2.3.4",
        },
        body: JSON.stringify({
          ticketB64: args.ticketB64,
          rootB64: witness.rootB64,
          pathHash: args.pathHash,
          nonce,
          captchaToken: "",
        }),
      }),
      {},
      {}
    );
    assert.equal(commitRes.status, 200);
    const commitCookie = (commitRes.headers.get("set-cookie") || "").split(";")[0];
    assert.ok(commitCookie);

    const challengeRes = await bridgeFetch(
      new Request("https://example.com/__pow/challenge", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({}),
      }),
      {},
      {}
    );
    assert.equal(challengeRes.status, 200);
    const challenge = await challengeRes.json();
    assert.equal(challenge.done, false);

    const opens = challenge.indices.map((idx, pos) => witness.makeOpenEntry(idx, challenge.segs[pos]));
    const openRes = await bridgeFetch(
      new Request("https://example.com/__pow/open", {
        method: "POST",
        headers: {
          ...makeInnerHeaders(payload),
          "Content-Type": "application/json",
          Cookie: commitCookie,
        },
        body: JSON.stringify({
          sid: challenge.sid,
          cursor: challenge.cursor,
          token: challenge.token,
          captchaToken: "",
          opens,
        }),
      }),
      {},
      {}
    );

    assert.equal(openRes.status, 403);
    assert.equal(openRes.headers.get("x-pow-h"), "cheat");
  } finally {
    restoreGlobals();
  }
});
