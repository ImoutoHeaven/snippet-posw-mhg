import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";
import { buildCrossEndFixture } from "../../esm/mhg-worker.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const encoder = new TextEncoder();

const runWorkerCommit = async ({
  ticketB64 = "dGVzdC10aWNrZXQ",
  steps = 8,
  pageBytes = 64,
  mixRounds = 2,
  hashcashBits = 0,
  progressEvery = 1,
  beforeImport,
} = {}) => {
  const prevSelf = globalThis.self;
  const prevPostMessage = globalThis.postMessage;
  const prevAtob = globalThis.atob;
  const prevBtoa = globalThis.btoa;
  const prevCrypto = globalThis.crypto;
  const prevFactory = globalThis.__MHG_HASH_WASM_FACTORY__;

  if (!globalThis.atob) {
    globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  }
  if (!globalThis.btoa) {
    globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  }
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }

  const progress = [];
  const pending = new Map();
  let rid = 0;
  const workerSelf = { addEventListener() {} };

  globalThis.self = workerSelf;
  globalThis.postMessage = (msg) => {
    if (msg && msg.type === "PROGRESS") {
      progress.push(msg);
      return;
    }
    const entry = pending.get(msg && msg.rid);
    if (!entry) return;
    pending.delete(msg.rid);
    if (msg.type === "ERROR") {
      entry.reject(new Error(msg.message || "worker error"));
      return;
    }
    entry.resolve(msg);
  };

  if (typeof beforeImport === "function") {
    beforeImport();
  }

  const workerUrl = `${pathToFileURL(join(repoRoot, "esm/mhg-worker.js")).href}?v=${Date.now()}-${Math.random()}`;
  await import(workerUrl);
  const onmessage = workerSelf.onmessage;

  const call = (type, payload = {}) =>
    new Promise((resolve, reject) => {
      const id = ++rid;
      pending.set(id, { resolve, reject });
      onmessage({ data: { type, rid: id, ...payload } });
    });

  try {
    await call("INIT", { ticketB64, steps, pageBytes, mixRounds, hashcashBits, progressEvery });
    const commit = await call("COMMIT");
    return { progress, commit };
  } finally {
    globalThis.self = prevSelf;
    globalThis.postMessage = prevPostMessage;
    globalThis.atob = prevAtob;
    globalThis.btoa = prevBtoa;
    if (!prevCrypto) {
      delete globalThis.crypto;
    } else {
      Object.defineProperty(globalThis, "crypto", { value: prevCrypto, configurable: true });
    }
    if (typeof prevFactory === "undefined") {
      delete globalThis.__MHG_HASH_WASM_FACTORY__;
    } else {
      globalThis.__MHG_HASH_WASM_FACTORY__ = prevFactory;
    }
  }
};

test("mhg worker emits chain progress during commit", async () => {
  const { progress } = await runWorkerCommit({
    steps: 8,
    hashcashBits: 0,
    progressEvery: 1,
  });
  assert.equal(
    progress.some((msg) => msg && msg.phase === "chain"),
    true,
  );
});

test("worker hash path is WebCrypto-only", async () => {
  let factoryCalls = 0;
  const digestAlgorithms = [];

  const { commit } = await runWorkerCommit({
    steps: 4,
    hashcashBits: 0,
    progressEvery: 1,
    beforeImport() {
      globalThis.__MHG_HASH_WASM_FACTORY__ = async () => {
        factoryCalls += 1;
        throw new Error("wasm factory must not run");
      };

      const baseCrypto = globalThis.crypto || webcrypto;
      const wrappedSubtle = {
        digest: async (algorithm, data) => {
          digestAlgorithms.push(algorithm);
          return baseCrypto.subtle.digest.call(baseCrypto.subtle, algorithm, data);
        },
        importKey: (...args) => baseCrypto.subtle.importKey.call(baseCrypto.subtle, ...args),
        encrypt: (...args) => baseCrypto.subtle.encrypt.call(baseCrypto.subtle, ...args),
      };
      Object.defineProperty(globalThis, "crypto", {
        value: {
          ...baseCrypto,
          subtle: wrappedSubtle,
          getRandomValues: (...args) => baseCrypto.getRandomValues(...args),
        },
        configurable: true,
      });
    },
  });

  assert.equal(factoryCalls, 0);
  assert.equal(digestAlgorithms.length > 0, true);
  assert.equal(digestAlgorithms.every((algorithm) => algorithm === "SHA-256"), true);
  assert.equal(typeof commit.rootB64, "string");
  assert.equal(commit.rootB64.length > 0, true);
  assert.equal(typeof commit.nonce, "string");
  assert.equal(commit.nonce.length > 0, true);
  assert.equal(encoder.encode(commit.nonce).length > 0, true);
});

test("worker fails closed when parent rejection sampling cannot converge", { timeout: 750 }, async () => {
  await assert.rejects(
    runWorkerCommit({
      steps: 4,
      hashcashBits: 0,
      beforeImport() {
        const baseCrypto = globalThis.crypto || webcrypto;
        const wrappedSubtle = {
          digest: async () => new Uint8Array(32).fill(0xff),
          importKey: (...args) => baseCrypto.subtle.importKey.call(baseCrypto.subtle, ...args),
          encrypt: (...args) => baseCrypto.subtle.encrypt.call(baseCrypto.subtle, ...args),
        };
        Object.defineProperty(globalThis, "crypto", {
          value: {
            ...baseCrypto,
            subtle: wrappedSubtle,
            getRandomValues: (...args) => baseCrypto.getRandomValues(...args),
          },
          configurable: true,
        });
      },
    }),
    /parent invariants violated/,
  );
});

test("worker INIT rejects mixRounds outside 1..4", async () => {
  await assert.rejects(runWorkerCommit({ mixRounds: 0 }), /mixRounds invalid/);
  await assert.rejects(runWorkerCommit({ mixRounds: 5 }), /mixRounds invalid/);
});

test("buildCrossEndFixture rejects invalid mixRounds", async () => {
  const baseVector = {
    graphSeedHex: "000102030405060708090a0b0c0d0e0f",
    nonceHex: "0f0e0d0c0b0a09080706050403020100",
    pageBytes: 64,
    pages: 4,
    indices: [],
    segs: [],
  };

  await assert.rejects(buildCrossEndFixture(baseVector), /mixRounds invalid/);
  await assert.rejects(buildCrossEndFixture({ ...baseVector, mixRounds: 0 }), /mixRounds invalid/);
  await assert.rejects(buildCrossEndFixture({ ...baseVector, mixRounds: 5 }), /mixRounds invalid/);
  await assert.rejects(buildCrossEndFixture({ ...baseVector, mixRounds: 2.5 }), /mixRounds invalid/);
});

test("worker derives PA/PB once per page index", async () => {
  let paCalls = 0;
  let pbCalls = 0;
  const decoder = new TextDecoder();

  await runWorkerCommit({
    steps: 4,
    mixRounds: 4,
    hashcashBits: 0,
    progressEvery: 1,
    beforeImport() {
      const baseCrypto = globalThis.crypto || webcrypto;
      const wrappedSubtle = {
        digest: async (algorithm, data) => {
          const buffer = new Uint8Array(data);
          const head = decoder.decode(buffer.subarray(0, 7));
          if (head === "MHG1-PA") paCalls += 1;
          if (head === "MHG1-PB") pbCalls += 1;
          return baseCrypto.subtle.digest.call(baseCrypto.subtle, algorithm, data);
        },
        importKey: (...args) => baseCrypto.subtle.importKey.call(baseCrypto.subtle, ...args),
        encrypt: (...args) => baseCrypto.subtle.encrypt.call(baseCrypto.subtle, ...args),
      };
      Object.defineProperty(globalThis, "crypto", {
        value: {
          ...baseCrypto,
          subtle: wrappedSubtle,
          getRandomValues: (...args) => baseCrypto.getRandomValues(...args),
        },
        configurable: true,
      });
    },
  });

  assert.equal(paCalls, 4);
  assert.equal(pbCalls, 4);
});

test("worker makeGenesisPage keeps subarray view semantics", async () => {
  const pageBytes = 64;
  let genesisPage = null;

  await buildCrossEndFixture(
    {
      graphSeedHex: "000102030405060708090a0b0c0d0e0f",
      nonceHex: "0f0e0d0c0b0a09080706050403020100",
      pageBytes,
      mixRounds: 2,
      pages: 4,
      indices: [],
      segs: [],
    },
    {
      mutatePages(pages) {
        genesisPage = pages[0];
      },
    },
  );

  assert.ok(genesisPage instanceof Uint8Array);
  assert.equal(genesisPage.length, pageBytes);
  assert.equal(genesisPage.buffer.byteLength > genesisPage.length, true);
});
