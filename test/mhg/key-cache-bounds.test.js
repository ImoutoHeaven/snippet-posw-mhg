import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const KEY_CACHE_MAX_ENTRIES = 256;
const SAMPLE_CONTEXTS = 320;

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const keyIdFor = (graphSeed, nonce) => `${bytesToHex(graphSeed)}:${bytesToHex(nonce)}`;

const makeSeed16 = (base, salt = 0) => {
  const out = new Uint8Array(16);
  out[0] = base & 0xff;
  out[1] = (base >>> 8) & 0xff;
  out[2] = (base >>> 16) & 0xff;
  out[3] = (base >>> 24) & 0xff;
  for (let i = 4; i < out.length; i += 1) {
    out[i] = (salt + i) & 0xff;
  }
  return out;
};

const withTrackedMaps = async ({ stackMarker, run }) => {
  const OriginalMap = globalThis.Map;
  const tracked = [];

  class TrackingMap extends OriginalMap {
    constructor(...args) {
      super(...args);
      const stack = new Error().stack || "";
      if (stack.includes(stackMarker)) {
        tracked.push(this);
      }
    }
  }

  globalThis.Map = TrackingMap;
  try {
    return await run(tracked);
  } finally {
    globalThis.Map = OriginalMap;
  }
};

test("mix-aes key cache stays bounded across many contexts", async () => {
  await withTrackedMaps({
    stackMarker: "/lib/mhg/mix-aes.js",
    run: async (tracked) => {
      const modulePath = join(repoRoot, "lib/mhg/mix-aes.js");
      const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}-${Math.random()}`);
      const importMapCount = tracked.length;
      assert.ok(importMapCount >= 1, "expected to track mix-aes key cache map");

      const { createMixContext } = mod;
      const insertedKeyIds = [];
      for (let i = 0; i < SAMPLE_CONTEXTS; i += 1) {
        const graphSeed = makeSeed16(i, 0x11);
        const nonce = makeSeed16(i + 10_000, 0x77);
        insertedKeyIds.push(keyIdFor(graphSeed, nonce));
        await createMixContext({
          graphSeed,
          nonce,
        });
      }

      const keyCache = tracked[importMapCount - 1];
      const oldestSurvivorIndex = SAMPLE_CONTEXTS - KEY_CACHE_MAX_ENTRIES;
      assert.equal(keyCache.size, KEY_CACHE_MAX_ENTRIES, `keyCache must be bounded, got ${keyCache.size}`);
      assert.equal(keyCache.has(insertedKeyIds[0]), false, "oldest key should be evicted");
      assert.equal(keyCache.has(insertedKeyIds[oldestSurvivorIndex]), true, "first surviving key should remain");
      assert.equal(keyCache.has(insertedKeyIds[SAMPLE_CONTEXTS - 1]), true, "newest key should remain");
      assert.equal(keyCache.keys().next().value, insertedKeyIds[oldestSurvivorIndex], "FIFO eviction order must hold");
    },
  });
});

test("worker key cache stays bounded across many fixtures", async () => {
  await withTrackedMaps({
    stackMarker: "/esm/mhg-worker.js",
    run: async (tracked) => {
      const modulePath = join(repoRoot, "esm/mhg-worker.js");
      const mod = await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}-${Math.random()}`);
      const importMapCount = tracked.length;
      assert.ok(importMapCount >= 1, "expected to track worker key cache map");

      const { buildCrossEndFixture } = mod;
      const insertedKeyIds = [];
      for (let i = 0; i < SAMPLE_CONTEXTS; i += 1) {
        const graphSeed = makeSeed16(i);
        const nonce = makeSeed16(i + 20_000, 0xa5);
        insertedKeyIds.push(keyIdFor(graphSeed, nonce));
        await buildCrossEndFixture({
          graphSeedHex: bytesToHex(graphSeed),
          nonceHex: bytesToHex(nonce),
          pageBytes: 64,
          mixRounds: 2,
          pages: 4,
          indices: [],
          segs: [],
        });
      }

      const keyCache = tracked[importMapCount - 1];
      const oldestSurvivorIndex = SAMPLE_CONTEXTS - KEY_CACHE_MAX_ENTRIES;
      assert.equal(keyCache.size, KEY_CACHE_MAX_ENTRIES, `keyCache must be bounded, got ${keyCache.size}`);
      assert.equal(keyCache.has(insertedKeyIds[0]), false, "oldest key should be evicted");
      assert.equal(keyCache.has(insertedKeyIds[oldestSurvivorIndex]), true, "first surviving key should remain");
      assert.equal(keyCache.has(insertedKeyIds[SAMPLE_CONTEXTS - 1]), true, "newest key should remain");
      assert.equal(keyCache.keys().next().value, insertedKeyIds[oldestSurvivorIndex], "FIFO eviction order must hold");
    },
  });
});
