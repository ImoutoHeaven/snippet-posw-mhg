import test from "node:test";
import assert from "node:assert/strict";

test("mix function deterministic under same inputs", async () => {
  const { makeGenesisPage, mixPage } = await import("../../lib/mhg/mix-aes.js");

  const graphSeed = new Uint8Array(16);
  const nonce = new Uint8Array(16);
  const pageBytes = 4096;

  const g = await makeGenesisPage({ graphSeed, nonce, pageBytes });
  const a = await mixPage({ i: 1, p0: g, p1: g, p2: g, graphSeed, nonce, pageBytes });
  const b = await mixPage({ i: 1, p0: g, p1: g, p2: g, graphSeed, nonce, pageBytes });

  assert.deepEqual(Buffer.from(a), Buffer.from(b));
});

test("deriveKey rejects i outside uint32 range", async () => {
  const { deriveKey } = await import("../../lib/mhg/mix-aes.js");

  await assert.rejects(
    deriveKey({ graphSeed: new Uint8Array(16), nonce: new Uint8Array(16), i: 2 ** 32 }),
    /non-negative uint32 integer/,
  );
});
