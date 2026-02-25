import test from "node:test";
import assert from "node:assert/strict";

import { staticParentsOf, deriveDynamicParent2 } from "../../lib/mhg/graph.js";
import { verifyOpenBatchVector } from "../../lib/mhg/verify.js";
import { runWorkerFlow } from "./helpers/worker-rpc-harness.js";
import {
  deriveLeafCountFromSteps,
  deriveGraphSeed16FromTicketNonce,
  deriveNonce16FromCommitNonce,
} from "./helpers/vector-derivation.js";

const VERIFY_MAX_MS = Number(process.env.MHG_VERIFY_MAX_MS || 2500);
const PARENT_MAX_MS = Number(process.env.MHG_PARENT_MAX_MS || 1800);

const nowMs = () => Date.now();

const makeVerifyFixture = async () => {
  const fixture = {
    ticketB64: "dGVzdC10aWNrZXQtcGVyZi1ndWFyZA",
    steps: 127,
    pageBytes: 512,
    mixRounds: 2,
    hashcashBits: 0,
    indices: [95, 111, 127],
    segs: [16, 16, 16],
  };
  const out = await runWorkerFlow(fixture);
  const graphSeed = await deriveGraphSeed16FromTicketNonce(fixture.ticketB64, out.commit.nonce);
  const nonce = await deriveNonce16FromCommitNonce(out.commit.nonce);
  return {
    rootB64: out.commit.rootB64,
    leafCount: deriveLeafCountFromSteps(fixture.steps),
    graphSeed,
    nonce,
    pageBytes: fixture.pageBytes,
    mixRounds: fixture.mixRounds,
    opens: out.open.opens,
  };
};

test("perf gate: verifyOpenBatchVector stays within throughput budget", { timeout: 30000 }, async () => {
  const vector = await makeVerifyFixture();
  const started = nowMs();
  const out = await verifyOpenBatchVector(vector);
  const elapsedMs = nowMs() - started;

  assert.equal(out.ok, true);
  assert.ok(
    elapsedMs <= VERIFY_MAX_MS,
    `verifyOpenBatchVector took ${elapsedMs}ms (budget ${VERIFY_MAX_MS}ms)`
  );
});

test("perf gate: explicit v4 parent resolver loop for i>=3 stays within budget", { timeout: 30000 }, async () => {
  const seed = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  const pageBytes = 512;
  const iterations = 900;
  const pages = Array.from({ length: iterations + 3 }, () => new Uint8Array(pageBytes));

  const started = nowMs();
  for (let i = 3; i < 3 + iterations; i += 1) {
    pages[i - 1][i % pageBytes] = i & 0xff;
    const { p0, p1 } = await staticParentsOf(i, seed);
    await deriveDynamicParent2({
      i,
      seed,
      pageBytes,
      p0,
      p1,
      p0Page: pages[p0],
      p1Page: pages[p1],
    });
  }
  const elapsedMs = nowMs() - started;

  assert.ok(
    elapsedMs <= PARENT_MAX_MS,
    `explicit v4 parent resolver loop took ${elapsedMs}ms (budget ${PARENT_MAX_MS}ms)`
  );
});
