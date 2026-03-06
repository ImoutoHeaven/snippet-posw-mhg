import test from "node:test";
import assert from "node:assert/strict";

import { LOW_PROFILE, assertLowProfileFixture } from "./helpers/low-profile.js";
import { cleanupWorkerGlobals, createTestWorker, rpcCall } from "./helpers/worker-rpc-harness.js";
import { runGlueFlow } from "./helpers/glue-flow-harness.js";

const CANCEL_MAX_MS = Number(process.env.MHG_CANCEL_MAX_MS || 1000);
const nowMs = () => Date.now();

const runWorkerFlow = async ({ ticketB64, steps, pageBytes, mixRounds, hashcashX, indices, segs }) => {
  const worker = await createTestWorker();
  try {
    await rpcCall(worker, "INIT", { ticketB64, steps, pageBytes, mixRounds, hashcashX });
    const commit = await rpcCall(worker, "COMMIT");
    const open =
      Array.isArray(indices) && Array.isArray(segs)
        ? await rpcCall(worker, "OPEN", { indices, segs })
        : null;
    return { commit, open };
  } finally {
    worker.terminate();
    await cleanupWorkerGlobals();
  }
};

test("L2 high-hashcash commit search stays serial", async () => {
  const fixture = {
    bindingString: "binding-l2-serial",
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 96,
    segmentLen: 3,
    pageBytes: 512,
    mixRounds: 1,
    hashcashX: 8,
  };

  const traces = await runGlueFlow({
    bootstrap: fixture,
    challengeFixture: {
      done: true,
      indices: [],
      segs: [],
      sid: "sid-l2-serial",
      cursor: 0,
      token: "tok-l2-serial",
    },
    workerScript: [
      {
        workerId: "w-only",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "AQ", nonce: "serial-nonce" } },
        ],
      },
      {
        workerId: "w-should-not-init-a",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "BA", nonce: "extra-a" } },
        ],
      },
      {
        workerId: "w-should-not-init-b",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "CA", nonce: "extra-b" } },
        ],
      },
    ],
  });

  assert.deepEqual(traces.initWorkerIds, ["w-only"]);
  assert.deepEqual(traces.workerCommitResults, [{ rootB64: "AQ", nonce: "serial-nonce" }]);
  const commitReq = traces.endpointRequests.find((req) => req.pathname === "/__pow/commit");
  assert.equal(commitReq.body.rootB64, "AQ");
  assert.equal(commitReq.body.nonce, "serial-nonce");
  assert.deepEqual(traces.raceTrace.raceDisposedIds, []);
  assert.deepEqual(traces.raceTrace.raceCanceledIds, []);
  assert.deepEqual(traces.raceTrace.raceTerminatedIds, []);
  assert.equal(traces.callCounts.commit, 1);
});

test("L2 one real-worker smoke remains low-difficulty", async () => {
  const fixture = {
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 64,
    pageBytes: 240,
    mixRounds: 3,
    hashcashX: LOW_PROFILE.hashcashX,
    indices: [16],
    segs: [4],
  };
  assertLowProfileFixture(fixture);

  const out = await runWorkerFlow(fixture);
  assert.equal(typeof out.commit.rootB64, "string");
  assert.equal(typeof out.commit.nonce, "string");
  assert.equal(out.open.opens[0].seg, 4);
});

test("L2 cancel latency stays bounded while worker is under load", { timeout: 30000 }, async () => {
  const worker = await createTestWorker();
  try {
    await rpcCall(worker, "INIT", {
      ticketB64: "dGVzdC10aWNrZXQtbDItY2FuY2Vs",
      steps: 384,
      pageBytes: 1024,
      mixRounds: 3,
      hashcashX: 256,
    });

    const commitPromise = rpcCall(worker, "COMMIT");
    await new Promise((resolve) => setTimeout(resolve, 0));

    const cancelStart = nowMs();
    await rpcCall(worker, "CANCEL");
    const cancelAckMs = nowMs() - cancelStart;
    assert.ok(cancelAckMs <= CANCEL_MAX_MS, `cancel ACK took ${cancelAckMs}ms (budget ${CANCEL_MAX_MS}ms)`);

    const commitAbortStart = nowMs();
    await assert.rejects(commitPromise, /mhg aborted/);
    const commitAbortMs = nowMs() - commitAbortStart;
    assert.ok(commitAbortMs <= CANCEL_MAX_MS, `commit abort took ${commitAbortMs}ms (budget ${CANCEL_MAX_MS}ms)`);
  } finally {
    worker.terminate();
    await cleanupWorkerGlobals();
  }
});
