import test from "node:test";
import assert from "node:assert/strict";

import { LOW_PROFILE, assertLowProfileFixture } from "./helpers/low-profile.js";
import { runWorkerFlow } from "./helpers/worker-rpc-harness.js";
import { runGlueFlow } from "./helpers/glue-flow-harness.js";

test("L2 multi-worker race has one winner and disposes losers", async () => {
  const fixture = {
    bindingString: "binding-l2-race",
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: LOW_PROFILE.defaults.steps,
    segmentLen: 2,
    pageBytes: LOW_PROFILE.defaults.pageBytes,
    mixRounds: LOW_PROFILE.defaults.mixRounds,
    hashcashBits: LOW_PROFILE.hashcashBits,
  };
  assertLowProfileFixture(fixture);

  const traces = await runGlueFlow({
    bootstrap: fixture,
    challengeFixture: {
      done: true,
      indices: [],
      segs: [],
      sid: "sid-l2-race",
      cursor: 0,
      token: "tok-l2-race",
    },
    forceWorkerCount: 3,
    workerScript: [
      {
        workerId: "w-fast",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "AQ", nonce: "winner-nonce" } },
        ],
      },
      {
        workerId: "w-slow-a",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "Ag", nonce: "loser-a" } },
        ],
      },
      {
        workerId: "w-slow-b",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "Aw", nonce: "loser-b" } },
        ],
      },
    ],
  });

  assert.equal(traces.raceTrace.winnerIds[0], "w-fast");
  const commitReq = traces.endpointRequests.find((req) => req.pathname === "/__pow/commit");
  const winnerExpectedById = {
    "w-fast": { rootB64: "AQ", nonce: "winner-nonce" },
  };
  const acceptedWinner = winnerExpectedById[traces.raceTrace.winnerIds[0]];
  assert.equal(commitReq.body.rootB64, acceptedWinner.rootB64);
  assert.equal(commitReq.body.nonce, acceptedWinner.nonce);
  assert.deepEqual(traces.raceTrace.raceDisposedIds, ["w-slow-a", "w-slow-b"]);
  assert.deepEqual(traces.raceTrace.raceCanceledIds, ["w-slow-a", "w-slow-b"]);
  assert.deepEqual(traces.raceTrace.raceTerminatedIds, ["w-slow-a", "w-slow-b"]);
  assert.equal(traces.raceTrace.ignoredLateMessages, 0);
  assert.equal(traces.callCounts.commit, 1);
});

test("L2 cancel/dispose prevents ghost messages", async () => {
  const fixture = {
    bindingString: "binding-l2-ghost",
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 96,
    segmentLen: 3,
    pageBytes: 512,
    mixRounds: 1,
    hashcashBits: LOW_PROFILE.hashcashBits,
  };
  assertLowProfileFixture(fixture);

  const traces = await runGlueFlow({
    bootstrap: fixture,
    challengeFixture: {
      done: true,
      indices: [],
      segs: [],
      sid: "sid-l2-ghost",
      cursor: 0,
      token: "tok-l2-ghost",
    },
    forceWorkerCount: 3,
    workerScript: [
      {
        workerId: "w-win",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "COMMIT_OK", rootB64: "BA", nonce: "winner" } },
        ],
      },
      {
        workerId: "w-ghost-a",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "PROGRESS", phase: "chain", done: 1, total: 2 } },
          { on: "POST_DISPOSE", msg: { type: "COMMIT_OK", rootB64: "late", nonce: "ghost-a" } },
        ],
      },
      {
        workerId: "w-ghost-b",
        events: [
          { on: "INIT", msg: { type: "INIT_OK" } },
          { on: "COMMIT", msg: { type: "PROGRESS", phase: "chain", done: 1, total: 2 } },
          { on: "POST_DISPOSE", msg: { type: "COMMIT_OK", rootB64: "late", nonce: "ghost-b" } },
        ],
      },
    ],
  });

  assert.equal(traces.raceTrace.ignoredLateMessages, 2);
  assert.deepEqual(traces.raceTrace.ignoredLateWorkerIds, ["w-ghost-a", "w-ghost-b"]);
  assert.equal(traces.raceTrace.winnerIds.length, 1);
  assert.deepEqual(traces.raceTrace.raceDisposedIds, ["w-ghost-a", "w-ghost-b"]);
  const commitReq = traces.endpointRequests.find((req) => req.pathname === "/__pow/commit");
  assert.equal(commitReq.body.nonce, "winner");
});

test("L2 one real-worker smoke remains low-difficulty", async () => {
  const fixture = {
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 64,
    pageBytes: 240,
    mixRounds: 3,
    hashcashBits: LOW_PROFILE.hashcashBits,
    indices: [16],
    segs: [4],
  };
  assertLowProfileFixture(fixture);

  const out = await runWorkerFlow(fixture);
  assert.equal(typeof out.commit.rootB64, "string");
  assert.equal(typeof out.commit.nonce, "string");
  assert.equal(out.open.opens[0].seg, 4);
});
