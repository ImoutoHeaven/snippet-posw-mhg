import test from "node:test";
import assert from "node:assert/strict";

import { LOW_PROFILE, assertLowProfileFixture } from "./helpers/low-profile.js";
import { runWorkerFlow } from "./helpers/worker-rpc-harness.js";
import { runGlueFlow } from "./helpers/glue-flow-harness.js";
import challengeRequestBaseline from "./fixtures/challenge-request-baseline.js";

const scriptedEchoWorker = ({ msg }) => {
  if (msg.type === "INIT") {
    return { type: "INIT_OK", rid: msg.rid };
  }
  if (msg.type === "COMMIT") {
    return { type: "COMMIT_OK", rid: msg.rid, rootB64: "AQ", nonce: "scripted-nonce-b" };
  }
  if (msg.type === "OPEN") {
    return {
      type: "OPEN_OK",
      rid: msg.rid,
      opens: (msg.indices || []).map((i, pos) => ({
        i,
        seg: msg.segs[pos],
        nodes: {
          "0": { pageB64: "AA", proof: [] },
          [String(i)]: { pageB64: "AA", proof: [] },
        },
      })),
    };
  }
  if (msg.type === "DISPOSE" || msg.type === "CANCEL") {
    return { type: `${msg.type}_OK`, rid: msg.rid };
  }
  return null;
};

test("L1 commit->challenge->open flow preserves server values", async () => {
  const assertFlow = ({ bootstrap, challengeFixture, workerScript }) => {
    return runGlueFlow({ bootstrap, challengeFixture, workerScript });
  };

  assertLowProfileFixture({
    steps: LOW_PROFILE.defaults.steps,
    pageBytes: LOW_PROFILE.defaults.pageBytes,
    hashcashBits: LOW_PROFILE.hashcashBits,
  });
  const caseA = await assertFlow({
    bootstrap: {
      bindingString: "binding-a",
      ticketB64: "dGVzdC10aWNrZXQ",
      steps: LOW_PROFILE.defaults.steps,
      segmentLen: 2,
      pageBytes: LOW_PROFILE.defaults.pageBytes,
      mixRounds: LOW_PROFILE.defaults.mixRounds,
      hashcashBits: LOW_PROFILE.hashcashBits,
      pathHash: "pathhash-a",
    },
    challengeFixture: {
      done: false,
      indices: [32],
      segs: [7],
      sid: "sid-a",
      cursor: 0,
      token: "tok-a",
    },
    workerScript: scriptedEchoWorker,
  });

  const reqByPathA = Object.fromEntries(caseA.endpointRequests.map((req) => [req.pathname, req]));
  const callOrderA = caseA.endpointRequests.map((req) => req.pathname);
  assert.deepEqual(callOrderA, ["/__pow/commit", "/__pow/challenge", "/__pow/open"]);
  assert.equal(caseA.endpointRequests.length, 3);

  assert.equal(reqByPathA["/__pow/commit"].method, "POST");
  assert.equal(reqByPathA["/__pow/challenge"].method, "POST");
  assert.equal(reqByPathA["/__pow/open"].method, "POST");

  assert.deepEqual(
    Object.keys(reqByPathA["/__pow/commit"].body).sort(),
    ["nonce", "pathHash", "rootB64", "ticketB64"],
  );
  assert.deepEqual(Object.keys(reqByPathA["/__pow/challenge"].body), []);
  assert.deepEqual(Object.keys(reqByPathA["/__pow/open"].body).sort(), ["cursor", "opens", "sid", "token"]);
  assert.deepEqual(reqByPathA["/__pow/challenge"].body, challengeRequestBaseline);

  const mappingRowsA = [
    [caseA.runPowArgs.bindingString, caseA.initPayloads[0].bindingString, "strict"],
    [caseA.runPowArgs.steps, caseA.initPayloads[0].steps, "strict"],
    [caseA.runPowArgs.segmentLen, caseA.initPayloads[0].segmentLen, "strict"],
    [caseA.runPowArgs.pageBytes, caseA.initPayloads[0].pageBytes, "strict"],
    [caseA.runPowArgs.mixRounds, caseA.initPayloads[0].mixRounds, "strict"],
    [caseA.runPowArgs.hashcashBits, caseA.initPayloads[0].hashcashBits, "strict"],
    [caseA.runPowArgs.pathHash, reqByPathA["/__pow/commit"].body.pathHash, "strict"],
    [caseA.challengeFixture.indices, caseA.openPayloads[0].indices, "deep"],
    [caseA.challengeFixture.segs, caseA.openPayloads[0].segs, "deep"],
    [caseA.challengeFixture.segs, reqByPathA["/__pow/open"].body.opens.map((x) => x.seg), "deep"],
    [caseA.workerCommitResults[0].rootB64, reqByPathA["/__pow/commit"].body.rootB64, "strict"],
    [caseA.workerCommitResults[0].nonce, reqByPathA["/__pow/commit"].body.nonce, "strict"],
  ];
  for (const [src, target, mode] of mappingRowsA) {
    if (mode === "deep") {
      assert.deepEqual(target, src);
    } else {
      assert.equal(target, src);
    }
  }
  assert.equal(caseA.callCounts.commit, 1);
  assert.equal(caseA.callCounts.challenge, 1);
  assert.equal(caseA.callCounts.open, 1);

  assertLowProfileFixture({ steps: 127, pageBytes: 1001, hashcashBits: 0 });
  const caseB = await assertFlow({
    bootstrap: {
      bindingString: "binding-b",
      ticketB64: "dGVzdC10aWNrZXQ",
      steps: 127,
      segmentLen: 9,
      pageBytes: 1001,
      mixRounds: 0,
      hashcashBits: 0,
      pathHash: "pathhash-b",
    },
    challengeFixture: {
      done: false,
      indices: [33],
      segs: [19],
      sid: "sid-b",
      cursor: 0,
      token: "tok-b",
    },
    workerScript: scriptedEchoWorker,
  });

  const reqByPathB = Object.fromEntries(caseB.endpointRequests.map((req) => [req.pathname, req]));
  assert.equal(caseB.initPayloads[0].steps, 127);
  assert.equal(caseB.initPayloads[0].pageBytes, 1001);
  assert.equal(caseB.initPayloads[0].mixRounds, 0);
  assert.equal(caseB.initPayloads[0].hashcashBits, 0);
  assert.deepEqual(caseB.openPayloads[0].indices, [33]);
  assert.deepEqual(caseB.openPayloads[0].segs, [19]);
  assert.equal(caseB.workerCommitResults[0].rootB64, reqByPathB["/__pow/commit"].body.rootB64);
  assert.equal(caseB.workerCommitResults[0].nonce, reqByPathB["/__pow/commit"].body.nonce);
  assert.deepEqual(reqByPathB["/__pow/open"].body.opens.map((x) => x.seg), [19]);
  assert.equal(caseB.callCounts.commit, 1);
  assert.equal(caseB.callCounts.challenge, 1);
  assert.equal(caseB.callCounts.open, 1);
});

test("real worker OPEN returns seg unchanged", async () => {
  assertLowProfileFixture({ steps: 64, pageBytes: 240, hashcashBits: 0 });
  const out = await runWorkerFlow({
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 64,
    pageBytes: 240,
    mixRounds: 2,
    hashcashBits: 0,
    indices: [32],
    segs: [16],
  });
  assert.equal(out.open.opens[0].seg, 16);
});

test("worker-count policy lock stays unchanged for hashcashBits=0 low-profile matrix", async () => {
  const matrix = [
    { steps: 24, pageBytes: 64 },
    { steps: 64, pageBytes: 240 },
    { steps: 96, pageBytes: 1008 },
  ];

  for (const row of matrix) {
    assertLowProfileFixture({
      steps: row.steps,
      pageBytes: row.pageBytes,
      hashcashBits: LOW_PROFILE.hashcashBits,
    });
    const traces = await runGlueFlow({
      bootstrap: {
        bindingString: `binding-policy-${row.steps}-${row.pageBytes}`,
        ticketB64: "dGVzdC10aWNrZXQ",
        steps: row.steps,
        segmentLen: 2,
        pageBytes: row.pageBytes,
        mixRounds: 1,
        hashcashBits: LOW_PROFILE.hashcashBits,
        pathHash: `pathhash-policy-${row.steps}-${row.pageBytes}`,
      },
      challengeFixture: {
        done: false,
        indices: [1],
        segs: [1],
        sid: `sid-policy-${row.steps}-${row.pageBytes}`,
        cursor: 0,
        token: `tok-policy-${row.steps}-${row.pageBytes}`,
      },
      workerScript: scriptedEchoWorker,
    });

    assert.equal(traces.initPayloads.length, 1);
    assert.equal(traces.callCounts.commit, 1);
    assert.equal(traces.callCounts.challenge, 1);
    assert.equal(traces.callCounts.open, 1);
  }
});
