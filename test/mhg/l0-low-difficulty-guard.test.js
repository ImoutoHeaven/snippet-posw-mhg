import test from "node:test";
import assert from "node:assert/strict";

import { LOW_PROFILE, assertLowProfileFixture } from "./helpers/low-profile.js";
import { verifyOpenBatchVector } from "../../lib/mhg/verify.js";
import { rpcCall, runWorkerFlow } from "./helpers/worker-rpc-harness.js";
import { runGlueFlow } from "./helpers/glue-flow-harness.js";
import {
  deriveLeafCountFromSteps,
  deriveGraphSeed16FromTicketNonce,
  deriveNonce16FromCommitNonce,
} from "./helpers/vector-derivation.js";
import vectors from "./fixtures/derivation-vectors.js";

const toHex = (bytes) => Buffer.from(bytes).toString("hex");

const openWitnessShape = (opens) =>
  opens.map((entry) => ({
    i: entry.i,
    seg: entry.seg,
    nodeKeys: Object.keys(entry.nodes || {}).sort(),
    proofLens: Object.values(entry.nodes || {}).map((node) =>
      Array.isArray(node && node.proof) ? node.proof.length : -1
    ),
  }));

test("helpers expose low-profile defaults", async () => {
  assert.equal(LOW_PROFILE.maxSteps, 128);
  assert.equal(LOW_PROFILE.maxPageBytes, 1024);
  assert.equal(LOW_PROFILE.hashcashBits, 0);
  await runWorkerFlow({
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 24,
    pageBytes: 64,
    mixRounds: 1,
    hashcashBits: 0,
  });
});

test("vector derivation helpers match fixed known vectors", async () => {
  const graphSeed = await deriveGraphSeed16FromTicketNonce(
    "dGVzdC10aWNrZXQ",
    "bm9uY2UtMTIzNDU2Nzg5MGFiYw"
  );
  assert.equal(toHex(graphSeed), vectors.graphSeed16_hex);

  const nonceA = await deriveNonce16FromCommitNonce("AAECAwQFBgcICQoLDA0ODxAREhM");
  assert.equal(toHex(nonceA), vectors.nonce16_from_b64u_ge16_hex);

  const nonceB = await deriveNonce16FromCommitNonce("AQI");
  assert.equal(toHex(nonceB), vectors.nonce16_from_short_hex);

  const nonceBad = await deriveNonce16FromCommitNonce("%%%");
  assert.equal(toHex(nonceBad), vectors.nonce16_from_invalid_b64_hex);
});

test("glue harness records payload-only INIT trace and restores globals", async () => {
  const prevDocument = globalThis.document;
  const prevWindow = globalThis.window;
  const prevNavigator = globalThis.navigator;

  const traces = await runGlueFlow({
    bootstrap: {
      bindingString: "binding-a",
      ticketB64: "dGVzdC10aWNrZXQ",
      steps: 64,
      segmentLen: 2,
      pageBytes: 240,
      mixRounds: 3,
      hashcashBits: 0,
    },
    challengeFixture: {
      done: true,
      indices: [],
      sid: "sid-1",
      cursor: 0,
      token: "tok-1",
    },
  });

  assert.deepEqual(Object.keys(traces.initPayloads[0]).sort(), [
    "bindingString",
    "ticketB64",
    "steps",
    "segmentLen",
    "pageBytes",
    "mixRounds",
    "hashcashBits",
  ].sort());
  assert.equal(globalThis.document, prevDocument);
  assert.equal(globalThis.window, prevWindow);
  assert.equal(globalThis.navigator, prevNavigator);
});

test("rpcCall waits for *_OK and removes listener after settle", async () => {
  const listeners = new Set();
  const worker = {
    __rid: 0,
    addEventListener(type, cb) {
      if (type === "message") listeners.add(cb);
    },
    removeEventListener(type, cb) {
      if (type === "message") listeners.delete(cb);
    },
    postMessage(msg) {
      const emit = (data) => {
        for (const cb of Array.from(listeners)) cb({ data });
      };
      queueMicrotask(() => emit({ type: "PROGRESS", rid: msg.rid }));
      queueMicrotask(() => emit({ type: "OPEN_PARTIAL", rid: msg.rid }));
      queueMicrotask(() => emit({ type: "OPEN_OK", rid: msg.rid, opens: [] }));
    },
  };

  const out = await rpcCall(worker, "OPEN", { indices: [1], segs: [1] }, { workerMessages: [] });
  assert.equal(out.type, "OPEN_OK");
  assert.equal(listeners.size, 0);
});

test("L0 matrix: worker output verifies with verifyOpenBatchVector", async () => {
  const matrix = [
    {
      ticketB64: "dGVzdC10aWNrZXQ",
      steps: 24,
      pageBytes: 64,
      mixRounds: 2,
      hashcashBits: LOW_PROFILE.hashcashBits,
      indices: [1, 12],
      segs: [1, 2],
    },
    {
      ticketB64: "dGVzdC10aWNrZXQ",
      steps: 47,
      pageBytes: 240,
      mixRounds: 2,
      hashcashBits: LOW_PROFILE.hashcashBits,
      indices: [2, 31],
      segs: [2, 5],
    },
    {
      ticketB64: "dGVzdC10aWNrZXQ",
      steps: 96,
      pageBytes: 512,
      mixRounds: 2,
      hashcashBits: LOW_PROFILE.hashcashBits,
      indices: [5, 48],
      segs: [5, 11],
    },
  ];

  for (const fixture of matrix) {
    assertLowProfileFixture(fixture);
    assert.equal(fixture.steps <= LOW_PROFILE.maxSteps, true);
    assert.equal(fixture.pageBytes <= LOW_PROFILE.maxPageBytes, true);
    assert.equal(fixture.hashcashBits, LOW_PROFILE.hashcashBits);
    const out = await runWorkerFlow({
      ticketB64: fixture.ticketB64,
      steps: fixture.steps,
      pageBytes: fixture.pageBytes,
      mixRounds: fixture.mixRounds,
      hashcashBits: fixture.hashcashBits,
      indices: fixture.indices,
      segs: fixture.segs,
    });

    assert.equal(typeof out.commit.rootB64, "string");
    assert.equal(typeof out.commit.nonce, "string");
    assert.equal(typeof out.open, "object");
    assert.notEqual(out.open, null);
    assert.equal(Array.isArray(out.open.opens), true);
    assert.equal(out.open.opens.length > 0, true);
    for (const open of out.open.opens) {
      assert.equal(Number.isInteger(open.i), true);
      assert.equal(Number.isInteger(open.seg), true);
      assert.equal(typeof open.nodes, "object");
      assert.notEqual(open.nodes, null);
      assert.equal(Array.isArray(open.nodes), false);
    }

    const graphSeed = await deriveGraphSeed16FromTicketNonce(fixture.ticketB64, out.commit.nonce);
    const nonce = await deriveNonce16FromCommitNonce(out.commit.nonce);
    const leafCount = deriveLeafCountFromSteps(fixture.steps);

    const verify = await verifyOpenBatchVector({
      rootB64: out.commit.rootB64,
      leafCount,
      graphSeed,
      nonce,
      pageBytes: fixture.pageBytes,
      opens: out.open.opens,
    });
    assert.equal(verify.ok, true);
  }
});

test("L0 deterministic lock: repeated identical flow keeps root and OPEN shape", async () => {
  const fixture = {
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 24,
    pageBytes: 64,
    mixRounds: 2,
    hashcashBits: LOW_PROFILE.hashcashBits,
    indices: [1, 12],
    segs: [1, 2],
  };

  const first = await runWorkerFlow(fixture);
  const second = await runWorkerFlow(fixture);

  assert.equal(first.commit.rootB64, second.commit.rootB64);
  assert.deepEqual(openWitnessShape(first.open.opens), openWitnessShape(second.open.opens));
});
