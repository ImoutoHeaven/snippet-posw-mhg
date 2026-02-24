import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

import { mixPage } from "../../lib/mhg/mix-aes.js";
import { parentsOf } from "../../lib/mhg/graph.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const encoder = new TextEncoder();

const b64uToBytes = (value) => {
  let b64 = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Uint8Array.from(Buffer.from(b64, "base64"));
};

const digest = async (...chunks) => {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return new Uint8Array(await webcrypto.subtle.digest("SHA-256", out));
};

const deriveGraphSeed16 = async (ticketB64, nonceString) => {
  const d = await digest(
    encoder.encode("mhg|graph|v2|"),
    encoder.encode(ticketB64),
    encoder.encode("|"),
    encoder.encode(nonceString),
  );
  return d.slice(0, 16);
};

const deriveNonce16 = async (nonceString) => {
  const raw = b64uToBytes(nonceString);
  if (raw.length >= 16) return raw.slice(0, 16);
  return (await digest(raw)).slice(0, 16);
};

const runWorkerFlow = async ({ ticketB64, steps, pageBytes = 64, mixRounds = 2, hashcashBits = 0, indices, segs }) => {
  const prevSelf = globalThis.self;
  const prevPostMessage = globalThis.postMessage;
  const prevAtob = globalThis.atob;
  const prevBtoa = globalThis.btoa;
  const prevCrypto = globalThis.crypto;

  if (!globalThis.atob) {
    globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  }
  if (!globalThis.btoa) {
    globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  }
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }

  const pending = new Map();
  let rid = 0;
  const workerSelf = { addEventListener() {} };

  globalThis.self = workerSelf;
  globalThis.postMessage = (msg) => {
    if (msg && msg.type === "PROGRESS") return;
    const entry = pending.get(msg && msg.rid);
    if (!entry) return;
    pending.delete(msg.rid);
    if (msg.type === "ERROR") {
      entry.reject(new Error(msg.message || "worker error"));
      return;
    }
    entry.resolve(msg);
  };

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
    await call("INIT", { ticketB64, steps, pageBytes, mixRounds, hashcashBits });
    const commit = await call("COMMIT");
    const open = await call("OPEN", { indices, segs });
    return { commit, open };
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
  }
};

const openWitnessShape = (opens) =>
  opens.map((entry) => ({
    i: entry.i,
    seg: entry.seg,
    nodeKeys: Object.keys(entry.nodes || {}).sort(),
    proofLens: Object.values(entry.nodes || {}).map((node) =>
      Array.isArray(node && node.proof) ? node.proof.length : -1
    ),
  }));

const buildEqSet = (index, segmentLen) => {
  const start = Math.max(1, index - segmentLen + 1);
  const out = [];
  for (let i = start; i <= index; i += 1) out.push(i);
  return out;
};

const expectedNeedKeysFromOpen = async ({ open, graphSeed }) => {
  const need = new Set();
  const eqSet = buildEqSet(open.i, open.seg);
  const p2ByEquation = new Map();
  for (const j of eqSet) {
    const prevNode = open.nodes[String(j - 1)];
    const prevPage = j >= 3 ? b64uToBytes(prevNode && prevNode.pageB64) : undefined;
    const parents = await parentsOf(j, graphSeed, prevPage);
    need.add(j);
    need.add(parents.p0);
    need.add(parents.p1);
    need.add(parents.p2);
    p2ByEquation.set(j, parents.p2);
  }
  const sorted = Array.from(need).sort((a, b) => a - b).map(String);
  return { sorted, p2ByEquation };
};

const verifyOpenEquationsWithServer = async ({ open, graphSeed, nonce, pageBytes = 64, mixRounds = 2 }) => {
  const readNodePage = (idx) => {
    const node = open.nodes[String(idx)];
    if (!node) throw new Error(`missing node ${idx} from worker witness`);
    return b64uToBytes(node.pageB64);
  };

  const eqSet = buildEqSet(open.i, open.seg);
  for (const i of eqSet) {
    const prevPage = i >= 3 ? readNodePage(i - 1) : undefined;
    const parent = await parentsOf(i, graphSeed, prevPage);
    const expected = await mixPage({
      i,
      p0: readNodePage(parent.p0),
      p1: readNodePage(parent.p1),
      p2: readNodePage(parent.p2),
      graphSeed,
      nonce,
      pageBytes,
      mixRounds,
    });
    assert.deepEqual(expected, readNodePage(i));
  }
};

test("fixed vectors produce cross-end consistent verification", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 127;
  const indices = [1, 64, 127];
  const segs = [2, 2, 2];
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices, segs });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const nonce = await deriveNonce16(commit.nonce);
  for (const entry of open.opens) {
    await verifyOpenEquationsWithServer({ open: entry, graphSeed, nonce });
  }
});

test("repeated identical worker flow yields same root and OPEN witness shape", async () => {
  const fixture = {
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 127,
    indices: [1, 64, 127],
    segs: [2, 2, 2],
  };

  const first = await runWorkerFlow(fixture);
  const second = await runWorkerFlow(fixture);

  assert.equal(first.commit.rootB64, second.commit.rootB64);
  assert.deepEqual(openWitnessShape(first.open.opens), openWitnessShape(second.open.opens));
});

test("1-bit tamper is rejected by server verification", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 127;
  const indices = [64];
  const segs = [2];
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices, segs });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const nonce = await deriveNonce16(commit.nonce);
  nonce[0] ^= 0x01;
  await assert.rejects(
    verifyOpenEquationsWithServer({ open: open.opens[0], graphSeed, nonce }),
    /Expected values to be strictly deep-equal/
  );
});

test("server mixPage matches worker bytes for identical inputs", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 32;
  const index = 17;
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices: [index], segs: [2] });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const nonce = await deriveNonce16(commit.nonce);
  const parent = await parentsOf(index, graphSeed, b64uToBytes(open.opens[0].nodes[String(index - 1)].pageB64));
  const entry = open.opens[0];

  const readNodePage = (idx) => {
    const node = entry.nodes[String(idx)];
    assert.ok(node, `missing node ${idx} from worker witness`);
    return b64uToBytes(node.pageB64);
  };

  const serverPage = await mixPage({
    i: index,
    p0: readNodePage(parent.p0),
    p1: readNodePage(parent.p1),
    p2: readNodePage(parent.p2),
    graphSeed,
    nonce,
    pageBytes: 64,
    mixRounds: 2,
  });

  assert.deepEqual(serverPage, readNodePage(index));
});

test("worker rejects OPEN segment lengths outside 2..16", async () => {
  const base = {
    ticketB64: "dGVzdC10aWNrZXQ",
    steps: 32,
    indices: [17],
  };

  await assert.rejects(
    runWorkerFlow({ ...base, segs: [1] }),
    /segs invalid/
  );
  await assert.rejects(
    runWorkerFlow({ ...base, segs: [17] }),
    /segs invalid/
  );
});

test("worker OPEN includes dynamic parents with canonical unique key order", async () => {
  const ticketB64 = "dGVzdC10aWNrZXQ";
  const steps = 48;
  const index = 31;
  const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices: [index], segs: [2] });
  const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
  const entry = open.opens[0];

  const expected = await expectedNeedKeysFromOpen({ open: entry, graphSeed });
  const actual = Object.keys(entry.nodes || {});
  assert.equal(entry.seg, 2);
  assert.deepEqual(actual, expected.sorted);
  assert.equal(actual.length, new Set(actual).size);

  const eqSet = buildEqSet(entry.i, entry.seg);
  for (const j of eqSet) {
    assert.ok(entry.nodes[String(expected.p2ByEquation.get(j))], `missing dynamic p2 node for equation ${j}`);
  }
});

test("randomized parity: worker/server parent outputs match for all i in [1..L]", async () => {
  const deterministicSteps = [12, 15, 19, 14, 18];
  for (let round = 0; round < deterministicSteps.length; round += 1) {
    const ticketB64 = `dGVzdC10aWNrZXQ-${round}`;
    const steps = deterministicSteps[round];
    const indices = Array.from({ length: steps }, (_, idx) => idx + 1);
    const segs = Array.from({ length: steps }, () => 2);
    const { commit, open } = await runWorkerFlow({ ticketB64, steps, indices, segs });
    const graphSeed = await deriveGraphSeed16(ticketB64, commit.nonce);
    const nonce = await deriveNonce16(commit.nonce);

    for (const entry of open.opens) {
      const expected = await expectedNeedKeysFromOpen({ open: entry, graphSeed });
      assert.deepEqual(Object.keys(entry.nodes || {}), expected.sorted);
      await verifyOpenEquationsWithServer({ open: entry, graphSeed, nonce });
    }
  }
});
