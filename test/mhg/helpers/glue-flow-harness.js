import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

let glueGlobalState = null;

const b64u = (value) =>
  Buffer.from(String(value), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const makeModuleUrl = (workerUrl) =>
  `data:text/javascript,${encodeURIComponent(`export const workerUrl = "${workerUrl}";`)}`;

const setCrypto = (value) => {
  Object.defineProperty(globalThis, "crypto", { value, configurable: true });
};

const resolveWorkerScript = (workerScript, index) => {
  if (Array.isArray(workerScript)) {
    return workerScript[index] || workerScript[workerScript.length - 1] || null;
  }
  if (workerScript && typeof workerScript === "object" && Array.isArray(workerScript.workers)) {
    return workerScript.workers[index] || workerScript.workers[workerScript.workers.length - 1] || null;
  }
  return workerScript || null;
};

const createFakeWorkerClass = ({ traces, workerScript }) => {
  let nextWorkerIndex = 0;

  class FakeWorker {
    constructor() {
      const workerIndex = nextWorkerIndex++;
      const scriptConfig = resolveWorkerScript(workerScript, workerIndex);
      this.listeners = new Map();
      this.workerId =
        (scriptConfig && typeof scriptConfig === "object" && scriptConfig.workerId) ||
        `fake-worker-${workerIndex + 1}`;
      this.scriptByType = new Map();
      this.scriptHandler = typeof scriptConfig === "function" ? scriptConfig : null;
      this.disposed = false;
      this.canceled = false;
      if (scriptConfig && typeof scriptConfig === "object" && Array.isArray(scriptConfig.events)) {
        for (const event of scriptConfig.events) {
          const key = String(event.on || "");
          const list = this.scriptByType.get(key) || [];
          list.push(event.msg || {});
          this.scriptByType.set(key, list);
        }
      }
    }

    addEventListener(type, cb) {
      const list = this.listeners.get(type) || [];
      list.push(cb);
      this.listeners.set(type, list);
    }

    emit(data) {
      if (this.disposed && data && data.type === "COMMIT_OK") {
        traces.raceTrace.ignoredLateMessages += 1;
        traces.raceTrace.ignoredLateWorkerIds.push(this.workerId);
        return;
      }
      const list = this.listeners.get("message") || [];
      for (const cb of list) cb({ data });
    }

    scriptedFor(msg, keyOverride) {
      const out = [];
      if (this.scriptHandler) {
        const scripted = this.scriptHandler({ msg, workerId: this.workerId, key: keyOverride || msg.type });
        const list = Array.isArray(scripted) ? scripted : scripted ? [scripted] : [];
        for (const entry of list) {
          const data = { ...entry };
          if (typeof data.rid === "undefined") data.rid = msg.rid;
          out.push(data);
        }
        return out;
      }

      const type = keyOverride || (msg && msg.type);
      const rid = msg && msg.rid;
      const key = String(type || "");
      const list = this.scriptByType.get(key) || [];
      while (list.length > 0) {
        const next = list.shift();
        const data = { ...next };
        if (typeof data.rid === "undefined") data.rid = rid;
        out.push(data);
      }
      return out;
    }

    queueScripted(msg, keyOverride) {
      const scripted = this.scriptedFor(msg, keyOverride);
      if (!scripted || scripted.length === 0) return false;
      for (const entry of scripted) {
        if (msg.type === "COMMIT" && entry.type === "COMMIT_OK" && !this.disposed) {
          if (!traces.raceTrace.winnerIds.includes(this.workerId)) {
            traces.raceTrace.winnerIds.push(this.workerId);
          }
          traces.workerCommitResults.push({ rootB64: entry.rootB64, nonce: entry.nonce });
        }
        queueMicrotask(() => this.emit(entry));
      }
      return true;
    }

    postMessage(msg) {
      if (msg.type === "INIT") {
        traces.initPayloads.push({
          bindingString: msg.bindingString,
          ticketB64: msg.ticketB64,
          steps: msg.steps,
          segmentLen: msg.segmentLen,
          pageBytes: msg.pageBytes,
          mixRounds: msg.mixRounds,
          hashcashBits: msg.hashcashBits,
        });
      }
      if (msg.type === "OPEN") traces.openPayloads.push({ indices: msg.indices, segs: msg.segs });

      if (this.queueScripted(msg)) {
        return;
      }

      if (msg.type === "INIT") {
        queueMicrotask(() => this.emit({ type: "INIT_OK", rid: msg.rid }));
        return;
      }
      if (msg.type === "COMMIT") {
        traces.workerCommitResults.push({ rootB64: "AA", nonce: "nonce" });
        queueMicrotask(() => this.emit({ type: "COMMIT_OK", rid: msg.rid, rootB64: "AA", nonce: "nonce" }));
        return;
      }
      if (msg.type === "OPEN") {
        const opens = (msg.indices || []).map((i, pos) => ({
          i,
          seg: msg.segs[pos],
          nodes: {
            "0": { pageB64: "AA", proof: [] },
            [String(i)]: { pageB64: "AA", proof: [] },
          },
        }));
        queueMicrotask(() => this.emit({ type: "OPEN_OK", rid: msg.rid, opens }));
        return;
      }
      if (msg.type === "CANCEL") {
        this.canceled = true;
        traces.raceTrace.canceledIds.push(this.workerId);
        if (traces.callCounts.commit === 0) {
          traces.raceTrace.raceCanceledIds.push(this.workerId);
        }
        queueMicrotask(() => this.emit({ type: "CANCEL_OK", rid: msg.rid }));
        return;
      }
      if (msg.type === "DISPOSE") {
        this.disposed = true;
        traces.raceTrace.disposedIds.push(this.workerId);
        if (traces.callCounts.commit === 0) {
          traces.raceTrace.raceDisposedIds.push(this.workerId);
        }
        queueMicrotask(() => this.emit({ type: "DISPOSE_OK", rid: msg.rid }));
        this.queueScripted(msg, "POST_DISPOSE");
      }
    }

    terminate() {
      traces.raceTrace.terminatedIds.push(this.workerId);
      if (traces.callCounts.commit === 0) {
        traces.raceTrace.raceTerminatedIds.push(this.workerId);
      }
    }
  };

  return FakeWorker;
};

export async function setupGlueTestGlobals({ bootstrap, challengeFixture, workerScript, fetchMap, traces, forceWorkerCount }) {
  if (glueGlobalState) {
    throw new Error("glue globals already active");
  }

  const prev = {
    document: globalThis.document,
    window: globalThis.window,
    navigator: globalThis.navigator,
    fetch: globalThis.fetch,
    testWorkerCount: globalThis.__MHG_TEST_FORCE_WORKER_COUNT__,
    Worker: globalThis.Worker,
    requestAnimationFrame: globalThis.requestAnimationFrame,
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    crypto: globalThis.crypto,
    createObjectURL: globalThis.URL.createObjectURL,
    revokeObjectURL: globalThis.URL.revokeObjectURL,
  };

  const makeEl = (tag = "div") => ({
    tagName: tag,
    style: { setProperty() {} },
    classList: { add() {}, remove() {}, contains() { return false; } },
    appendChild() {},
    addEventListener() {},
    remove() {},
    innerHTML: "",
    textContent: "",
  });
  const store = new Map();
  const getEl = (id) => {
    if (!store.has(id)) store.set(id, makeEl());
    return store.get(id);
  };

  globalThis.document = {
    title: "",
    head: makeEl("head"),
    documentElement: makeEl("html"),
    body: makeEl("body"),
    createElement: (tag) => makeEl(tag),
    getElementById: (id) => getEl(id),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  globalThis.window = {
    location: { href: "https://example.com/", replace() {}, reload() {} },
    parent: null,
    opener: null,
    innerWidth: 1200,
    innerHeight: 800,
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {} },
  };
  globalThis.window.parent = globalThis.window;

  Object.defineProperty(globalThis, "navigator", {
    value: { languages: ["en-US"], language: "en-US" },
    configurable: true,
  });

  globalThis.requestAnimationFrame = () => 0;
  globalThis.setTimeout = (fn) => {
    if (typeof fn === "function") fn();
    return 0;
  };
  globalThis.clearTimeout = () => {};
  globalThis.setInterval = () => 0;
  globalThis.clearInterval = () => {};
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
  if (!globalThis.crypto) {
    setCrypto(webcrypto);
  }
  if (!globalThis.URL.createObjectURL) {
    globalThis.URL.createObjectURL = () => "blob:mock";
  }
  if (!globalThis.URL.revokeObjectURL) {
    globalThis.URL.revokeObjectURL = () => {};
  }

  globalThis.Worker = createFakeWorkerClass({ traces, workerScript });
  if (Number.isInteger(forceWorkerCount) && forceWorkerCount > 0) {
    globalThis.__MHG_TEST_FORCE_WORKER_COUNT__ = forceWorkerCount;
  }

  const defaultChallenge = challengeFixture || { done: true, indices: [], sid: "sid", cursor: 0, token: "tok" };
  globalThis.fetch = async (url, init = {}) => {
    const endpoint = String(url);
    if (endpoint === "https://example.com/worker.js") {
      return { ok: true, status: 200, text: async () => "self.onmessage = () => {};" };
    }

    const parsed = new URL(endpoint, "https://example.com");
    const body = init.body ? JSON.parse(init.body) : {};
    traces.endpointRequests.push({
      method: String(init.method || "GET").toUpperCase(),
      pathname: parsed.pathname,
      body,
    });
    if (parsed.pathname.endsWith("/commit")) traces.callCounts.commit += 1;
    if (parsed.pathname.endsWith("/challenge")) traces.callCounts.challenge += 1;
    if (parsed.pathname.endsWith("/open")) traces.callCounts.open += 1;

    if (fetchMap && typeof fetchMap[parsed.pathname] === "function") {
      return await fetchMap[parsed.pathname]({ url: endpoint, init, body });
    }
    if (parsed.pathname.endsWith("/commit")) {
      return { ok: true, status: 200, json: async () => ({ commitToken: "v5.test.commit-token" }) };
    }
    if (parsed.pathname.endsWith("/challenge")) {
      return { ok: true, status: 200, json: async () => defaultChallenge };
    }
    if (parsed.pathname.endsWith("/open")) {
      return { ok: true, status: 200, json: async () => ({ done: true }) };
    }
    throw new Error(`unexpected fetch: ${endpoint}`);
  };

  glueGlobalState = { prev, bootstrap };
}

export async function importGlueWithCacheBust({ forceWorkerCount } = {}) {
  const cacheBust = `${Date.now()}-${Math.random()}`;
  const gluePath = join(repoRoot, "glue.js");
  if (Number.isInteger(forceWorkerCount) && forceWorkerCount > 0) {
    const source = await readFile(gluePath, "utf8");
    const marker = "const workerCount = Number(hashcashBits) >= 2 ? 4 : 1;";
    const patched = source.replace(
      marker,
      "const workerCount = globalThis.__MHG_TEST_FORCE_WORKER_COUNT__ ?? (Number(hashcashBits) >= 2 ? 4 : 1);"
    );
    if (patched === source) {
      throw new Error("failed to apply test worker-count patch");
    }
    const glueUrl = `data:text/javascript,${encodeURIComponent(patched)}#v=${cacheBust}`;
    return await import(glueUrl);
  }
  const glueUrl = `${pathToFileURL(gluePath).href}?v=${cacheBust}`;
  return await import(glueUrl);
}

export function buildGlueArgs(bootstrap) {
  const workerUrl = bootstrap.workerUrl || "https://example.com/worker.js";
  const moduleUrl = bootstrap.moduleUrl || makeModuleUrl(workerUrl);
  return [
    b64u(bootstrap.bindingString),
    bootstrap.steps,
    bootstrap.ticketB64,
    bootstrap.pathHash || "pathhash",
    bootstrap.hashcashBits,
    bootstrap.segmentLen,
    b64u(bootstrap.reloadUrl || "https://example.com/ok"),
    b64u(bootstrap.apiPrefix || "/__pow"),
    b64u(moduleUrl),
    b64u(bootstrap.captchaCfg || "{}"),
    bootstrap.atomicCfg || "0",
    bootstrap.pageBytes,
    bootstrap.mixRounds,
  ];
}

export async function teardownGlueTestGlobals() {
  if (!glueGlobalState) return;
  const { prev } = glueGlobalState;
  globalThis.document = prev.document;
  globalThis.window = prev.window;
  if (typeof prev.navigator === "undefined") {
    delete globalThis.navigator;
  } else {
    Object.defineProperty(globalThis, "navigator", {
      value: prev.navigator,
      configurable: true,
    });
  }
  globalThis.fetch = prev.fetch;
  if (typeof prev.testWorkerCount === "undefined") {
    delete globalThis.__MHG_TEST_FORCE_WORKER_COUNT__;
  } else {
    globalThis.__MHG_TEST_FORCE_WORKER_COUNT__ = prev.testWorkerCount;
  }
  globalThis.Worker = prev.Worker;
  globalThis.requestAnimationFrame = prev.requestAnimationFrame;
  globalThis.setTimeout = prev.setTimeout;
  globalThis.clearTimeout = prev.clearTimeout;
  globalThis.setInterval = prev.setInterval;
  globalThis.clearInterval = prev.clearInterval;
  globalThis.atob = prev.atob;
  globalThis.btoa = prev.btoa;
  if (!prev.crypto) {
    delete globalThis.crypto;
  } else {
    setCrypto(prev.crypto);
  }
  globalThis.URL.createObjectURL = prev.createObjectURL;
  globalThis.URL.revokeObjectURL = prev.revokeObjectURL;
  glueGlobalState = null;
}

export async function runGlueFlow({ bootstrap, challengeFixture, workerScript, fetchMap, forceWorkerCount }) {
  const required = [
    "bindingString",
    "ticketB64",
    "steps",
    "segmentLen",
    "pageBytes",
    "mixRounds",
    "hashcashBits",
  ];
  for (const key of required) {
    if (!(key in (bootstrap || {}))) throw new Error(`bootstrap.${key} required`);
  }

  const traces = {
    endpointRequests: [],
    initPayloads: [],
    openPayloads: [],
    workerCommitResults: [],
    callCounts: { commit: 0, challenge: 0, open: 0 },
    runPowArgs: {
      bindingString: bootstrap.bindingString,
      steps: bootstrap.steps,
      segmentLen: bootstrap.segmentLen,
      pageBytes: bootstrap.pageBytes,
      mixRounds: bootstrap.mixRounds,
      hashcashBits: bootstrap.hashcashBits,
      pathHash: bootstrap.pathHash || "pathhash",
    },
    challengeFixture:
      challengeFixture || { done: true, indices: [], sid: "sid", cursor: 0, token: "tok" },
    raceTrace: {
      winnerIds: [],
      canceledIds: [],
      disposedIds: [],
      terminatedIds: [],
      raceCanceledIds: [],
      raceDisposedIds: [],
      raceTerminatedIds: [],
      ignoredLateMessages: 0,
      ignoredLateWorkerIds: [],
    },
  };

  await setupGlueTestGlobals({ bootstrap, challengeFixture, workerScript, fetchMap, traces, forceWorkerCount });
  try {
    const glue = await importGlueWithCacheBust({ forceWorkerCount });
    await glue.default(...buildGlueArgs(bootstrap));
    assert.deepEqual(traces.initPayloads[0], {
      bindingString: bootstrap.bindingString,
      ticketB64: bootstrap.ticketB64,
      steps: bootstrap.steps,
      segmentLen: bootstrap.segmentLen,
      pageBytes: bootstrap.pageBytes,
      mixRounds: bootstrap.mixRounds,
      hashcashBits: bootstrap.hashcashBits,
    });
    return traces;
  } finally {
    await teardownGlueTestGlobals();
  }
}
