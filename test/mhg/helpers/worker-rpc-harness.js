import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

let workerGlobalState = null;

const setCrypto = (value) => {
  Object.defineProperty(globalThis, "crypto", { value, configurable: true });
};

const restoreWorkerGlobals = (prev) => {
  globalThis.self = prev.self;
  globalThis.postMessage = prev.postMessage;
  globalThis.atob = prev.atob;
  globalThis.btoa = prev.btoa;
  if (!prev.crypto) {
    delete globalThis.crypto;
  } else {
    setCrypto(prev.crypto);
  }
};

export async function createTestWorker() {
  if (workerGlobalState) {
    throw new Error("worker globals already active");
  }

  const prev = {
    self: globalThis.self,
    postMessage: globalThis.postMessage,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    crypto: globalThis.crypto,
  };

  if (!globalThis.atob) {
    globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  }
  if (!globalThis.btoa) {
    globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  }
  if (!globalThis.crypto) {
    setCrypto(webcrypto);
  }

  const listeners = new Set();
  const workerSelf = {
    onmessage: null,
    addEventListener() {},
  };

  globalThis.self = workerSelf;
  globalThis.postMessage = (data) => {
    for (const cb of Array.from(listeners)) cb({ data });
  };

  const workerUrl = `${pathToFileURL(join(repoRoot, "esm/mhg-worker.js")).href}?v=${Date.now()}-${Math.random()}`;
  try {
    await import(workerUrl);
  } catch (error) {
    restoreWorkerGlobals(prev);
    throw error;
  }

  const worker = {
    __rid: 0,
    postMessage(data) {
      if (typeof workerSelf.onmessage !== "function") {
        throw new Error("worker message handler unavailable");
      }
      workerSelf.onmessage({ data });
    },
    addEventListener(type, cb) {
      if (type !== "message" || typeof cb !== "function") return;
      listeners.add(cb);
    },
    removeEventListener(type, cb) {
      if (type !== "message" || typeof cb !== "function") return;
      listeners.delete(cb);
    },
    terminate() {
      listeners.clear();
    },
  };

  workerGlobalState = { prev };
  return worker;
}

export async function rpcCall(worker, type, payload = {}, traces = null) {
  const rid = ++worker.__rid;
  const request = { type, rid, ...(payload || {}) };
  if (traces && Array.isArray(traces.workerMessages)) {
    traces.workerMessages.push({ dir: "to-worker", type, rid });
  }

  return await new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      if (typeof worker.removeEventListener === "function") {
        worker.removeEventListener("message", onMessage);
      }
      fn(value);
    };

    const onMessage = (event) => {
      const data = event && event.data ? event.data : {};
      if (data.rid !== rid) return;
      if (traces && Array.isArray(traces.workerMessages)) {
        traces.workerMessages.push({ dir: "from-worker", type: data.type, rid: data.rid });
      }
      if (data.type === "ERROR") {
        settle(reject, new Error(data.message || "worker error"));
        return;
      }
      if (typeof data.type === "string" && data.type.endsWith("_OK")) {
        settle(resolve, data);
      }
    };

    worker.addEventListener("message", onMessage);
    try {
      worker.postMessage(request);
    } catch (error) {
      settle(reject, error);
    }
  });
}

export async function cleanupWorkerGlobals() {
  if (!workerGlobalState) return;
  const { prev } = workerGlobalState;
  restoreWorkerGlobals(prev);
  workerGlobalState = null;
}

export async function runWorkerFlow({
  ticketB64,
  steps,
  pageBytes,
  mixRounds,
  hashcashBits,
  indices,
  segs,
}) {
  if (!ticketB64) throw new Error("ticketB64 required");
  const initPayload = { ticketB64, steps, pageBytes, mixRounds, hashcashBits };
  const traces = { workerMessages: [] };
  const worker = await createTestWorker();
  try {
    await rpcCall(worker, "INIT", initPayload, traces);
    const commit = await rpcCall(worker, "COMMIT", {}, traces);
    const open =
      Array.isArray(indices) && Array.isArray(segs)
        ? await rpcCall(worker, "OPEN", { indices, segs }, traces)
        : null;
    return { initPayload, commit, open, traces };
  } finally {
    worker.terminate();
    await cleanupWorkerGlobals();
  }
}
