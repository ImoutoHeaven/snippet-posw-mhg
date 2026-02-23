import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const b64u = (value) =>
  Buffer.from(String(value), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const makeModuleUrl = (workerUrl) =>
  `data:text/javascript,${encodeURIComponent(`export const workerUrl = "${workerUrl}";`)}`;

const makeBootstrapB64 = ({ ticketB64, pathHash, n, k, apiPrefix = "/__pow" }) =>
  b64u(JSON.stringify({ ticketB64, pathHash, eq: { n, k }, apiPrefix }));

const setupDom = () => {
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
  };
  globalThis.window.parent = globalThis.window;
  globalThis.window.sessionStorage = {
    getItem() {
      return null;
    },
    setItem() {},
    removeItem() {},
    clear() {},
  };

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
  globalThis.setInterval = (fn) => {
    if (typeof fn === "function") fn();
    return 0;
  };
  globalThis.clearInterval = () => {};
  globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
  globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
  }
  if (!globalThis.URL.createObjectURL) globalThis.URL.createObjectURL = () => "blob:mock";
  if (!globalThis.URL.revokeObjectURL) globalThis.URL.revokeObjectURL = () => {};
};

const importGlue = async () => {
  setupDom();
  const glueUrl = `${pathToFileURL(join(repoRoot, "glue.js")).href}?v=${Date.now()}-${Math.random()}`;
  return await import(glueUrl);
};

test("client calls only /verify in pow mode", async () => {
  const sequence = [];
  const initPayloads = [];
  const solvePayloads = [];
  const glue = await importGlue();

  globalThis.Worker = class FakeWorker {
    constructor() {
      this.listeners = new Map();
    }
    addEventListener(type, cb) {
      const list = this.listeners.get(type) || [];
      list.push(cb);
      this.listeners.set(type, list);
    }
    postMessage(msg) {
      const emit = (data) => {
        const list = this.listeners.get("message") || [];
        for (const cb of list) cb({ data });
      };
      if (msg.type === "INIT") {
        initPayloads.push(msg);
        emit({ type: "OK", rid: msg.rid });
      }
      if (msg.type === "SOLVE") {
        solvePayloads.push(msg);
        emit({ type: "OK", rid: msg.rid, nonceB64: "nonce", proofB64: "proof" });
      }
      if (msg.type === "COMMIT") {
        emit({ type: "OK", rid: msg.rid, rootB64: "root", nonce: "nonce" });
      }
      if (msg.type === "OPEN") {
        emit({ type: "OK", rid: msg.rid, opens: [] });
      }
      if (msg.type === "CANCEL" || msg.type === "DISPOSE") {
        emit({ type: "OK", rid: msg.rid });
      }
    }
    terminate() {}
  };

  globalThis.fetch = async (url, init) => {
    const endpoint = String(url);
    if (endpoint.endsWith("/worker.js")) {
      return { ok: true, status: 200, text: async () => "self.onmessage = () => {};" };
    }
    if (endpoint.endsWith("/verify")) {
      sequence.push("verify");
      const body = init && init.body ? JSON.parse(init.body) : {};
      assert.equal(body.ticketB64, b64u("4.1700000600.3.1700000000.mactag"));
      assert.equal(body.pathHash, "pathhash");
      assert.equal(body.pow && body.pow.nonceB64, "nonce");
      assert.equal(body.pow && body.pow.proofB64, "proof");
      return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
    }
    if (endpoint.endsWith("/commit") || endpoint.endsWith("/challenge") || endpoint.endsWith("/open")) {
      sequence.push(endpoint.split("/").pop());
      throw new Error(`legacy endpoint called: ${endpoint}`);
    }
    throw new Error(`unexpected fetch: ${endpoint}`);
  };

  const args = [
    makeBootstrapB64({
      ticketB64: b64u("4.1700000600.3.1700000000.mactag"),
      pathHash: "pathhash",
      n: 90,
      k: 5,
    }),
    b64u("binding"),
    1,
    b64u("https://example.com/ok"),
    b64u(makeModuleUrl("https://example.com/worker.js")),
    b64u("{}"),
    "0",
  ];

  await glue.default(...args);
  assert.deepEqual(sequence, ["verify"]);
  assert.equal(initPayloads.length > 0, true);
  assert.equal(solvePayloads.length > 0, true);
});

test("client forwards bootstrap equihash params to worker", async () => {
  const initPayloads = [];
  const solvePayloads = [];
  const glue = await importGlue();

  globalThis.Worker = class FakeWorker {
    constructor() {
      this.listeners = new Map();
    }
    addEventListener(type, cb) {
      const list = this.listeners.get(type) || [];
      list.push(cb);
      this.listeners.set(type, list);
    }
    postMessage(msg) {
      const emit = (data) => {
        const list = this.listeners.get("message") || [];
        for (const cb of list) cb({ data });
      };
      if (msg.type === "INIT") {
        initPayloads.push(msg);
        emit({ type: "OK", rid: msg.rid });
      }
      if (msg.type === "SOLVE") {
        solvePayloads.push(msg);
        emit({ type: "OK", rid: msg.rid, nonceB64: "nonce", proofB64: "proof" });
      }
      if (msg.type === "CANCEL" || msg.type === "DISPOSE") {
        emit({ type: "OK", rid: msg.rid });
      }
    }
    terminate() {}
  };

  globalThis.fetch = async (url) => {
    const endpoint = String(url);
    if (endpoint.endsWith("/verify")) {
      return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
    }
    throw new Error(`unexpected fetch: ${endpoint}`);
  };

  const args = [
    makeBootstrapB64({
      ticketB64: b64u("4.1700000600.3.1700000000.mactag"),
      pathHash: "pathhash",
      n: 96,
      k: 3,
    }),
    b64u("binding"),
    1,
    b64u("https://example.com/ok"),
    b64u(makeModuleUrl("https://example.com/worker.js")),
    b64u("{}"),
    "0",
  ];

  await glue.default(...args);
  assert.equal(initPayloads.length, 1);
  assert.equal(solvePayloads.length, 1);
  assert.equal(initPayloads[0].n, 96);
  assert.equal(initPayloads[0].k, 3);
  assert.equal(solvePayloads[0].n, 96);
  assert.equal(solvePayloads[0].k, 3);
});

test("client rejects bootstrap with unsupported equihash params", async () => {
  const glue = await importGlue();
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return { ok: true, status: 200, json: async () => ({ ok: true, mode: "proof" }) };
  };

  const args = [
    makeBootstrapB64({
      ticketB64: b64u("4.1700000600.3.1700000000.mactag"),
      pathHash: "pathhash",
      n: 96,
      k: 8,
    }),
    b64u("binding"),
    1,
    b64u("https://example.com/ok"),
    b64u(makeModuleUrl("https://example.com/worker.js")),
    b64u("{}"),
    "0",
  ];

  await glue.default(...args);
  assert.equal(fetchCalls, 0);
  assert.equal(globalThis.document.getElementById("t").textContent, "Failed");
});
