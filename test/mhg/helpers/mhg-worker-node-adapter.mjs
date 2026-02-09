import { webcrypto } from "node:crypto";
import { parentPort } from "node:worker_threads";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}
if (!globalThis.atob) {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}
if (!globalThis.btoa) {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}

if (parentPort) {
  globalThis.self = globalThis;
  globalThis.addEventListener = () => {};
  globalThis.postMessage = (message) => {
    parentPort.postMessage(message);
  };

  await import("../../../esm/mhg-worker.js");

  parentPort.on("message", (data) => {
    if (typeof globalThis.onmessage === "function") {
      globalThis.onmessage({ data });
    }
  });
}
