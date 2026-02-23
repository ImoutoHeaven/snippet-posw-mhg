// Export the worker URL for use in glue.js.
export const workerUrl = new URL("./equihash-worker.js", import.meta.url).toString();
