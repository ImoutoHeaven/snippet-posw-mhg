// Export the worker URL for use in glue.js.
export const workerUrl = new URL("./mhg-worker.js", import.meta.url).toString();
