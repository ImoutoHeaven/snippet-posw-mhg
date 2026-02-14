import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

import { compileConfigEntry } from "./rule-engine/compile.js";
import { validateConfigEntry } from "./rule-engine/schema.js";

const extractConfigLiteral = (source) => {
  const match = source.match(/^\s*const\s+CONFIG\s*=/m);
  if (!match || match.index === undefined) return null;
  const start = source.indexOf("[", match.index + match[0].length);
  if (start === -1) return null;
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  let inLine = false;
  let inBlock = false;
  for (let i = start; i < source.length; i++) {
    const ch = source[i];
    const next = source[i + 1];
    if (inLine) {
      if (ch === "\n") inLine = false;
      continue;
    }
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        i++;
      }
      continue;
    }
    if (inSingle) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === '"') inDouble = false;
      continue;
    }
    if (inTemplate) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === "`") inTemplate = false;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      i++;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }
    if (ch === "`") {
      inTemplate = true;
      continue;
    }
    if (ch === "[") depth++;
    if (ch === "]") {
      depth--;
      if (depth === 0) {
        return source.slice(start, i + 1);
      }
    }
  }
  return null;
};

const isRegExp = (value) => Object.prototype.toString.call(value) === "[object RegExp]";

const cloneValue = (value) => {
  if (Array.isArray(value)) {
    return value.map((entry) => cloneValue(entry));
  }
  if (isRegExp(value)) {
    return new RegExp(value.source, value.flags);
  }
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, entry] of Object.entries(value)) {
      output[key] = cloneValue(entry);
    }
    return output;
  }
  return value;
};

export const buildCompiledConfig = async (sourcePath) => {
  const source = await readFile(sourcePath, "utf-8");
  const literal = extractConfigLiteral(source);
  if (!literal) {
    throw new Error(`CONFIG not found in ${sourcePath}`);
  }
  const config = runInNewContext(`(${literal})`);
  if (!Array.isArray(config)) {
    throw new Error("CONFIG must be array");
  }
  const normalized = cloneValue(config);
  const compiled = [];
  for (let index = 0; index < normalized.length; index += 1) {
    const entry = normalized[index];
    validateConfigEntry(entry, `CONFIG[${index}]`);
    compiled.push(compileConfigEntry(entry));
  }
  return JSON.stringify(compiled);
};
