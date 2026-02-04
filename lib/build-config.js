import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

import {
  compileWhenCondition,
  validateWhenCondition,
} from "./when-compile.js";

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

const splitPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const trimmed = pattern.trim();
  if (!trimmed) return null;
  const slashIndex = trimmed.indexOf("/");
  if (slashIndex === -1) return { host: trimmed, path: null };
  const host = trimmed.slice(0, slashIndex);
  if (!host) return null;
  return { host, path: trimmed.slice(slashIndex) };
};

const escapeRegex = (value) => value.replace(/[.+?^${}()|[\]\\]/g, "\\$&");

const isRegExp = (value) => Object.prototype.toString.call(value) === "[object RegExp]";

const cloneValue = (value) => {
  if (Array.isArray(value)) {
    return value.map((entry) => cloneValue(entry));
  }
  if (isRegExp(value)) {
    return new RegExp(value.source, value.flags);
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = cloneValue(entry);
    }
    return out;
  }
  return value;
};

const compileHostPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const host = pattern.trim().toLowerCase();
  if (!host) return null;
  const escaped = escapeRegex(host).replace(/\*/g, "[^.]*");
  try {
    return new RegExp(`^${escaped}$`);
  } catch {
    return null;
  }
};

const compilePathPattern = (pattern) => {
  if (typeof pattern !== "string") return null;
  const path = pattern.trim();
  if (!path.startsWith("/")) return null;
  let out = "";
  for (let i = 0; i < path.length; i++) {
    const ch = path[i];
    if (ch === "*") {
      if (path[i + 1] === "*") {
        const isLast = i + 2 >= path.length;
        const prevIsSlash = i > 0 && path[i - 1] === "/";
        if (isLast && prevIsSlash && out.endsWith("/") && out.length > 1) {
          out = `${out.slice(0, -1)}(?:/.*)?`;
        } else {
          out += ".*";
        }
        i++;
      } else {
        out += "[^/]*";
      }
      continue;
    }
    out += /[.+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
  }
  try {
    return new RegExp(`^${out}$`);
  } catch {
    return null;
  }
};

const compileConfigEntry = (entry) => {
  const config = (entry && entry.config) || {};
  const when = entry && entry.when;
  validateWhenCondition(when);
  const compiledWhen = compileWhenCondition(when);
  const parts = splitPattern(entry && entry.pattern);
  if (!parts) {
    return { hostRegex: null, pathRegex: null, config, when: compiledWhen };
  }
  const hostRegex = compileHostPattern(parts.host);
  if (!hostRegex) {
    return { hostRegex: null, pathRegex: null, config, when: compiledWhen };
  }
  const pathRegex = parts.path ? compilePathPattern(parts.path) : null;
  if (parts.path && !pathRegex) {
    return { hostRegex: null, pathRegex: null, config, when: compiledWhen };
  }
  return { hostRegex, pathRegex, config, when: compiledWhen };
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
  const compiled = normalized.map(compileConfigEntry);
  return JSON.stringify(
    compiled.map((entry) => ({
      host: entry.hostRegex ? { s: entry.hostRegex.source, f: entry.hostRegex.flags } : null,
      path: entry.pathRegex ? { s: entry.pathRegex.source, f: entry.pathRegex.flags } : null,
      when: entry.when ?? null,
      config: entry.config || {},
    }))
  );
};
