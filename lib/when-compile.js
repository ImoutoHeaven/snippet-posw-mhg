export const ALLOWED_KEYS = new Set([
  "and",
  "or",
  "not",
  "country",
  "asn",
  "ip",
  "method",
  "ua",
  "path",
  "tls",
  "header",
  "cookie",
  "query",
]);

const LOGIC_ARRAY_KEYS = new Set(["and", "or"]);
const STRING_KEYS = new Set(["country", "asn", "ip", "method"]);
const STRING_OR_REGEX_KEYS = new Set(["ua", "path"]);
const OBJECT_VALUE_KEYS = new Set(["header", "cookie", "query"]);

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value) || value instanceof RegExp) {
    return false;
  }
  return Object.getPrototypeOf(value) === Object.prototype;
}

function isCompiledRegex(value) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== "$re") {
    return false;
  }
  const inner = value.$re;
  if (!isPlainObject(inner)) {
    return false;
  }
  const innerKeys = Object.keys(inner);
  if (innerKeys.length === 0 || innerKeys.length > 2) {
    return false;
  }
  if (!("s" in inner) || typeof inner.s !== "string") {
    return false;
  }
  if ("f" in inner && typeof inner.f !== "string") {
    return false;
  }
  return true;
}

export function compileWhenCondition(input) {
  if (input instanceof RegExp) {
    return { $re: { s: input.source, f: input.flags } };
  }

  if (Array.isArray(input)) {
    return input.map((entry) => compileWhenCondition(entry));
  }

  if (input && typeof input === "object") {
    const output = {};
    for (const [key, value] of Object.entries(input)) {
      output[key] = compileWhenCondition(value);
    }
    return output;
  }

  return input;
}

export function validateWhenCondition(input) {
  if (input === null || input === undefined) {
    return;
  }
  if (input instanceof RegExp) {
    throw new Error("RegExp is only allowed as a leaf value");
  }

  if (!isPlainObject(input)) {
    throw new Error("Condition must be an object");
  }

  validateConditionObject(input);
}

function validateConditionObject(node) {
  for (const key of Object.keys(node)) {
    if (!ALLOWED_KEYS.has(key)) {
      throw new Error(`Unknown key: ${key}`);
    }
  }

  for (const [key, value] of Object.entries(node)) {
    if (LOGIC_ARRAY_KEYS.has(key)) {
      if (!Array.isArray(value)) {
        throw new Error(`${key} must be an array`);
      }
      for (const entry of value) {
        if (entry instanceof RegExp) {
          throw new Error("RegExp is only allowed as a leaf value");
        }
        if (!isPlainObject(entry)) {
          throw new Error(`${key} entries must be condition objects`);
        }
        validateConditionObject(entry);
      }
      continue;
    }

    if (key === "not") {
      if (!isPlainObject(value)) {
        throw new Error("not must be a condition object");
      }
      validateConditionObject(value);
      continue;
    }

    if (STRING_KEYS.has(key)) {
      validateStringOrArray(key, value);
      continue;
    }

    if (STRING_OR_REGEX_KEYS.has(key)) {
      validateStringOrRegexOrArray(key, value);
      continue;
    }

    if (key === "tls") {
      if (typeof value !== "boolean") {
        throw new Error("tls must be boolean");
      }
      continue;
    }

    if (OBJECT_VALUE_KEYS.has(key)) {
      validateObjectValueMap(key, value);
    }
  }
}

function validateStringOrArray(key, value) {
  if (typeof value === "string") {
    return;
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
    return;
  }
  throw new Error(`${key} must be a string or string array`);
}

function validateStringOrRegexOrArray(key, value) {
  if (
    typeof value === "string" ||
    value instanceof RegExp ||
    isCompiledRegex(value)
  ) {
    return;
  }
  if (
    Array.isArray(value) &&
    value.every(
      (entry) =>
        typeof entry === "string" ||
        entry instanceof RegExp ||
        isCompiledRegex(entry),
    )
  ) {
    return;
  }
  throw new Error(`${key} must be a string, RegExp, or array`);
}

function validateObjectValueMap(key, value) {
  if (!isPlainObject(value)) {
    throw new Error(`${key} must be an object`);
  }
  for (const entry of Object.values(value)) {
    validateObjectValueEntry(entry);
  }
}

function validateObjectValueEntry(entry) {
  if (
    typeof entry === "string" ||
    entry instanceof RegExp ||
    isCompiledRegex(entry)
  ) {
    return;
  }
  if (
    Array.isArray(entry) &&
    entry.every(
      (value) =>
        typeof value === "string" ||
        value instanceof RegExp ||
        isCompiledRegex(value),
    )
  ) {
    return;
  }
  if (isPlainObject(entry)) {
    const keys = Object.keys(entry);
    if (keys.length !== 1 || keys[0] !== "exists") {
      throw new Error("exists object must only contain exists");
    }
    if (typeof entry.exists !== "boolean") {
      throw new Error("exists must be boolean");
    }
    return;
  }
  throw new Error("Invalid object value entry");
}
