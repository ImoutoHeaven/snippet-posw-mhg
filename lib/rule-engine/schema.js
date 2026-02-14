import {
  LOGIC_OPERATORS,
  TEXT_MATCHER_OPERATORS,
  IP_MATCHER_OPERATORS,
  WHEN_ATOM_FIELDS,
  isPlainObject,
} from "./types.js";

const LOGIC_OPERATOR_SET = new Set(LOGIC_OPERATORS);
const TEXT_MATCHER_SET = new Set(TEXT_MATCHER_OPERATORS);
const IP_MATCHER_SET = new Set(IP_MATCHER_OPERATORS);
const WHEN_ATOM_FIELD_SET = new Set(WHEN_ATOM_FIELDS);
const VALUE_MAP_FIELDS = new Set(["header", "cookie", "query"]);
const IP_FIELDS = new Set(["ip"]);

export function validateConfigEntry(entry, rootPath = "CONFIG") {
  if (!isPlainObject(entry)) {
    throw new Error(`${rootPath} must be an object`);
  }

  validateTopLevelKeys(entry, rootPath);
  validateRequiredConfig(entry, rootPath);

  if ("host" in entry) {
    validateHostPathMatcher(entry.host, `${rootPath}.host`);
  }
  if ("path" in entry) {
    validateHostPathMatcher(entry.path, `${rootPath}.path`);
  }
  if ("when" in entry) {
    validateWhenCondition(entry.when, `${rootPath}.when`);
  }
}

function validateTopLevelKeys(entry, rootPath) {
  const allowed = new Set(["host", "path", "when", "config"]);
  for (const key of Object.keys(entry)) {
    if (!allowed.has(key)) {
      throw new Error(`${rootPath}.${key} is not allowed`);
    }
  }
}

function validateRequiredConfig(entry, rootPath) {
  if (!isPlainObject(entry.config)) {
    throw new Error(`${rootPath}.config must be an object`);
  }
}

function validateHostPathMatcher(value, path) {
  validateMatcherObject(value, path, {
    allowedOps: TEXT_MATCHER_SET,
    matcherKind: "text",
    disallowExists: true,
    noCompatMessage: `${path} must be a matcher object (legacy strings and RegExp literals are not supported)`,
  });
}

function validateWhenCondition(node, path) {
  if (!isPlainObject(node)) {
    throw new Error(`${path} must be an object`);
  }

  for (const [key, value] of Object.entries(node)) {
    if (LOGIC_OPERATOR_SET.has(key)) {
      validateLogicNode(key, value, `${path}.${key}`);
      continue;
    }
    if (!WHEN_ATOM_FIELD_SET.has(key)) {
      throw new Error(`${path}.${key} is not a supported condition field`);
    }
    validateWhenAtom(key, value, `${path}.${key}`);
  }
}

function validateLogicNode(key, value, path) {
  if (key === "not") {
    if (!isPlainObject(value)) {
      throw new Error(`${path} must be a condition object`);
    }
    validateWhenCondition(value, path);
    return;
  }

  if (!Array.isArray(value)) {
    throw new Error(`${path} must be an array of condition objects`);
  }

  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const entryPath = `${path}[${index}]`;
    if (!isPlainObject(entry)) {
      throw new Error(`${entryPath} must be a condition object`);
    }
    validateWhenCondition(entry, entryPath);
  }
}

function validateWhenAtom(field, value, path) {
  if (VALUE_MAP_FIELDS.has(field)) {
    validateValueMapMatcher(value, path);
    return;
  }

  if (field === "tls") {
    validateMatcherObject(value, path, {
      allowedOps: new Set(["eq", "in"]),
      matcherKind: "tls",
      disallowExists: true,
      noCompatMessage: `${path} must be a matcher object (legacy boolean values are not supported)`,
    });
    return;
  }

  validateMatcherObject(value, path, {
    allowedOps: IP_FIELDS.has(field) ? IP_MATCHER_SET : TEXT_MATCHER_SET,
    matcherKind: IP_FIELDS.has(field) ? "ip" : "text",
    disallowExists: true,
    noCompatMessage: `${path} must be a matcher object (legacy strings and RegExp literals are not supported)`,
  });
}

function validateValueMapMatcher(value, path) {
  if (!isPlainObject(value)) {
    throw new Error(`${path} must be an object map`);
  }

  for (const [key, matcher] of Object.entries(value)) {
    validateMatcherObject(matcher, `${path}[${JSON.stringify(key)}]`, {
      allowedOps: TEXT_MATCHER_SET,
      matcherKind: "text",
      disallowExists: false,
      noCompatMessage: `${path}[${JSON.stringify(key)}] must be a matcher object (legacy strings and RegExp literals are not supported)`,
    });
  }
}

function validateMatcherObject(value, path, options) {
  const { allowedOps, matcherKind, disallowExists, noCompatMessage } = options;

  if (!isPlainObject(value)) {
    throw new Error(noCompatMessage);
  }

  const keys = Object.keys(value);
  if (keys.length === 0) {
    throw new Error(`${path} matcher object must not be empty`);
  }

  if ("exists" in value) {
    if (disallowExists) {
      throw new Error(`${path}.exists is not allowed for ${matcherKind} matcher`);
    }
    if (keys.length !== 1) {
      throw new Error(`${path} exists matcher must only contain exists`);
    }
    if (typeof value.exists !== "boolean") {
      throw new Error(`${path}.exists must be a boolean`);
    }
    return;
  }

  const opKeys = keys.filter((key) => key !== "flags");
  if (opKeys.length !== 1) {
    throw new Error(`${path} matcher must define exactly one operator`);
  }

  const op = opKeys[0];
  if (!allowedOps.has(op)) {
    throw new Error(`${path}.${op} is not a valid ${matcherKind} matcher operator`);
  }

  if ("flags" in value && op !== "re") {
    throw new Error(`${path}.flags is only allowed with re matcher`);
  }

  validateOperatorValue(op, value[op], path, matcherKind);

  if (op === "re" && "flags" in value && typeof value.flags !== "string") {
    throw new Error(`${path}.flags must be a string`);
  }
}

function validateOperatorValue(op, operand, path, matcherKind) {
  if (matcherKind === "tls") {
    if (op === "eq") {
      if (typeof operand !== "boolean") {
        throw new Error(`${path}.eq must be a boolean`);
      }
      return;
    }
    if (op === "in") {
      if (
        !Array.isArray(operand) ||
        operand.length === 0 ||
        !operand.every((value) => typeof value === "boolean")
      ) {
        throw new Error(`${path}.in must be a non-empty boolean array`);
      }
      return;
    }
  }

  if (op === "in") {
    if (
      !Array.isArray(operand) ||
      operand.length === 0 ||
      !operand.every((value) => typeof value === "string")
    ) {
      throw new Error(`${path}.in must be a non-empty string array`);
    }
    return;
  }

  if (typeof operand !== "string") {
    throw new Error(`${path}.${op} must be a string`);
  }
}
