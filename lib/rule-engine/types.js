export const LOGIC_OPERATORS = Object.freeze(["and", "or", "not"]);

export const TEXT_MATCHER_OPERATORS = Object.freeze(["eq", "in", "glob", "re"]);

export const EXISTS_MATCHER_OPERATORS = Object.freeze(["exists"]);

export const IP_MATCHER_OPERATORS = Object.freeze(["eq", "in", "cidr"]);

export const MATCHER_OPERATOR_GROUPS = Object.freeze({
  logic: LOGIC_OPERATORS,
  text: TEXT_MATCHER_OPERATORS,
  exists: EXISTS_MATCHER_OPERATORS,
  ip: IP_MATCHER_OPERATORS,
});

export const WHEN_ATOM_FIELDS = Object.freeze([
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

export function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value) || value instanceof RegExp) {
    return false;
  }
  return Object.getPrototypeOf(value) === Object.prototype;
}
