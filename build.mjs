import { build } from "esbuild";
import { mkdir, rm, stat, readFile, writeFile } from "fs/promises";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { minify as minifyHtml } from "html-minifier-terser";
import { minify as minifyJs } from "terser";
import { runInNewContext } from "node:vm";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const powEntry = resolve(__dirname, "pow.js");
const powConfigEntry = resolve(__dirname, "pow-config.js");
const templatePath = resolve(__dirname, "template.html");
const outdir = resolve(__dirname, "dist");
const powOutfile = resolve(outdir, "pow_snippet.js");
const powConfigOutfile = resolve(outdir, "pow_config_snippet.js");

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
  const parts = splitPattern(entry && entry.pattern);
  if (!parts) {
    return { hostRegex: null, pathRegex: null, config };
  }
  const hostRegex = compileHostPattern(parts.host);
  if (!hostRegex) {
    return { hostRegex: null, pathRegex: null, config };
  }
  const pathRegex = parts.path ? compilePathPattern(parts.path) : null;
  if (parts.path && !pathRegex) {
    return { hostRegex: null, pathRegex: null, config };
  }
  return { hostRegex, pathRegex, config };
};

const buildCompiledConfig = async (sourcePath) => {
  const source = await readFile(sourcePath, "utf-8");
  const literal = extractConfigLiteral(source);
  if (!literal) {
    throw new Error(`CONFIG not found in ${sourcePath}`);
  }
  const config = runInNewContext(`(${literal})`);
  if (!Array.isArray(config)) {
    throw new Error("CONFIG must be array");
  }
  const compiled = config.map(compileConfigEntry);
  return JSON.stringify(
    compiled.map((entry) => ({
      host: entry.hostRegex ? { s: entry.hostRegex.source, f: entry.hostRegex.flags } : null,
      path: entry.pathRegex ? { s: entry.pathRegex.source, f: entry.pathRegex.flags } : null,
      config: entry.config || {},
    }))
  );
};

console.log("Reading HTML template...");
const templateContent = await readFile(templatePath, "utf-8");

console.log("Minifying HTML template...");
const minifiedHtml = await minifyHtml(templateContent, {
  collapseWhitespace: true,
  removeComments: true,
  removeRedundantAttributes: true,
  removeEmptyAttributes: true,
  minifyCSS: true,
  minifyJS: {
    compress: {
      dead_code: true,
      drop_console: false,
      drop_debugger: true,
      keep_classnames: false,
      keep_fnames: false,
    },
    mangle: {
      toplevel: true,
    },
  },
  minifyURLs: true,
  removeAttributeQuotes: true,
  removeOptionalTags: false,
  removeScriptTypeAttributes: true,
  removeStyleLinkTypeAttributes: true,
  useShortDoctype: true,
  keepClosingSlash: false,
  caseSensitive: false,
  conservativeCollapse: false,
  quoteCharacter: '"',
});

console.log(
  `Template: ${templateContent.length} → ${minifiedHtml.length} bytes (${Math.round(
    (1 - minifiedHtml.length / templateContent.length) * 100
  )}% reduction)`
);

const compiledConfig = await buildCompiledConfig(powConfigEntry);

await mkdir(outdir, { recursive: true });
await rm(powOutfile, { force: true });
await rm(powConfigOutfile, { force: true });

const buildSnippet = async ({ entryPoints, outfile, define }) => {
  await build({
    entryPoints,
    outfile,
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "neutral",
    minify: true,
    legalComments: "none",
    charset: "ascii",
    define,
  });
};

const minifyAndCheck = async (path) => {
  const built = await readFile(path, "utf-8");
  const terserResult = await minifyJs(built, {
    ecma: 2022,
    module: true,
    compress: {
      passes: 3,
      toplevel: true,
      unsafe: true,
      unsafe_arrows: true,
      unsafe_comps: true,
      unsafe_Function: true,
      unsafe_math: true,
      unsafe_methods: true,
      unsafe_proto: true,
      unsafe_regexp: true,
      unsafe_undefined: true,
      unsafe_symbols: true,
    },
    mangle: { toplevel: true },
    format: { ascii_only: true },
  });
  if (terserResult && typeof terserResult.code === "string") {
    await writeFile(path, terserResult.code);
  }

  const { size } = await stat(path);
  const limit = 32 * 1024;
  const status = size <= limit ? "OK" : "OVER";
  console.log(`Built snippet: ${path} (${size} bytes, ${status} ${limit} bytes)`);
  if (size > limit) process.exitCode = 1;
};

await buildSnippet({
  entryPoints: [powConfigEntry],
  outfile: powConfigOutfile,
  define: {
    __COMPILED_CONFIG__: compiledConfig,
  },
});
await buildSnippet({
  entryPoints: [powEntry],
  outfile: powOutfile,
  define: {
    __HTML_TEMPLATE__: JSON.stringify(minifiedHtml),
  },
});

await minifyAndCheck(powConfigOutfile);
await minifyAndCheck(powOutfile);
