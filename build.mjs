#!/usr/bin/env node
/**
 * Builds the Nouvopolis evidence checker: dist/check.html (one
 * self-contained page) and dist/check.sh (a POSIX shell script), the two
 * tools shipped in every Nouvopolis evidence export and published, with
 * their SHA-256, at https://nouvopolis.com/check.
 *
 * The build is reproducible: from this directory, with the exact
 * dependencies in package-lock.json (`npm ci`), `npm run build` gives the
 * published files byte for byte. Nothing in the output depends on the time,
 * the machine or the path.
 *
 * - The page's script (src/app/lib/evidence/checker/page.ts) is bundled and
 *   inlined. The page's Content Security Policy allows only that script and
 *   that style, by hash, and no connection, image, font, frame or form.
 * - The licence of every package bundled into the page is embedded in it.
 *   No GPL or LGPL code: the build fails on one.
 * - The wording comes from src/texts.en.json (the Nouvopolis `en` locale);
 *   the version from package.json.
 *
 * Usage: node build.mjs [outDir]   (default: dist)
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "src");
const REFUSED_LICENCES = /\b(?:L?GPL|AGPL)/i;
const TEXTS_PLACEHOLDER = "__NOUVOPOLIS_CHECKER_TEXTS__";

const STYLE = `
:root { color-scheme: light dark; --ink: #1b1b1f; --muted: #5d5d66; --line: #d4d4da; --ok: #1d6b3a; --fail: #a32020; --bg: #fbfbfa; }
@media (prefers-color-scheme: dark) { :root { --ink: #ececf0; --muted: #a6a6b0; --line: #3a3a42; --ok: #6fcf8f; --fail: #ff8a80; --bg: #16161a; } }
body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
#app { max-width: 52rem; margin: 0 auto; padding: 2rem 1rem 4rem; }
h1 { font-size: 1.5rem; font-weight: 600; margin: 0 0 1rem; }
p, label, small { overflow-wrap: anywhere; }
small { color: var(--muted); }
button { font: inherit; padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--line); cursor: pointer; }
#summary[data-result="ok"] { color: var(--ok); font-weight: 600; }
#summary[data-result="fail"] { color: var(--fail); font-weight: 600; }
#results { padding-left: 1.25rem; }
#results li { margin: 0.25rem 0; overflow-wrap: anywhere; }
#results li[data-status="ok"] strong { color: var(--ok); }
#results li[data-status="fail"] strong { color: var(--fail); }
#results li[data-status="note"] strong { color: var(--muted); }
code, pre { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.875em; }
pre { white-space: pre-wrap; border: 1px solid var(--line); padding: 0.75rem; border-radius: 6px; }
`.trim();

/** The version of the checker, from package.json. */
export const checkerVersion = () => JSON.parse(readFileSync(join(HERE, "package.json"), "utf8")).version;

/**
 * The texts, with {version} filled in.
 * @param {string} version
 * @returns {Record<string, string>}
 */
function texts(version) {
  const raw = JSON.parse(readFileSync(join(SRC, "texts.en.json"), "utf8"));
  return Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, String(v).replaceAll("{version}", version)]));
}

/**
 * The package a bundled module belongs to, from its node_modules path.
 * @param {string} id
 * @returns {string}
 */
function packageOf(id) {
  const [scope = "", name = ""] = (id.split("node_modules/").pop() ?? "").split("/");
  return scope.startsWith("@") ? `${scope}/${name}` : scope;
}

/**
 * The directory of an installed package, looked up from this directory upwards.
 * @param {string} name
 */
function packageDir(name) {
  for (let dir = HERE; ; dir = dirname(dir)) {
    const candidate = join(dir, "node_modules", name);
    if (existsSync(join(candidate, "package.json"))) return candidate;
    if (dirname(dir) === dir) throw new Error(`build: ${name} is not installed`);
  }
}

/** @param {string} name */
function licenceOf(name) {
  const dir = packageDir(name);
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const license = typeof pkg.license === "string" ? pkg.license : JSON.stringify(pkg.license ?? "UNKNOWN");
  if (REFUSED_LICENCES.test(license)) throw new Error(`build: ${name} is ${license}; no (L)GPL code in the checker`);
  const file = readdirSync(dir).sort().find((f) => /^(licen[cs]e|copying)(\.md|\.txt)?$/i.test(f));
  if (!file) throw new Error(`build: ${name} ships no licence file`);
  return { name: `${name} ${pkg.version}`, license, text: readFileSync(join(dir, file), "utf8") };
}

/** @param {string} text */
const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("base64");

/** A shell-safe single-quoted string. @param {string} text */
const shellQuote = (text) => `'${text.replace(/'/g, `'\\''`)}'`;

/** The page. @param {Record<string, string>} words */
async function buildPage(words) {
  const result = await build({
    configFile: false,
    logLevel: "warn",
    root: HERE,
    resolve: { alias: { "~": join(SRC, "app") } },
    build: {
      write: false,
      minify: true,
      target: "es2022",
      lib: { entry: join(SRC, "app/lib/evidence/checker/page.ts"), formats: ["iife"], name: "NouvopolisChecker", fileName: () => "check.js" },
    },
  });
  const outputs = /** @type {import("vite").Rollup.RollupOutput[]} */ (Array.isArray(result) ? result : [result]).flatMap((r) => r.output);
  const chunk = outputs.find((o) => o.type === "chunk");
  if (!chunk) throw new Error("build: no script was built");
  const code = chunk.code.replace(/<\/script/gi, "<\\/script");
  const packages = [...new Set(Object.keys(chunk.modules).filter((id) => id.includes("node_modules/")).map(packageOf))].sort();
  const licenceJson = JSON.stringify(packages.map(licenceOf)).replace(/</g, "\\u003c");
  const textJson = JSON.stringify(words).replace(/</g, "\\u003c");
  const csp = [
    "default-src 'none'",
    `script-src 'sha256-${sha256(code)}'`,
    `style-src 'sha256-${sha256(STYLE)}'`,
    "connect-src 'none'",
    "img-src 'none'",
    "font-src 'none'",
    "frame-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
  ].join("; ");
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<title>Nouvopolis</title>
<style>${STYLE}</style>
</head>
<body>
<main id="app"></main>
<script type="application/json" id="texts">${textJson}</script>
<script type="application/json" id="licences">${licenceJson}</script>
<script>${code}</script>
</body>
</html>
`;
  return { html, packages };
}

/** The script, with every {{key}} replaced by its text, shell-quoted. @param {Record<string, string>} words */
function buildScript(words) {
  const template = readFileSync(join(SRC, "app/lib/evidence/checker/check.sh"), "utf8");
  return template.replace(/\{\{([A-Za-z0-9.-]+)\}\}/g, (_m, key) => {
    if (!(key in words)) throw new Error(`build: no text for ${key}`);
    return shellQuote(/** @type {string} */ (words[key]));
  });
}

/**
 * Builds both tools into outDir. Returns their paths, sizes and SHA-256.
 * @param {string} [outDir]
 */
export async function buildChecker(outDir = join(HERE, "dist")) {
  const version = checkerVersion();
  const words = texts(version);
  const { html, packages } = await buildPage(words);
  const script = buildScript(words);
  mkdirSync(outDir, { recursive: true });
  const files = { "check.html": html, "check.sh": script };
  const out = [];
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(outDir, name), content);
    out.push({ name, bytes: Buffer.byteLength(content), sha256: createHash("sha256").update(content, "utf8").digest("hex") });
  }
  return { version, packages, files: out };
}

if (process.argv[1] && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  const result = await buildChecker(process.argv[2] ? resolve(process.argv[2]) : undefined);
  console.log(`Nouvopolis evidence checker ${result.version} (${result.packages.join(", ")})`);
  for (const f of result.files) console.log(`${f.sha256}  ${f.name}  (${f.bytes} bytes)`);
}
