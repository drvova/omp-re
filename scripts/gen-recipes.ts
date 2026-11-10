#!/usr/bin/env bun
/**
 * Generates the recipe tables for every host from recipes/tables.json.
 *
 * The recipes — triage, scan-imports, inspect-function, find-comparisons,
 * find-crypto — are code composed in the host's eval over the one read tool:
 * Lisp verbs under nodecode (nodecode/recipes.lisp), and under omp one
 * `%load`-able script for each of eval's kernels (skills/re-triage/recipes.js
 * for JavaScript, recipes.py for Python). The judgement they share — which
 * imports a reviewer stops at and why, what a program's imports say it can
 * reach, which strings are worth a first look, which byte strings betray
 * which algorithm — lives once, in recipes/tables.json, and is written from
 * there into each host's own language:
 *
 *   nodecode/recipe-data.lisp          the whole file
 *   skills/re-triage/recipes.js        the block between the generated markers
 *   skills/re-triage/recipes.py        the block between the generated markers
 *
 *   bun scripts/gen-recipes.ts            # rewrite all three
 *   bun scripts/gen-recipes.ts --check    # exit 1 if any is stale
 *
 * test/nodecode-parity.test.ts runs the check.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const SOURCE = join(ROOT, "recipes", "tables.json");
const LISP = join(ROOT, "nodecode", "recipe-data.lisp");
const JS = join(ROOT, "skills", "re-triage", "recipes.js");
const PY = join(ROOT, "skills", "re-triage", "recipes.py");
const MARK_BEGIN = "<generated:tables> — from recipes/tables.json by scripts/gen-recipes.ts; do not edit";
const MARK_END = "</generated:tables>";
const BEGIN = `// ${MARK_BEGIN}`;
const END = `// ${MARK_END}`;
const PY_BEGIN = `# ${MARK_BEGIN}`;
const PY_END = `# ${MARK_END}`;

interface Tables {
	riskyImports: { category: string; severity: string; why: string; names: string[] }[];
	capabilities: { capability: string; names: string[] }[];
	severityOrder: string[];
	stringInterest: { kind: string; pattern: string }[];
	packerSectionNames: string;
	comparingCalls: string;
	cryptoConstants: { algorithm: string; what: string; hex: string }[];
}

const tables = JSON.parse(readFileSync(SOURCE, "utf8")) as Tables;

/**
 * Why `pattern` would not mean the same thing to Python's `re` as to JavaScript's RegExp, or
 * undefined when it would. recipes.js compiles a pattern with the `i` flag and no `u`;
 * recipes.py with `re.IGNORECASE | re.ASCII`, which gives the same ASCII-only case folding,
 * `\b`, `\d` and `\w` — provided the pattern stays inside what the two dialects share. This
 * is that subset, checked by hand because Python cannot be asked from here; what it cannot see
 * (a look-behind of variable width, which Python refuses) is caught by the test that compiles
 * every pattern in omp's real Python kernel (test/recipes-eval.test.ts).
 */
function notPortableToPython(pattern: string): string | undefined {
	let inClass = false;
	for (let i = 0; i < pattern.length; i++) {
		const c = pattern[i]!;
		const rest = pattern.slice(i);
		if (c.charCodeAt(0) > 126 || c.charCodeAt(0) < 32) return `has a character outside printable ASCII at ${i}; under re.ASCII Python folds case for ASCII only, as JavaScript does only for an ASCII pattern — write it as \\uXXXX if it must be there`;
		if (c === "\\") {
			const next = pattern[i + 1];
			if (next === undefined) return "ends in a lone backslash";
			const hex = next === "x" ? /^\\x[0-9a-fA-F]{2}/.test(rest) : next === "u" ? /^\\u[0-9a-fA-F]{4}/.test(rest) : false;
			const shared = inClass ? "bdDwWnrtfv" : "bBdDwWnrtfv";
			if (hex) i += next === "x" ? 3 : 5;
			else if (shared.includes(next) || (!inClass && /[1-9]/.test(next)) || !/[A-Za-z0-9]/.test(next)) i += 1;
			else return `uses \\${next}, which the two dialects read differently or one lacks (\\s covers different characters; \\A, \\Z, \\0, \\k, \\p are not shared)`;
			continue;
		}
		if (inClass) {
			if (c === "]") inClass = false;
			else if (c === "[") return `has an unescaped [ inside a character class at ${i}, which Python warns about`;
			continue;
		}
		if (c === "[") {
			if (/^\[\^?\]/.test(rest)) return `has an empty character class at ${i}: JavaScript matches nothing (or anything) with it, Python reads the ] as a member`;
			inClass = true;
			if (pattern[i + 1] === "^") i += 1;
		} else if (c === "$") return `uses $ at ${i}: Python's also matches before a final newline — anchor with a look-ahead instead`;
		else if (c === ".") return `uses . at ${i}: JavaScript's stops at \\r, U+2028 and U+2029 as well as \\n, Python's at \\n alone — write the class meant`;
		else if (c === "(" && pattern[i + 1] === "?" && !/^\(\?(?::|=|!|<=|<!)/.test(rest)) return `uses a group form at ${i} the two dialects do not share (named groups are (?<n>…) in one and (?P<n>…) in the other; inline flags and atomic groups are Python's alone)`;
		else if (c === "{" && !/^\{\d+(?:,\d*)?\}/.test(rest)) return `has a { at ${i} that is not a {n}, {n,} or {n,m} quantifier`;
	}
	return inClass ? "has an unclosed character class" : undefined;
}

// The patterns are matched without regard to case on every host; each must be valid, and mean the same, in every dialect.
for (const pattern of [...tables.stringInterest.map((s) => s.pattern), tables.packerSectionNames, tables.comparingCalls]) {
	new RegExp(pattern, "i");
	if (/\(\?[a-zA-Z]/.test(pattern)) throw new Error(`gen-recipes: ${pattern} uses an inline flag JavaScript does not have`);
	const why = notPortableToPython(pattern);
	if (why !== undefined) throw new Error(`gen-recipes: ${pattern} is not portable to Python's re: it ${why}`);
}
for (const constant of tables.cryptoConstants) {
	if (!/^(?:[0-9a-f]{2})+$/.test(constant.hex)) throw new Error(`gen-recipes: ${constant.algorithm} ${constant.what}: ${constant.hex} is not whole bytes of lowercase hex`);
}

const q = (text: string) => `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/** Strings wrapped to the line width, each line indented by `indent`. */
function wrapped(items: string[], indent: string): string {
	const lines: string[] = [];
	let line = indent;
	for (const item of items) {
		if (line.length + item.length + 1 > 100 && line.trim() !== "") {
			lines.push(line.trimEnd());
			line = indent;
		}
		line += `${line === indent ? "" : " "}${item}`;
	}
	if (line.trim() !== "") lines.push(line.trimEnd());
	return lines.join("\n");
}

const lisp = `;;;; recipe-data.lisp --- GENERATED from recipes/tables.json. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-recipes.ts
;;;; The judgement the recipes rest on, kept as data so it can be argued with
;;;; and so the Lisp verbs and omp's eval script (skills/re-triage/recipes.js)
;;;; read the same tables. recipes.lisp is the code over them.

(in-package #:nodecode-re)

(defparameter *risky-imports*
  ;; (CATEGORY SEVERITY WHY NAME...) — what a reviewer would stop at, and the
  ;; reason in a line. Severity is how little the caller can do to make the
  ;; call safe, not how likely a bug is.
  '(${tables.riskyImports.map((row) => `(${q(row.category)} ${q(row.severity)} ${q(row.why)}\n${wrapped(row.names.map(q), "     ")})`).join("\n    ")})
  "Imports a reviewer stops at.")

(defparameter *capability-imports*
  ;; (CAPABILITY NAME...) — what the program can reach, read off what it links.
  '(${tables.capabilities.map((row) => `(${q(row.capability)}\n${wrapped(row.names.map(q), "     ")})`).join("\n    ")})
  "What a program can do, read off what it imports. A capability is not an intent.")

(defparameter *severity-order* '(${tables.severityOrder.map(q).join(" ")})
  "Severities, the one to read first first.")

(defparameter *string-interest*
  '(${tables.stringInterest.map((row) => `(${q(row.kind)} ${q(`(?i)${row.pattern}`)})`).join("\n    ")})
  "What makes a string worth a first look, by the kind of lead it is.")

(defparameter +packer-section-names+
  ${q(`(?i)${tables.packerSectionNames}`)}
  "Section names packers and protectors leave behind.")

(defparameter +comparing-calls+
  ${q(`(?i)${tables.comparingCalls}`)}
  "Calls that decide something about their input: comparisons by name, and names that say they validate.")

(defparameter *crypto-constants*
  ;; (ALGORITHM WHAT HEX) — byte strings as they lie in memory; a table of
  ;; words is listed in both byte orders. These are published constants.
  '(${tables.cryptoConstants.map((row) => `(${q(row.algorithm)} ${q(row.what)} ${q(row.hex)})`).join("\n    ")})
  "Byte strings whose presence says an algorithm's tables are in the binary.")
`;

const jsBlock = `${BEGIN}\nconst TABLES = ${JSON.stringify(tables, null, 2)};\n${END}`;

/**
 * `value` as a Python literal, laid out as JSON.stringify lays out JSON. The two notations differ
 * in three words (true, false, null) and in nothing else these tables can hold: a JSON string is
 * a Python string literal with the same escapes, once the few characters JSON leaves raw and a
 * Python source file should not hold raw are escaped too.
 */
function pyLiteral(value: unknown, indent: string): string {
	if (value === null) return "None";
	if (value === true) return "True";
	if (value === false) return "False";
	if (typeof value === "string") return JSON.stringify(value).replace(/[\u007f-\u009f\u2028\u2029\ufeff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error(`gen-recipes: ${value} has no plain Python literal`);
		return String(value);
	}
	const inner = `${indent}  `;
	if (Array.isArray(value)) return value.length === 0 ? "[]" : `[\n${value.map((member) => `${inner}${pyLiteral(member, inner)}`).join(",\n")}\n${indent}]`;
	if (typeof value === "object") {
		const members = Object.entries(value as Record<string, unknown>);
		return members.length === 0 ? "{}" : `{\n${members.map(([key, member]) => `${inner}${pyLiteral(key, inner)}: ${pyLiteral(member, inner)}`).join(",\n")}\n${indent}}`;
	}
	throw new Error(`gen-recipes: ${String(value)} has no Python literal`);
}

// The tables are a local of the function recipes.py builds its namespace in, hence the indentation; the marker lines are comments and need none.
const pyBlock = `${PY_BEGIN}\n    TABLES = ${pyLiteral(tables, "    ")}\n${PY_END}`;

function withBlock(file: string, source: string, begin: string, end: string, block: string): string {
	const from = source.indexOf(begin);
	const to = source.indexOf(end);
	if (from === -1 || to === -1 || to < from) throw new Error(`gen-recipes: ${file} has no generated-tables block (expected the two marker lines)`);
	return `${source.slice(0, from)}${block}${source.slice(to + end.length)}`;
}

const check = process.argv.includes("--check");
const stale: string[] = [];
if (!existsSync(LISP) || readFileSync(LISP, "utf8") !== lisp) {
	if (check) stale.push("nodecode/recipe-data.lisp");
	else writeFileSync(LISP, lisp);
}
for (const [file, name, begin, end, block] of [
	[JS, "skills/re-triage/recipes.js", BEGIN, END, jsBlock],
	[PY, "skills/re-triage/recipes.py", PY_BEGIN, PY_END, pyBlock],
] as const) {
	if (existsSync(file)) {
		const current = readFileSync(file, "utf8");
		const next = withBlock(file, current, begin, end, block);
		if (current !== next) {
			if (check) stale.push(name);
			else writeFileSync(file, next);
		}
	} else if (check) stale.push(`${name} (missing)`);
}
if (check && stale.length > 0) {
	console.error(`stale: ${stale.join(", ")} — run \`bun scripts/gen-recipes.ts\``);
	process.exit(1);
}
if (!check) console.log("recipe tables written");
