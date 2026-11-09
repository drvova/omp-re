#!/usr/bin/env bun
/**
 * Generates the recipe tables for both hosts from recipes/tables.json.
 *
 * The recipes — triage, scan-imports, inspect-function, find-comparisons,
 * find-crypto — are code composed in the host's eval over the one read tool:
 * Lisp verbs under nodecode (nodecode/recipes.lisp), a `%load`-able script
 * under omp (skills/re-triage/recipes.js). The judgement they share — which
 * imports a reviewer stops at and why, what a program's imports say it can
 * reach, which strings are worth a first look, which byte strings betray
 * which algorithm — lives once, in recipes/tables.json, and is written from
 * there into each host's own language:
 *
 *   nodecode/recipe-data.lisp          the whole file
 *   skills/re-triage/recipes.js        the block between the generated markers
 *
 *   bun scripts/gen-recipes.ts            # rewrite both
 *   bun scripts/gen-recipes.ts --check    # exit 1 if either is stale
 *
 * test/nodecode-parity.test.ts runs the check.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const SOURCE = join(ROOT, "recipes", "tables.json");
const LISP = join(ROOT, "nodecode", "recipe-data.lisp");
const JS = join(ROOT, "skills", "re-triage", "recipes.js");
const BEGIN = "// <generated:tables> — from recipes/tables.json by scripts/gen-recipes.ts; do not edit";
const END = "// </generated:tables>";

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

// The patterns are matched without regard to case on both hosts; each must be valid in both dialects.
for (const pattern of [...tables.stringInterest.map((s) => s.pattern), tables.packerSectionNames, tables.comparingCalls]) {
	new RegExp(pattern, "i");
	if (/\(\?[a-zA-Z]/.test(pattern)) throw new Error(`gen-recipes: ${pattern} uses an inline flag JavaScript does not have`);
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

function jsWithBlock(source: string): string {
	const from = source.indexOf(BEGIN);
	const to = source.indexOf(END);
	if (from === -1 || to === -1 || to < from) throw new Error(`gen-recipes: ${JS} has no generated-tables block (expected the two marker lines)`);
	return `${source.slice(0, from)}${jsBlock}${source.slice(to + END.length)}`;
}

const check = process.argv.includes("--check");
const stale: string[] = [];
if (!existsSync(LISP) || readFileSync(LISP, "utf8") !== lisp) {
	if (check) stale.push("nodecode/recipe-data.lisp");
	else writeFileSync(LISP, lisp);
}
if (existsSync(JS)) {
	const current = readFileSync(JS, "utf8");
	const next = jsWithBlock(current);
	if (current !== next) {
		if (check) stale.push("skills/re-triage/recipes.js");
		else writeFileSync(JS, next);
	}
} else if (check) stale.push("skills/re-triage/recipes.js (missing)");
if (check && stale.length > 0) {
	console.error(`stale: ${stale.join(", ")} — run \`bun scripts/gen-recipes.ts\``);
	process.exit(1);
}
if (!check) console.log("recipe tables written");
