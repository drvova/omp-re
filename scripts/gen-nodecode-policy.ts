#!/usr/bin/env bun
/**
 * Generates nodecode/policy-data.lisp from extensions/re/catalog.ts.
 *
 * The read-only command policy is the engine's security boundary, and the
 * nodecode cell carries its own Lisp engine. Rather than transcribe the
 * policy's regular expressions and command lists by hand — where one dropped
 * character silently widens what `rizin_command` will run — this script lifts
 * them out of catalog.ts and writes them as Lisp data. cl-ppcre reads the
 * same Perl syntax JavaScript writes, so the patterns cross unchanged.
 *
 *   bun scripts/gen-nodecode-policy.ts            # rewrite the file
 *   bun scripts/gen-nodecode-policy.ts --check    # exit 1 if it is stale
 *
 * test/nodecode-policy.test.ts runs the check, so a change to the policy in
 * catalog.ts that is not regenerated here fails CI.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { NOARG_DUALS, READ_ONLY_EXTRAS, REQUIRED_COMMANDS } from "../extensions/re/catalog.ts";

const ROOT = join(import.meta.dir, "..");
const SOURCE = join(ROOT, "extensions", "re", "catalog.ts");
const TARGET = join(ROOT, "nodecode", "policy-data.lisp");
const source = readFileSync(SOURCE, "utf8");

/** The body between the brackets that open at `open` (index of `[` or `(`), honouring strings and regex literals well enough for this one file. */
function literalAfter(marker: string): string {
	const start = source.indexOf(marker);
	if (start === -1) throw new Error(`gen-nodecode-policy: ${marker} not found in catalog.ts`);
	const from = start + marker.length;
	const end = source.indexOf(";\n", from);
	return source.slice(from, end).trim();
}

/** A non-exported `const NAME = <literal>;` evaluated as JavaScript. */
function constant<T>(name: string, typed = ""): T {
	const literal = literalAfter(`const ${name}${typed} = `);
	return new Function(`return (${literal});`)() as T;
}

const allowed = constant<RegExp>("ALLOWED_COMMAND");
const denied = constant<RegExp>("DENIED_COMMAND");
const entropy = constant<RegExp>("ENTROPY_MAP");
const forbidden = constant<[RegExp, string][]>("FORBIDDEN_SYNTAX", ": readonly [RegExp, string][]");
const debugReads = constant<Set<string>>("DEBUG_READ_COMMANDS", ": ReadonlySet<string>");

for (const regex of [allowed, denied, entropy, ...forbidden.map(([r]) => r)]) {
	if (regex.flags !== "") throw new Error(`gen-nodecode-policy: /${regex.source}/${regex.flags} carries flags the Lisp side does not model`);
}

const lispString = (text: string) => `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

function stringList(name: string, doc: string, values: Iterable<string>): string {
	const items = [...values].map(lispString);
	const lines: string[] = [];
	let line = "   ";
	for (const item of items) {
		if (line.length + item.length + 1 > 96) {
			lines.push(line.trimEnd());
			line = "   ";
		}
		line += ` ${item}`;
	}
	if (line.trim() !== "") lines.push(line.trimEnd());
	return `(defparameter ${name}\n  '(\n${lines.join("\n")})\n  ${lispString(doc)})`;
}

const out = `;;;; policy-data.lisp --- GENERATED from extensions/re/catalog.ts. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-nodecode-policy.ts
;;;; The read-only command policy's patterns and command lists, lifted out of
;;;; the TypeScript engine so the two engines cannot disagree about what
;;;; rizin_command may run. policy.lisp is the logic over this data; the
;;;; reasons for every entry are in catalog.ts.

(in-package #:nodecode-re)

(defparameter +allowed-command+
  ${lispString(allowed.source)}
  "The read-only command families rizin_command may run.")

(defparameter +denied-command+
  ${lispString(denied.source)}
  "The exceptions inside those families, and any name that adds, removes or sets.")

(defparameter +entropy-map+
  ${lispString(entropy.source)}
  "The p=/p== histogram family, read-only despite the = in its name.")

(defparameter +forbidden-syntax+
  '(${forbidden.map(([regex, label]) => `(${lispString(regex.source)} . ${lispString(label)})`).join("\n    ")})
  "Syntax refused anywhere in a command, each with the words that name it.")

${stringList("+read-only-extras+", "Read-only commands the family pattern does not cover, by exact name.", READ_ONLY_EXTRAS)}

${stringList("+noarg-duals+", "Commands that list with no argument and mutate with one.", NOARG_DUALS)}

${stringList("+debug-read-commands+", "Read-only debugger-state commands a breakpoint's on-hit command may run.", debugReads)}

${stringList("+required-commands+", "Every rizin command the engine itself relies on.", REQUIRED_COMMANDS)}
`;

if (process.argv.includes("--check")) {
	if (readFileSync(TARGET, "utf8") !== out) {
		console.error("nodecode/policy-data.lisp is stale: run `bun scripts/gen-nodecode-policy.ts`");
		process.exit(1);
	}
} else {
	writeFileSync(TARGET, out);
	console.log(`wrote ${TARGET}`);
}
