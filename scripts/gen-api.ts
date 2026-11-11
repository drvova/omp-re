#!/usr/bin/env bun
/**
 * Generates the verbs the model calls from eval, for every host, from recipes/api.json.
 *
 * The model has one way in on each host — eval — and the same handful of verbs there: open, cmd,
 * json, call, tools, doc, slash, status. They are thin: each checks what it was given, makes one
 * call of an engine tool or runs one line, and answers the engine's text (or, for json, the data).
 * What each takes, what it does and how it refuses is said once, in recipes/api.json, and written
 * from there in each host's language, so the three cannot drift:
 *
 *   nodecode/verb-forms.lisp           the whole file: a DEFINE-VERB each (nodecode/verbs.lisp is what they call)
 *   skills/re-triage/recipes.js        the block between the generated markers: `re.<verb>`, async
 *   skills/re-triage/recipes.py        the block between the generated markers: `omp_re.<verb>`, plain calls
 *
 *   bun scripts/gen-api.ts            # rewrite all three
 *   bun scripts/gen-api.ts --check    # exit 1 if any is stale
 *
 * A verb is { name, hosts?, takes, rest?, does, answers, doc }:
 *   takes    its arguments in order, each { name, type, optional?, nonEmpty?, refusal? }. `type` is
 *            "string", or "name" for the name of a tool — which the Lisp host also takes as a symbol,
 *            spelled the engine's way. With `refusal` an argument that is no string (or, with
 *            `nonEmpty`, an empty one) is refused in those words, {given} being what was passed.
 *   rest     what the remaining arguments are called: keyword arguments in Lisp and Python, one
 *            object in JavaScript (and, in Python, one dict before the keywords, for a name that is
 *            no Python identifier). They go to the tool beside the named ones.
 *   does     { call, arguments? }: one call of the engine tool `call` — a name, or { param } for the
 *            argument that names it — with `arguments` mapping each of the tool's parameters to the
 *            verb's argument of that name or to a { value }. Or { line }: one line, written as its
 *            parts, strings and { param }s, run together.
 *   answers  "text": the engine's text. "data": the output decoded from JSON, with the evidence id.
 *   doc      what it does, with {argument} where one is named: Lisp's docstring says it in capitals.
 *   hosts    the hosts that have it, where not all three do.
 * `hosts` at the top is what a refusal's {listTools} stands for on each.
 *
 * The wire the JavaScript and Python verbs speak — omp's listener, extensions/re/bridge.ts — has
 * its version and its directory's name in stdio/protocol.json's constants; they are written into
 * the two blocks from there.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readProtocol } from "./protocol.ts";

const ROOT = join(import.meta.dir, "..");
const SOURCE = join(ROOT, "recipes", "api.json");
const LISP = join(ROOT, "nodecode", "verb-forms.lisp");
const JS = join(ROOT, "skills", "re-triage", "recipes.js");
const PY = join(ROOT, "skills", "re-triage", "recipes.py");
const MARK_BEGIN = "<generated:api> — from recipes/api.json by scripts/gen-api.ts; do not edit";
const MARK_END = "</generated:api>";
const WIDTH = 100;

type Host = "js" | "py" | "lisp";
const HOSTS: Host[] = ["js", "py", "lisp"];

interface Argument {
	name: string;
	type: "string" | "name";
	optional?: boolean;
	nonEmpty?: boolean;
	refusal?: string;
}
type Part = string | { param: string };
type Given = string | { value: string };
interface Verb {
	name: string;
	hosts?: Host[];
	takes: Argument[];
	rest?: string;
	does: { call: string | { param: string }; arguments?: Record<string, Given> } | { line: Part[] };
	answers: "text" | "data";
	doc: string[];
}
interface Api {
	verbs: Verb[];
	hosts: Record<Host, { listTools: string }>;
}

const api = JSON.parse(readFileSync(SOURCE, "utf8")) as Api;
const constants = readProtocol().constants;
const refuse = (why: string): never => {
	throw new Error(`gen-api: ${why}`);
};

// --- the description must be one every host can be written from --------------------------------------

const IDENTIFIER = /^[a-z][a-z0-9_]*$/;
const recipes = (JSON.parse(readFileSync(join(ROOT, "recipes", "tables.json"), "utf8")) as { recipes: { name: string }[] }).recipes.map((recipe) => recipe.name);
const taken = new Set<string>(["recipes", ...recipes]);
for (const verb of api.verbs) {
	const where = `verbs.${verb.name}`;
	if (!IDENTIFIER.test(verb.name)) refuse(`${where}: a verb's name is lowercase letters, digits and underscores`);
	if (taken.has(verb.name)) refuse(`${where}: the name is a recipe's or another verb's`);
	taken.add(verb.name);
	for (const host of verb.hosts ?? []) if (!HOSTS.includes(host)) refuse(`${where}: no host called ${host}`);
	const names = [...verb.takes.map((argument) => argument.name), ...(verb.rest ? [verb.rest] : [])];
	for (const name of names) if (!IDENTIFIER.test(name)) refuse(`${where}: the argument ${name} is not lowercase letters, digits and underscores`);
	if (new Set(names).size !== names.length) refuse(`${where}: two arguments have one name`);
	let optional = false;
	for (const argument of verb.takes) {
		if (!["string", "name"].includes(argument.type)) refuse(`${where}: ${argument.name} has the type ${argument.type}; there are string and name`);
		if (optional && !argument.optional) refuse(`${where}: ${argument.name} is required after an optional argument`);
		optional ||= argument.optional === true;
		if (argument.optional && argument.refusal) refuse(`${where}: ${argument.name} is optional and has a refusal; an argument left out cannot be refused`);
		if (argument.nonEmpty && !argument.refusal) refuse(`${where}: ${argument.name} must not be empty and has no words to refuse an empty one with`);
		if (argument.refusal && !argument.refusal.includes("{given}")) refuse(`${where}: the refusal of ${argument.name} does not say what was {given}`);
	}
	const known = (name: string) => (verb.takes.some((argument) => argument.name === name) ? name : refuse(`${where}: does names ${name}, which it does not take`));
	if ("line" in verb.does) {
		if (verb.rest) refuse(`${where}: a line takes no further arguments`);
		if (verb.does.line.length === 0) refuse(`${where}: a line has at least one part`);
		for (const part of verb.does.line) if (typeof part !== "string") known(part.param);
	} else {
		if (typeof verb.does.call !== "string") known(verb.does.call.param);
		for (const given of Object.values(verb.does.arguments ?? {})) if (typeof given === "string") known(given);
	}
	if (!["text", "data"].includes(verb.answers)) refuse(`${where}: answers ${verb.answers}; there are text and data`);
	for (const match of verb.doc.join(" ").matchAll(/\{([^}]*)\}/g)) if (!names.includes(match[1]!)) refuse(`${where}: its doc names {${match[1]}}, which it does not take`);
}

const verbsOf = (host: Host) => api.verbs.filter((verb) => verb.hosts === undefined || verb.hosts.includes(host));

/** A refusal's words on `host`, split at what was given. */
function refusalParts(host: Host, argument: Argument): [string, string] {
	const [before, after] = argument.refusal!.replaceAll("{listTools}", api.hosts[host].listTools).split("{given}") as [string, string];
	return [before, after];
}

/** Words packed onto lines no wider than WIDTH less `indent`. */
function wrapped(text: string, indent: number): string[] {
	const lines: string[] = [];
	let line = "";
	for (const word of text.split(" ")) {
		if (line !== "" && indent + line.length + 1 + word.length > WIDTH) {
			lines.push(line);
			line = "";
		}
		line += `${line === "" ? "" : " "}${word}`;
	}
	if (line !== "") lines.push(line);
	return lines;
}

const docOf = (verb: Verb, spell: (name: string) => string) => verb.doc.join(" ").replace(/\{([^}]*)\}/g, (_all, name: string) => spell(name));

// --- JavaScript ------------------------------------------------------------------------------------

const js = JSON.stringify;

function jsVerb(verb: Verb): string {
	const parameters = [...verb.takes.map((argument) => argument.name), ...(verb.rest ? [verb.rest] : [])];
	const lines = wrapped(docOf(verb, (name) => `\`${name}\``), 12).map((line) => `\t\t// ${line}`);
	lines.push(`\t\t${verb.name}: async (${parameters.join(", ")}) => {`);
	for (const argument of verb.takes) {
		if (!argument.refusal) continue;
		const [before, after] = refusalParts("js", argument);
		const holds = `typeof ${argument.name} === "string"${argument.nonEmpty ? ` && trim(${argument.name}) !== ""` : ""}`;
		lines.push(`\t\t\tif (!(${holds})) throw refused(${js(before)}, ${argument.name}, ${js(after)});`);
	}
	let asked: string;
	if ("line" in verb.does) {
		const parts = verb.does.line;
		const only = parts.length === 1 ? parts[0]! : undefined;
		// A line that is one argument goes as it was given, so the engine refuses what is no line in its own words.
		const line = only !== undefined ? (typeof only === "string" ? js(only) : `${only.param} ?? ""`) : `\`${parts.map((part) => (typeof part === "string" ? part.replaceAll("`", "\\`").replaceAll("${", "\\${") : `\${${part.param}}`)).join("")}\``;
		asked = `engineLine(${line})`;
	} else {
		const tool = typeof verb.does.call === "string" ? js(verb.does.call) : verb.does.call.param;
		const named = Object.entries(verb.does.arguments ?? {}).map(([parameter, given]) => (typeof given === "string" ? (given === parameter ? parameter : `${parameter}: ${given}`) : `${parameter}: ${js(given.value)}`));
		const members = [...(verb.rest ? [`...rest(${js(verb.rest)}, ${verb.rest})`] : []), ...named];
		asked = `engineCall(${tool}, ${members.length === 0 ? "{}" : `{ ${members.join(", ")} }`})`;
	}
	lines.push(verb.answers === "data" ? `\t\t\treturn data(${verb.takes[0]!.name}, await ${asked});` : `\t\t\treturn text(await ${asked});`);
	lines.push("\t\t},");
	return lines.join("\n");
}

const jsBlock = [
	`\t// ${MARK_BEGIN}`,
	`\tconst BRIDGE = { version: ${js(constants.bridgeVersion)}, directory: ${js(constants.bridgeDirectory)} };`,
	"\tconst API = {",
	verbsOf("js").map(jsVerb).join("\n"),
	"\t};",
	`\t// ${MARK_END}`,
].join("\n");

// --- Python ----------------------------------------------------------------------------------------

/** A Python string literal: JSON's, with the characters a source file should not hold raw escaped too. */
const py = (text: string) => JSON.stringify(text).replace(/[\u007f-\u009f\u2028\u2029\ufeff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

function pyVerb(verb: Verb): string {
	const parameters = [...verb.takes.map((argument) => (argument.optional ? `${argument.name}=None` : argument.name)), ...(verb.rest ? [`${verb.rest}=None`, "**more"] : [])];
	const lines = [`        def ${verb.name}(${parameters.join(", ")}):`];
	const doc = wrapped(docOf(verb, (name) => `\`${name}\``), 12);
	lines.push(...(doc.length === 1 ? [`            """${doc[0]}"""`] : ['            """', ...doc.map((line) => `            ${line}`), '            """']));
	for (const argument of verb.takes) {
		if (!argument.refusal) continue;
		const [before, after] = refusalParts("py", argument);
		const holds = `isinstance(${argument.name}, str)${argument.nonEmpty ? ` and trim(${argument.name}) != ""` : ""}`;
		lines.push(`            if not (${holds}):`, `                raise refused(${py(before)}, ${argument.name}, ${py(after)})`);
	}
	let asked: string;
	if ("line" in verb.does) {
		const parts = verb.does.line;
		const only = parts.length === 1 ? parts[0]! : undefined;
		const line = only !== undefined ? (typeof only === "string" ? py(only) : `"" if ${only.param} is None else ${only.param}`) : parts.map((part) => (typeof part === "string" ? py(part) : `str(${part.param})`)).join(" + ");
		asked = `engine_line(${line})`;
	} else {
		const tool = typeof verb.does.call === "string" ? py(verb.does.call) : verb.does.call.param;
		const named = Object.entries(verb.does.arguments ?? {}).map(([parameter, given]) => `${py(parameter)}: ${typeof given === "string" ? given : py(given.value)}`);
		const members = `{${named.join(", ")}}`;
		asked = `engine_call(${tool}, ${verb.rest ? (named.length === 0 ? `rest(${py(verb.rest)}, ${verb.rest}, more)` : `dict(rest(${py(verb.rest)}, ${verb.rest}, more), **${members})`) : members})`;
	}
	lines.push(verb.answers === "data" ? `            return data(${verb.takes[0]!.name}, ${asked})` : `            return text(${asked})`);
	return lines.join("\n");
}

// The verbs are locals of the function recipes.py builds its namespace in, hence the indentation; the marker lines are comments and need none.
const pyBlock = [
	`# ${MARK_BEGIN}`,
	`    BRIDGE = {"version": ${constants.bridgeVersion}, "directory": ${py(String(constants.bridgeDirectory))}}`,
	"",
	"    def api_functions():",
	...verbsOf("py").map((verb) => `${pyVerb(verb)}\n`),
	`        return [${verbsOf("py")
		.map((verb) => verb.name)
		.join(", ")}]`,
	`# ${MARK_END}`,
].join("\n");

// --- Lisp ------------------------------------------------------------------------------------------

const lispString = (text: string) => `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const lispName = (name: string) => name.replaceAll("_", "-");

function lispVerb(verb: Verb): string {
	const required = verb.takes.filter((argument) => !argument.optional).map((argument) => lispName(argument.name));
	const optional = verb.takes.filter((argument) => argument.optional).map((argument) => lispName(argument.name));
	// A call that names its tool hands its keywords on as they are; one whose tool is fixed takes any key, and the tool's own schema says which it has.
	const fixed = !("line" in verb.does) && typeof verb.does.call === "string";
	const lambdaList = [...required, ...(optional.length > 0 ? ["&optional", ...optional] : []), ...(verb.rest ? ["&rest", lispName(verb.rest), ...(fixed ? ["&key", "&allow-other-keys"] : [])] : [])];
	const doc = wrapped(docOf(verb, (name) => lispName(name).toUpperCase()), 2);
	const lines = [`(define-verb ${verb.name} (${lambdaList.join(" ")})`, ...doc.map((line, index) => `${index === 0 ? '  "' : ""}${line.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}${index === doc.length - 1 ? '"' : ""}`)];
	for (const argument of verb.takes) {
		if (!argument.refusal) continue;
		const [before, after] = refusalParts("lisp", argument);
		const name = lispName(argument.name);
		const holds = argument.nonEmpty ? `(and (stringp ${name}) (not (blank-p ${name})))` : `(stringp ${name})`;
		lines.push(`  (unless ${holds}`, `    (fail ${lispString(`${before.replaceAll("~", "~~")}~s${after.replaceAll("~", "~~")}`)} ${name}))`);
	}
	const value = (argument: string) => {
		const found = verb.takes.find((one) => one.name === argument)!;
		return found.type === "name" ? `(engine-name ${lispName(argument)})` : lispName(argument);
	};
	let asked: string;
	if ("line" in verb.does) {
		const parts = verb.does.line;
		const only = parts.length === 1 ? parts[0]! : undefined;
		const line = only !== undefined ? (typeof only === "string" ? lispString(only) : lispName(only.param)) : `(format nil ${lispString(parts.map((part) => (typeof part === "string" ? part.replaceAll("~", "~~") : "~a")).join(""))} ${parts.flatMap((part) => (typeof part === "string" ? [] : [value(part.param)])).join(" ")})`;
		asked = `(line-for-turn ${line})`;
	} else {
		const tool = typeof verb.does.call === "string" ? lispString(verb.does.call) : value(verb.does.call.param);
		const named = Object.entries(verb.does.arguments ?? {}).flatMap(([parameter, given]) => [`:${lispName(parameter)}`, typeof given === "string" ? lispName(given) : lispString(given.value)]);
		const plist = verb.rest ? (named.length === 0 ? lispName(verb.rest) : `(list* ${named.join(" ")} ${lispName(verb.rest)})`) : `(list ${named.join(" ")})`;
		asked = `(call-for-turn ${tool} ${plist})`;
	}
	lines.push(verb.answers === "data" ? `  (answer-data ${lispName(verb.takes[0]!.name)} ${asked}))` : `  (answer-text ${asked}))`);
	return lines.join("\n");
}

const lispFile = `;;;; verb-forms.lisp --- GENERATED from recipes/api.json. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-api.ts
;;;; The verbs the model calls from eval. What each takes, what it does and
;;;; how it refuses is said once, so these and omp's two eval libraries
;;;; (skills/re-triage/recipes.js and recipes.py) are the same verbs.
;;;; verbs.lisp is what they call; scripts/gen-api.ts says what each part of
;;;; the description means.

(in-package #:nodecode-re)

${verbsOf("lisp").map(lispVerb).join("\n\n")}
`;

// --- the three files ---------------------------------------------------------------------------

function withBlock(file: string, source: string, begin: string, end: string, block: string): string {
	const from = source.indexOf(begin);
	const to = source.indexOf(end);
	if (from === -1 || to === -1 || to < from) refuse(`${file} has no generated-api block (expected the two marker lines)`);
	// The opening marker may be indented; the block brings its own indentation.
	const lineStart = source.lastIndexOf("\n", from) + 1;
	return `${source.slice(0, lineStart)}${block}${source.slice(to + end.length)}`;
}

const check = process.argv.includes("--check");
const stale: string[] = [];
if (!existsSync(LISP) || readFileSync(LISP, "utf8") !== lispFile) {
	if (check) stale.push("nodecode/verb-forms.lisp");
	else writeFileSync(LISP, lispFile);
}
for (const [file, name, comment, block] of [
	[JS, "skills/re-triage/recipes.js", "//", jsBlock],
	[PY, "skills/re-triage/recipes.py", "#", pyBlock],
] as const) {
	if (existsSync(file)) {
		const current = readFileSync(file, "utf8");
		const next = withBlock(file, current, `${comment} ${MARK_BEGIN}`, `${comment} ${MARK_END}`, block);
		if (current !== next) {
			if (check) stale.push(name);
			else writeFileSync(file, next);
		}
	} else if (check) stale.push(`${name} (missing)`);
}
if (check && stale.length > 0) {
	console.error(`stale: ${stale.join(", ")} — run \`bun scripts/gen-api.ts\``);
	process.exit(1);
}
if (!check) console.log("api verbs written");
