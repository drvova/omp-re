#!/usr/bin/env bun
/**
 * Generates what the recipes hold as data, for every host, from recipes/tables.json.
 *
 * The recipes — triage, scan_imports, inspect_function, find_comparisons,
 * find_crypto — are code composed in the host's eval over the one read tool:
 * Lisp verbs under nodecode (nodecode/recipes.lisp), and under omp one
 * `%load`-able script for each of eval's kernels (skills/re-triage/recipes.js
 * for JavaScript, recipes.py for Python). Each of those three files keeps only
 * what its language forces on it: reading rizin's JSON, the host's way to the
 * engine for one read, how a number is printed, the loop that renders a recipe, and the
 * few facts a section needs code for. Everything else lives once, in
 * recipes/tables.json, and is written from there into each host's language:
 *
 *   nodecode/recipe-data.lisp          the whole file
 *   skills/re-triage/recipes.js        the block between the generated markers
 *   skills/re-triage/recipes.py        the block between the generated markers
 *
 *   bun scripts/gen-recipes.ts            # rewrite all three
 *   bun scripts/gen-recipes.ts --check    # exit 1 if any is stale
 *
 * What the JSON holds:
 *   riskyImports, capabilities, severityOrder, importNameRules, stringInterest,
 *   packerSectionNames, comparingCalls, cryptoConstants, opTypes, calleeAfter,
 *   branchMeanings, sectionNotes, thresholds, limits, whitespace
 *                       the judgement and the constants the facts are worked out with.
 *   formats             what a template's `commas`, `s`, `es` … stand for.
 *   text                sentences every recipe shares, and every refusal.
 *   hosts, help         what differs by host (how it names a call), and the frame of what recipes()
 *                       answers and of the line a load prints. That line also names the verbs, which
 *                       are recipes/api.json's (scripts/gen-api.ts writes them).
 *   facts               for each step a host works out in code, the names it leaves for the templates.
 *   recipes             each recipe: its options with defaults and bounds, its steps in order
 *                       (a read, or a fact worked out in code), its title and its sections.
 *
 * A section is { title?, lines?, rows?, limit?, row? | line?, under?, empty?, more?, after?, when? }:
 * the title and `lines` are written as they stand; `rows` names a list, cut at `limit` (an option
 * or a name in `limits`), each written with `row` (and the sections in `under`, read against that
 * row) — or all in one line with `line`, where `shown` is the list as cut; `empty` is the line for
 * no rows, `more` what the "… not shown" line calls the rest. A row its line cannot be written for
 * is left out before the list is counted, and a line that comes out empty is not written.
 *
 * A template is text with {…} in it:
 *   {name}  {name.member}  {.member}  {.}      a fact; a member of it; a member of the row; the row
 *   {a/b}                                      the first of these that is there
 *   {x:d} {x:x} {x:f2} {x:line} {x:json}       a number in decimal, in hex, to two places; a string on one line; JSON
 *   {x:<18} {x:d>9}                            padded on the right, on the left
 *   {x|none}                                   what to write when it is not there
 *   {x:n}  {x:commas}  {x:s}                   how many; joined; a plural ending (see formats)
 *   {@read}  {@.name}                          the [evidence …] citation of a read, of a row's read
 *   {x?yes|no}                                 one text when x is true or a list with something in it, else the other
 *   {?…}                                       left out whole when something in it is not there
 *   {if x} {unless x} {if x=word}              in a {?…}: keeps it, or leaves it out
 *   \{ \} \\                                   the characters themselves
 * A text placeholder takes a string and a number format a number; anything else is "not there".
 * The templates are parsed here, so a host only walks what this writes.
 *
 * A table that would mislead cannot be generated: the checks below refuse it.
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
const WIDTH = 100;

type Host = "js" | "py" | "lisp";

interface Option {
	name: string;
	default: number | boolean;
	least?: number;
	most?: number;
	doc: string;
}
type Step = { read: string; command: string; at?: boolean } | { derive: string };
interface Section {
	title?: string;
	lines?: string[];
	rows?: string;
	limit?: string;
	row?: string;
	line?: string;
	under?: Section[];
	empty?: string;
	more?: string;
	after?: string[];
	when?: string;
}
interface Recipe {
	name: string;
	about: string;
	summary: string[];
	takes?: { example: string; doc: string };
	options: Option[];
	steps: Step[];
	title: string;
	sections: Section[];
}
interface Tables {
	riskyImports: { category: string; severity: string; why: string; names: string[] }[];
	capabilities: { capability: string; names: string[] }[];
	severityOrder: string[];
	importNameRules: { rule: string; text: string }[];
	stringInterest: { kind: string; pattern: string }[];
	packerSectionNames: string;
	comparingCalls: string;
	cryptoConstants: { algorithm: string; what: string; hex: string }[];
	opTypes: Record<string, string[]>;
	calleeAfter: string;
	branchMeanings: { mnemonics: string[]; meaning: string }[];
	otherBranch: string;
	sectionNotes: Record<string, string>;
	thresholds: Record<string, number>;
	limits: Record<string, number>;
	whitespace: string[];
	formats: { joins: Record<string, string>; plurals: Record<string, [string, string]> };
	text: { more: string; evidenceTaken: string; evidenceRow: string; nameless: string; refusals: Record<string, string> };
	hosts: Record<Host, { global?: string; listFunctions: string; openFirst?: string; calling?: string; manual?: string }>;
	help: { header: string[]; footer: string[]; loaded: string; shown: string };
	facts: Record<string, string[]>;
	recipes: Recipe[];
}

const tables = JSON.parse(readFileSync(SOURCE, "utf8")) as Tables;
/** The verbs each kernel's library has beside the recipes, by name. */
const verbs = (JSON.parse(readFileSync(join(ROOT, "recipes", "api.json"), "utf8")) as { verbs: { name: string; hosts?: Host[] }[] }).verbs;
const verbNames = (host: Host) => verbs.filter((verb) => verb.hosts === undefined || verb.hosts.includes(host)).map((verb) => verb.name);
const refuse = (why: string): never => {
	throw new Error(`gen-recipes: ${why}`);
};

// --- the tables must be ones a recipe can stand on ------------------------------------------------

/**
 * Why `pattern` would not mean the same thing to Python's `re` as to JavaScript's RegExp, or
 * undefined when it would. recipes.js compiles a pattern with the `i` flag and no `u`;
 * recipes.py with `re.IGNORECASE | re.ASCII`, which gives the same ASCII-only case folding,
 * `\b`, `\d` and `\w` — provided the pattern stays inside what the two dialects share. This
 * is that subset, checked by hand; what it cannot see (a look-behind of variable width, which
 * Python refuses) is caught below by asking a Python, where one is installed.
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

/** `names` must not repeat: a second listing would be a second answer to the same question. */
function unique(what: string, names: string[]): void {
	const seen = new Set<string>();
	for (const name of names) {
		if (seen.has(name)) refuse(`${what}: ${name} is listed twice`);
		seen.add(name);
	}
}

const patterns = [...tables.stringInterest.map((s) => s.pattern), tables.packerSectionNames, tables.comparingCalls];
// The patterns are matched without regard to case on every host; each must be valid, and mean the same, in every dialect.
for (const pattern of patterns) {
	new RegExp(pattern, "i");
	if (/\(\?[a-zA-Z]/.test(pattern)) refuse(`${pattern} uses an inline flag JavaScript does not have`);
	const why = notPortableToPython(pattern);
	if (why !== undefined) refuse(`${pattern} is not portable to Python's re: it ${why}`);
}
const python3 = Bun.which("python3");
if (python3 !== null) {
	// Warnings are errors: Python warns about a pattern it reads differently from what was written.
	const asked = Bun.spawnSync(
		[python3, "-I", "-c", "import json, re, sys, warnings\nwarnings.simplefilter('error')\nfor p in json.load(sys.stdin):\n    try:\n        re.compile(p, re.IGNORECASE | re.ASCII)\n    except Exception as e:\n        sys.exit('%s: %s' % (p, e))"],
		{ stdin: Buffer.from(JSON.stringify(patterns)), stdout: "pipe", stderr: "pipe" },
	);
	if (asked.exitCode !== 0) refuse(`Python's re refuses a pattern — ${asked.stderr.toString().trim()}`);
}

for (const constant of tables.cryptoConstants) {
	if (!/^(?:[0-9a-f]{2})+$/.test(constant.hex)) refuse(`${constant.algorithm} ${constant.what}: ${constant.hex} is not whole bytes of lowercase hex`);
}
unique("cryptoConstants", tables.cryptoConstants.map((constant) => constant.hex));
// One row an import, so a name has one verdict.
unique("riskyImports", tables.riskyImports.flatMap((row) => row.names));
for (const row of tables.riskyImports) if (!tables.severityOrder.includes(row.severity)) refuse(`riskyImports: severity ${row.severity} is not in severityOrder`);
unique("capabilities", tables.capabilities.map((row) => row.capability));
unique("branchMeanings", tables.branchMeanings.flatMap((row) => row.mnemonics));
for (const mnemonic of tables.branchMeanings.flatMap((row) => row.mnemonics)) if (mnemonic !== mnemonic.toLowerCase()) refuse(`branchMeanings: ${mnemonic} is not lowercase, and a mnemonic is looked up in lowercase`);
for (const { rule } of tables.importNameRules) if (!["dropThrough", "dropPrefix", "dropLeading", "dropSuffix"].includes(rule)) refuse(`importNameRules: no rule called ${rule}`);
for (const [name, value] of Object.entries(tables.limits)) if (!Number.isInteger(value) || value < 1) refuse(`limits.${name} must be a whole number of at least 1`);
const whitespace = tables.whitespace.map((point) => {
	if (!/^U\+[0-9A-F]{4}$/.test(point)) refuse(`whitespace: ${point} is not U+XXXX`);
	return Number.parseInt(point.slice(2), 16);
});
unique("recipes", tables.recipes.map((recipe) => recipe.name));

// --- templates ---------------------------------------------------------------------------------

/** What a placeholder names, as a host looks it up: `info.class` is a fact and a member of it, `.name` a member of the row, `.` the row. */
type Path = string;
type Node =
	| string
	| { group: Node[] }
	| { if: Path; is?: string }
	| { unless: Path; is?: string }
	| { choose: Path; yes: string; no: string }
	| { cite: Path }
	| { count: Path }
	| { join: Path; with: string }
	| { plural: Path; one: string; many: string }
	| { get: Path[]; as?: string; padLeft?: number; padRight?: number; or?: string };

const SCALARS = ["text", "d", "x", "f2", "line", "json"];
const PATH = String.raw`\.|\.?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*`;

/**
 * `template` as the nodes a host walks. `known` is the facts a template may name — a name that is
 * not among them would be a line silently left out, so it is refused here; undefined for a text
 * whose facts the host supplies as it goes.
 */
function compile(where: string, template: string, known: Set<string> | undefined): Node[] {
	const bad = (why: string): never => refuse(`${where}: ${JSON.stringify(template)} ${why}`);
	const path = (text: string, id = false): Path => {
		if (!new RegExp(`^(?:${PATH})$`).test(text)) bad(`names ${JSON.stringify(text)}, which is not a fact, a member or a row`);
		const row = text.startsWith(".");
		const keys = text.split(".").filter((key) => key !== "");
		if (id) {
			if (keys.length !== 1) bad(`cites @${text}: a citation names one read`);
			keys[0] = `@${keys[0]}`;
		}
		if (!row && known !== undefined && !known.has(keys[0]!)) bad(`names ${keys[0]}, which no option, limit, read or fact of this recipe is called`);
		return `${row ? "." : ""}${keys.join(".")}`;
	};
	const placeholder = (body: string): Node => {
		const test = /^(if|unless) ([^=]+)(?:=(.*))?$/.exec(body);
		if (test) return { [test[1]!]: path(test[2]!), ...(test[3] === undefined ? {} : { is: test[3] }) } as Node;
		const choice = new RegExp(`^(${PATH})\\?(.*)$`, "s").exec(body);
		if (choice) {
			const bar = choice[2]!.indexOf("|");
			return { choose: path(choice[1]!), yes: bar === -1 ? choice[2]! : choice[2]!.slice(0, bar), no: bar === -1 ? "" : choice[2]!.slice(bar + 1) };
		}
		const bar = body.indexOf("|");
		const head = bar === -1 ? body : body.slice(0, bar);
		const fallback = bar === -1 ? undefined : body.slice(bar + 1);
		const colon = head.indexOf(":");
		const names = colon === -1 ? head : head.slice(0, colon);
		const spec = colon === -1 ? "" : head.slice(colon + 1);
		if (names.startsWith("@")) {
			if (spec !== "" || fallback !== undefined) bad("gives a citation a format or a fallback; it has neither");
			return { cite: path(names.slice(1), true) };
		}
		const parsed = /^([A-Za-z0-9]*)(?:([<>])(\d+))?$/.exec(spec);
		if (!parsed) return bad(`has the format ${JSON.stringify(spec)}, which is not a name and a width`);
		const [, format = "", side, width] = parsed;
		const whole = format in tables.formats.joins || format in tables.formats.plurals || format === "n";
		if (whole) {
			if (side !== undefined || fallback !== undefined || names.includes("/")) bad(`gives ${format} a width, a fallback or alternatives; it takes one list`);
			if (format === "n") return { count: path(names) };
			if (format in tables.formats.joins) return { join: path(names), with: tables.formats.joins[format]! };
			const [one, many] = tables.formats.plurals[format]!;
			return { plural: path(names), one, many };
		}
		if (format !== "" && !SCALARS.includes(format)) bad(`has the format ${format}; there are ${[...SCALARS, "n", ...Object.keys(tables.formats.joins), ...Object.keys(tables.formats.plurals)].join(", ")}`);
		return {
			get: names.split("/").map((name) => path(name)),
			...(format === "" || format === "text" ? {} : { as: format }),
			...(side === ">" ? { padLeft: Number(width) } : side === "<" ? { padRight: Number(width) } : {}),
			...(fallback === undefined ? {} : { or: fallback }),
		};
	};
	let at = 0;
	const sequence = (inGroup: boolean): Node[] => {
		const nodes: Node[] = [];
		let text = "";
		const flush = () => {
			if (text !== "") nodes.push(text);
			text = "";
		};
		while (at < template.length) {
			const c = template[at]!;
			if (c === "\\") {
				if (!"{}\\".includes(template[at + 1] ?? "")) bad("has a backslash before something other than {, } or \\");
				text += template[at + 1];
				at += 2;
			} else if (c === "}") {
				if (!inGroup) bad("has a } that closes nothing");
				at += 1;
				flush();
				return nodes;
			} else if (c === "{") {
				flush();
				if (template[at + 1] === "?") {
					at += 2;
					nodes.push({ group: sequence(true) });
				} else {
					const end = template.indexOf("}", at);
					const body = end === -1 ? bad("has a { that is never closed") : template.slice(at + 1, end);
					if (body.includes("{")) bad("has a { inside a placeholder");
					nodes.push(placeholder(body));
					at = end + 1;
				}
			} else {
				text += c;
				at += 1;
			}
		}
		if (inGroup) bad("has a {? that is never closed");
		flush();
		return nodes;
	};
	return sequence(false);
}

// --- one recipe, checked and compiled ------------------------------------------------------------

const snake = (camel: string) => camel.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
const camel = (snaked: string) => snaked.replace(/_([a-z])/g, (_all, letter: string) => letter.toUpperCase());
const callName = (host: Host, recipe: Recipe) => (host === "js" ? camel(recipe.name) : host === "py" ? recipe.name : recipe.name.replaceAll("_", "-").toUpperCase());
const optionKey = (host: Host, option: Option) => (host === "js" ? option.name : host === "py" ? snake(option.name) : snake(option.name).replaceAll("_", "-").toUpperCase());
/** What every host calls the function a recipe is asked about: the fact, and the argument. */
const ADDRESS = "addr";
const isFlag = (option: Option) => typeof option.default === "boolean";

function compiledRecipe(host: Host, recipe: Recipe): Record<string, unknown> {
	const where = `recipes.${recipe.name}`;
	// What a template of this recipe may name, as the steps leave it.
	const known = new Set<string>(["recipe", "listFunctions", "shown", ...Object.keys(tables.limits)]);
	if (recipe.takes) known.add(ADDRESS);
	const count = (name: string) => (name in tables.limits || recipe.options.some((option) => option.name === name && !isFlag(option)) ? name : refuse(`${where}: limit ${name} is neither a counted option nor a name in limits`));
	for (const option of recipe.options) {
		if (known.has(option.name)) refuse(`${where}: the option ${option.name} has the name of a limit or of another option`);
		known.add(option.name);
		if (isFlag(option)) {
			// A flag is on unless false is given: that is how each host reads one, so "off unless asked" has no spelling.
			if (option.default !== true) refuse(`${where}: the flag ${option.name} must default to true`);
		} else if (![option.default, option.least, option.most].every(Number.isInteger) || !(option.least! <= (option.default as number) && (option.default as number) <= option.most!)) {
			refuse(`${where}: the option ${option.name} needs whole numbers least <= default <= most`);
		}
	}
	for (const step of recipe.steps) {
		if ("derive" in step) {
			for (const name of tables.facts[step.derive] ?? refuse(`${where}: facts has no entry for the step ${step.derive}`)) known.add(name);
		} else {
			if (step.at && !recipe.takes) refuse(`${where}: the read ${step.read} is at an address the recipe does not take`);
			known.add(step.read).add(`@${step.read}`);
		}
	}
	const section = (at: string, source: Section, nested: boolean): Record<string, unknown> => {
		const text = (key: keyof Section) => (source[key] === undefined ? {} : { [key]: compile(`${at}.${key}`, source[key] as string, known) });
		if (source.rows === undefined ? ["limit", "row", "line", "under", "empty", "more"].some((key) => key in source) : (source.row === undefined) === (source.line === undefined)) {
			refuse(`${at}: a section lists rows with exactly one of row and line, or lists none and has neither`);
		}
		if (source.more !== undefined && source.limit === undefined) refuse(`${at}: "more" needs a limit to be past`);
		if (source.line !== undefined && source.under !== undefined) refuse(`${at}: rows said in one line have nothing under each`);
		if (source.when !== undefined && !nested) refuse(`${at}: "when" is for a section under a row`);
		const single = (name: string) => compile(`${at}.${name}`, `{if ${name}}`, known)[0] as { if: Path };
		return {
			...(source.when === undefined ? {} : { when: single(source.when).if }),
			...text("title"),
			...(source.lines === undefined ? {} : { lines: source.lines.map((line, index) => compile(`${at}.lines[${index}]`, line, known)) }),
			...(source.rows === undefined ? {} : { rows: single(source.rows).if }),
			...(source.limit === undefined ? {} : { limit: count(source.limit) }),
			...text("row"),
			...text("line"),
			...(source.under === undefined ? {} : { under: source.under.map((inner, index) => section(`${at}.under[${index}]`, inner, true)) }),
			...text("empty"),
			...(source.more === undefined ? {} : { more: source.more }),
			...(source.after === undefined ? {} : { after: source.after.map((line, index) => compile(`${at}.after[${index}]`, line, known)) }),
		};
	};
	return {
		name: recipe.name,
		call: callName(host, recipe),
		takes: recipe.takes !== undefined,
		...(host === "js" ? {} : { doc: documentation(host, recipe) }),
		options: recipe.options.map((option) => ({
			name: option.name,
			...(host === "js" ? {} : { key: optionKey(host, option) }),
			...(isFlag(option) ? { flag: true } : { default: option.default, least: option.least, most: option.most }),
		})),
		steps: recipe.steps,
		title: compile(`${where}.title`, recipe.title, known),
		sections: recipe.sections.map((source, index) => section(`${where}.sections[${index}]`, source, false)),
	};
}

// --- what a host says about its recipes -----------------------------------------------------------

/** What a recipe answers and what each argument does, for the host's own way of asking (a docstring). */
function documentation(host: Host, recipe: Recipe): string {
	const lisp = host === "lisp";
	const lines = recipe.takes ? [`${lisp ? ADDRESS.toUpperCase() : ADDRESS}: ${recipe.takes.doc}.`] : [];
	for (const option of recipe.options) {
		const key = optionKey(host, option);
		lines.push(isFlag(option) ? `${key} (default ${lisp ? "T; :FALSE for no" : "True"}): ${option.doc}.` : `${key} (default ${option.default}, ${option.least}..${option.most}): ${option.doc}.`);
	}
	return `${wrapped(recipe.about.split(" "), "")}\n\n${lines.join("\n")}`;
}

/** How a recipe is called, with every option at its default: one line of help(). */
function signature(host: "js" | "py", recipe: Recipe): string {
	const call = `${tables.hosts[host].global}.${callName(host, recipe)}`;
	const example = recipe.takes ? [JSON.stringify(recipe.takes.example)] : [];
	if (host === "js") return `  await ${call}(${[...example, `{ ${recipe.options.map((option) => `${option.name} = ${option.default}`).join(", ")} }`].join(", ")})`;
	return `  ${call}(${[...example, ...recipe.options.map((option) => `${optionKey(host, option)}=${option.default === true ? "True" : option.default}`)].join(", ")})`;
}

function hostSays(host: Host): Record<string, string> {
	const says = tables.hosts[host];
	if (host === "lisp") return { listFunctions: says.listFunctions };
	const filled = (line: string) =>
		line
			.replaceAll("{openFirst}", says.openFirst!)
			.replaceAll("{global}", says.global!)
			.replaceAll("{calling}", says.calling!)
			.replaceAll("{manual}", says.manual!)
			.replaceAll("{verbs}", verbNames(host).map((name) => `${says.global}.${name}`).join(", "))
			.replaceAll("{verbNames}", verbNames(host).join(", "))
			.replaceAll("{calls}", tables.recipes.map((recipe) => `${says.global}.${callName(host, recipe)}`).join(", "))
			.replaceAll("{names}", tables.recipes.map((recipe) => callName(host, recipe)).join(", "));
	return {
		listFunctions: says.listFunctions,
		help: [...tables.help.header.map(filled), "", ...tables.recipes.flatMap((recipe) => [signature(host, recipe), ...recipe.summary.map((line) => `      ${line}`)]), "", ...tables.help.footer.map(filled)].join("\n"),
		loaded: filled(tables.help.loaded),
		...(host === "py" ? { shown: filled(tables.help.shown) } : {}),
	};
}

const REFUSAL_FACTS = new Set(["recipe", "given", "addr", "listFunctions"]);

function hostTables(host: Host): Record<string, unknown> {
	// cl-ppcre takes case-insensitivity as a prefix; JavaScript and Python take it as a flag where the pattern is compiled.
	const pattern = (source: string) => (host === "lisp" ? `(?i)${source}` : source);
	return {
		riskyImports: tables.riskyImports,
		capabilities: tables.capabilities,
		severityOrder: tables.severityOrder,
		importNameRules: tables.importNameRules,
		stringInterest: tables.stringInterest.map((row) => ({ kind: row.kind, pattern: pattern(row.pattern) })),
		packerSectionNames: pattern(tables.packerSectionNames),
		comparingCalls: pattern(tables.comparingCalls),
		cryptoConstants: tables.cryptoConstants,
		opTypes: tables.opTypes,
		calleeAfter: tables.calleeAfter,
		branchMeanings: tables.branchMeanings,
		otherBranch: tables.otherBranch,
		sectionNotes: tables.sectionNotes,
		thresholds: tables.thresholds,
		limits: tables.limits,
		whitespace,
		text: {
			more: compile("text.more", tables.text.more, new Set(["hidden", "what"])),
			evidenceTaken: tables.text.evidenceTaken,
			evidenceRow: compile("text.evidenceRow", tables.text.evidenceRow, new Set()),
			nameless: tables.text.nameless,
			refusals: Object.fromEntries(Object.entries(tables.text.refusals).map(([name, template]) => [name, compile(`text.refusals.${name}`, template, REFUSAL_FACTS)])),
		},
		host: hostSays(host),
		recipes: tables.recipes.map((recipe) => compiledRecipe(host, recipe)),
	};
}

// --- each host's notation ----------------------------------------------------------------------

const isScalar = (value: unknown) => value === null || typeof value !== "object";

/** Items packed onto lines no wider than WIDTH, each line indented by `indent`. */
function wrapped(items: string[], indent: string): string {
	const lines: string[] = [];
	let line = indent;
	for (const item of items) {
		if (line.length + item.length + 1 > WIDTH && line.trim() !== "") {
			lines.push(line.trimEnd());
			line = indent;
		}
		line += `${line === indent ? "" : " "}${item}`;
	}
	if (line.trim() !== "") lines.push(line.trimEnd());
	return lines.join("\n");
}

interface Notation {
	scalar(value: null | boolean | number | string): string;
	/** A list or an object on one line; `members` are already written. */
	inline(kind: "list" | "object", members: string[]): string;
	open(kind: "list" | "object"): string;
	close(kind: "list" | "object"): string;
	member(key: string, value: string): string;
	/** What stands between two members on a line and at a line's end. */
	separator: string;
	/** Whether the closing mark stays on the last member's line, as Lisp is written. */
	closeHangs: boolean;
}

/** `value` in a host's notation: on one line where it fits, a list of scalars packed, anything else a member a line. */
function written(notation: Notation, value: unknown, indent: string): string {
	if (isScalar(value)) return notation.scalar(value as null | boolean | number | string);
	const kind = Array.isArray(value) ? "list" : "object";
	const inner = `${indent}  `;
	const members = (at: string) => (Array.isArray(value) ? value.map((member) => written(notation, member, at)) : Object.entries(value as object).map(([key, member]) => notation.member(key, written(notation, member, at))));
	const flat = members(inner);
	const line = notation.inline(kind, flat);
	if (!line.includes("\n") && indent.length + line.length <= WIDTH) return line;
	const sep = notation.separator;
	const body = Array.isArray(value) && value.every(isScalar) ? wrapped(flat.map((member, index) => (index === flat.length - 1 ? member : member + sep)), inner) : flat.map((member) => inner + member).join(`${sep}\n`);
	return `${notation.open(kind)}\n${body}${notation.closeHangs ? "" : `\n${indent}`}${notation.close(kind)}`;
}

const json: Notation = {
	scalar: (value) => JSON.stringify(value),
	inline: (kind, members) => (kind === "list" ? `[${members.join(", ")}]` : members.length === 0 ? "{}" : `{ ${members.join(", ")} }`),
	open: (kind) => (kind === "list" ? "[" : "{"),
	close: (kind) => (kind === "list" ? "]" : "}"),
	member: (key, value) => `${JSON.stringify(key)}: ${value}`,
	separator: ",",
	closeHangs: false,
};

/**
 * Python's literals differ from JSON's in three words (True, False, None) and in nothing else these
 * tables can hold: a JSON string is a Python string literal with the same escapes, once the few
 * characters JSON leaves raw and a Python source file should not hold raw are escaped too.
 */
const pythonString = (text: string) => JSON.stringify(text).replace(/[\u007f-\u009f\u2028\u2029\ufeff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
const python: Notation = {
	...json,
	scalar: (value) => {
		if (value === null) return "None";
		if (typeof value === "boolean") return value ? "True" : "False";
		if (typeof value === "string") return pythonString(value);
		if (!Number.isFinite(value)) return refuse(`${value} has no plain Python literal`);
		return String(value);
	},
	inline: (kind, members) => (kind === "list" ? `[${members.join(", ")}]` : `{${members.join(", ")}}`),
	member: (key, value) => `${pythonString(key)}: ${value}`,
};

const lispString = (text: string) => `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
/** The shapes json.lisp gives decoded JSON, so recipes.lisp reads these tables as it reads rizin's: OBJ for an object, a vector for a list. */
const lisp: Notation = {
	scalar: (value) => {
		if (value === null) return ":null";
		if (typeof value === "boolean") return value ? "t" : "nil";
		if (typeof value === "string") return lispString(value);
		// A number with a fraction is a double there, as one rizin prints is.
		return Number.isInteger(value) ? String(value) : `${value}d0`;
	},
	inline: (kind, members) => `(${[kind === "list" ? "vector" : "obj", ...members].join(" ")})`,
	open: (kind) => (kind === "list" ? "(vector" : "(obj"),
	close: () => ")",
	member: (key, value) => `${lispString(key)} ${value}`,
	separator: "",
	closeHangs: true,
};

// --- the three files ---------------------------------------------------------------------------

const lispFile = `;;;; recipe-data.lisp --- GENERATED from recipes/tables.json. Do not edit.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Regenerate with: bun scripts/gen-recipes.ts
;;;; What the recipes hold as data — the judgement they rest on, their options,
;;;; steps, sections and every sentence — kept once so it can be argued with,
;;;; and so the Lisp verbs and omp's two eval scripts (skills/re-triage/recipes.js
;;;; and recipes.py) say the same thing. recipes.lisp is the code over it;
;;;; scripts/gen-recipes.ts says what each part means.

(in-package #:nodecode-re)

(defparameter *recipe-tables*
  ${written(lisp, hostTables("lisp"), "  ")}
  "The recipes' data, in the shapes decoded JSON has.")
`;

/** `value` as a JavaScript literal with nothing spent on layout: a key that is a name goes unquoted. */
function jsLiteral(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(jsLiteral).join(",")}]`;
	if (isScalar(value)) return JSON.stringify(value);
	return `{${Object.entries(value as object)
		.map(([key, member]) => `${/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : JSON.stringify(key)}:${jsLiteral(member)}`)
		.join(",")}}`;
}

// One table a line, and one recipe, written small: omp's read() cuts what it returns at 50 KB, and a skill's script should come back whole.
const jsLines = Object.entries(hostTables("js")).map(([key, value]) =>
	key === "recipes" ? `  recipes: [\n${(value as unknown[]).map((recipe) => `    ${jsLiteral(recipe)}`).join(",\n")}\n  ]` : `  ${key}: ${jsLiteral(value)}`,
);
const jsBlock = `// ${MARK_BEGIN}\nconst TABLES = {\n${jsLines.join(",\n")}\n};\n// ${MARK_END}`;

/** A recipe as Python calls it: the signature is Python's own, so a stray argument is refused in Python's words. */
function pythonFunction(recipe: Recipe): string {
	const options = recipe.options.map((option) => `${optionKey("py", option)}=None`);
	const parameters = [...(recipe.takes ? [`${ADDRESS}=None`] : []), "*", ...options].join(", ");
	const given = recipe.options.map((option) => `${pythonString(option.name)}: ${optionKey("py", option)}`).join(", ");
	return [`        def ${recipe.name}(${parameters}):`, `            return run_recipe(${pythonString(recipe.name)}, ${recipe.takes ? ADDRESS : "None"}, {${given}})`].join("\n");
}

// The tables are locals of the function recipes.py builds its namespace in, hence the indentation; the marker lines are comments and need none.
const pyBlock = [
	`# ${MARK_BEGIN}`,
	`    TABLES = ${written(python, hostTables("py"), "    ")}`,
	"",
	"    def recipe_functions(run_recipe):",
	...tables.recipes.map((recipe) => `${pythonFunction(recipe)}\n`),
	`        return [${tables.recipes.map((recipe) => recipe.name).join(", ")}]`,
	`# ${MARK_END}`,
].join("\n");

function withBlock(file: string, source: string, begin: string, end: string, block: string): string {
	const from = source.indexOf(begin);
	const to = source.indexOf(end);
	if (from === -1 || to === -1 || to < from) refuse(`${file} has no generated-tables block (expected the two marker lines)`);
	return `${source.slice(0, from)}${block}${source.slice(to + end.length)}`;
}

const check = process.argv.includes("--check");
const stale: string[] = [];
if (!existsSync(LISP) || readFileSync(LISP, "utf8") !== lispFile) {
	if (check) stale.push("nodecode/recipe-data.lisp");
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
	console.error(`stale: ${stale.join(", ")} — run \`bun scripts/gen-recipes.ts\``);
	process.exit(1);
}
if (!check) console.log("recipe tables written");
