/**
 * The cell compiler behind the `run` tool (tools-run.ts).
 *
 * A cell is TypeScript or JavaScript the model sends. It runs in one
 * long-lived namespace per omp session (namespace.ts), so what it declares at
 * the top level must outlive the call: `compileCell` rewrites every top-level
 * declaration into an assignment on the namespace's global object and wraps
 * the cell in an async function, so `await` works at the top level and the
 * last expression becomes the call's value.
 *
 *   const x = 1;               -> __ompre_g["x"] = (1);
 *   let { a, b } = obj;        -> (a, b pre-declared on the global) ({ a, b } = obj);
 *   class Foo {}               -> __ompre_g["Foo"] = class Foo {};
 *   function f() {}            -> hoisted: __ompre_g["f"] = function f() {};
 *   import fs from "node:fs";  -> { const m = await import("node:fs"); __ompre_g["fs"] = m.default; }
 *   expr  (last statement)     -> return (expr);
 *
 * Nothing stays a local of the wrapper, so a helper defined in one call reads
 * every other name late, from the namespace: redefining `parse` in a later
 * call is seen by an `analyze` defined earlier, the same as after a restart.
 *
 * The compiler also picks out the cell's *definitions* — top-level function
 * and class declarations, and `const` bindings whose initializer is static
 * (literals, functions, classes, and plain data built from them) — one unit
 * per bound name. Those are what kept.ts persists. A statement that does work
 * (a call, an `await`, anything else) is never a definition, so a restart
 * rebuilds the model's helpers without replaying its analysis.
 *
 * Parsing uses the Babel parser omp itself ships for its JS eval (an omp
 * plugin can only resolve the host's packages); TypeScript syntax is stripped
 * with Bun's transpiler, the same one omp uses.
 */

/** A Babel AST node, typed only as far as this module reads it. */
interface Node {
	type: string;
	start: number;
	end: number;
	[key: string]: unknown;
}

interface Program {
	program: { body: Node[] };
}

interface BabelParser {
	parse(code: string, options: Record<string, unknown>): Program;
}

/** A top-level definition a cell made: what kept.ts persists, one unit per name. */
export interface Definition {
	name: string;
	kind: "function" | "class" | "const";
	/** The definition's own source text (TypeScript kept), with its leading comment. */
	source: string;
}

export interface CompiledCell {
	/** `(async (__ompre_g, __ompre_import) => { … })`: evaluate it in the namespace, then call it with the namespace global and an import function. */
	source: string;
	definitions: Definition[];
}

/** The parameter names the wrapper binds. A cell that declares one of these at the top level shadows the rewrite, so it is refused. */
const GLOBAL_PARAM = "__ompre_g";
const IMPORT_PARAM = "__ompre_import";

let parserPromise: Promise<BabelParser> | null = null;

/** omp's own Babel parser, loaded on first use (the host resolves `@babel/parser`; this plugin cannot). */
function babel(): Promise<BabelParser> {
	if (!parserPromise) {
		parserPromise = import("@oh-my-pi/pi-coding-agent/eval/js/shared/rewrite-imports")
			.then((mod) => mod.loadBabelParser() as unknown as Promise<BabelParser>)
			.catch((err) => {
				parserPromise = null;
				throw new Error(`omp-re: run: could not load omp's JavaScript parser (${err instanceof Error ? err.message : String(err)}); this omp build may be incompatible`);
			});
	}
	return parserPromise;
}

const PARSE_OPTIONS = {
	sourceType: "module",
	allowAwaitOutsideFunction: true,
	allowReturnOutsideFunction: true,
	allowImportExportEverywhere: false,
};

/** Babel's error as a SyntaxError that points at the cell's line, with a caret under the column. */
function syntaxError(code: string, err: unknown): SyntaxError {
	const e = err as { message?: string; loc?: { line: number; column: number } };
	const message = (e.message ?? String(err)).replace(/\s*\(\d+:\d+\)$/, "");
	if (!e.loc) return new SyntaxError(message);
	const line = code.split("\n")[e.loc.line - 1] ?? "";
	return new SyntaxError(`${message} (line ${e.loc.line}, column ${e.loc.column + 1})\n  ${line}\n  ${" ".repeat(e.loc.column)}^`);
}

async function parse(code: string, typescript: boolean): Promise<Program> {
	const { parse } = await babel();
	try {
		return parse(code, { ...PARSE_OPTIONS, plugins: typescript ? ["typescript"] : [] });
	} catch (err) {
		throw syntaxError(code, err);
	}
}

// Dead-code elimination, tree shaking, and inlining all off: an unused top-level helper is the whole point of a cell, never dead code.
const TRANSPILER = new Bun.Transpiler({ loader: "ts", deadCodeElimination: false, treeShaking: false, inline: false, trimUnusedImports: false } as ConstructorParameters<typeof Bun.Transpiler>[0]);

function stripTypes(code: string): string {
	try {
		return TRANSPILER.transformSync(code);
	} catch (err) {
		throw new SyntaxError(`omp-re: run: ${err instanceof Error ? err.message : String(err)}`);
	}
}

function nodes(value: unknown): Node[] {
	return Array.isArray(value) ? (value.filter((v) => v && typeof v === "object") as Node[]) : [];
}

function child(node: Node, key: string): Node | null {
	const value = node[key];
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Node) : null;
}

function identName(node: Node | null): string | undefined {
	return node?.type === "Identifier" && typeof node.name === "string" ? node.name : undefined;
}

/** Every name a binding pattern binds (`{ a, b: [c, ...d] = x }` → a, c, d). */
function bindingNames(pattern: Node | null, out: string[] = []): string[] {
	if (!pattern) return out;
	switch (pattern.type) {
		case "Identifier":
			out.push(pattern.name as string);
			break;
		case "ObjectPattern":
			for (const prop of nodes(pattern.properties)) bindingNames(prop.type === "RestElement" ? child(prop, "argument") : child(prop, "value"), out);
			break;
		case "ArrayPattern":
			for (const el of nodes(pattern.elements)) bindingNames(el, out);
			break;
		case "AssignmentPattern":
			bindingNames(child(pattern, "left"), out);
			break;
		case "RestElement":
			bindingNames(child(pattern, "argument"), out);
			break;
	}
	return out;
}

/** The names a top-level statement binds, for the reserved-name check. */
function topLevelNames(node: Node): string[] {
	switch (node.type) {
		case "FunctionDeclaration":
		case "ClassDeclaration": {
			const name = identName(child(node, "id"));
			return name ? [name] : [];
		}
		case "VariableDeclaration":
			return nodes(node.declarations).flatMap((d) => bindingNames(child(d, "id")));
		case "ImportDeclaration":
			return nodes(node.specifiers).map((s) => identName(child(s, "local"))).filter((n): n is string => n !== undefined);
		default:
			return [];
	}
}

const PURE_CONSTRUCTORS = new Set(["Set", "Map", "RegExp", "WeakSet", "WeakMap"]);
const PURE_CALLS = new Set(["Symbol", "BigInt", "Object.freeze", "String.raw"]);

function calleeName(node: Node | null): string | undefined {
	if (!node) return undefined;
	if (node.type === "Identifier") return node.name as string;
	if (node.type === "MemberExpression" && !node.computed) {
		const object = calleeName(child(node, "object"));
		const property = identName(child(node, "property"));
		return object && property ? `${object}.${property}` : undefined;
	}
	return undefined;
}

/**
 * Whether evaluating `node` does no work: literals, functions and classes, and
 * plain data built from them (objects, arrays, arithmetic, references to other
 * names, a few pure builtins like `new Set([...])`). Calls, `await`, `new` of
 * anything else, assignments, and templates with live expressions are work.
 * Only a `const` with such an initializer is a definition; replaying it on a
 * restart can do nothing but define it again.
 */
export function isStaticInit(node: Node | null): boolean {
	if (!node) return false;
	switch (node.type) {
		case "StringLiteral":
		case "NumericLiteral":
		case "BooleanLiteral":
		case "NullLiteral":
		case "BigIntLiteral":
		case "RegExpLiteral":
		case "Identifier":
		case "ArrowFunctionExpression":
		case "FunctionExpression":
		case "ClassExpression":
			return true;
		case "TemplateLiteral":
			return nodes(node.expressions).every(isStaticInit);
		case "TaggedTemplateExpression":
			return calleeName(child(node, "tag")) === "String.raw" && isStaticInit(child(node, "quasi"));
		case "ParenthesizedExpression":
		case "TSAsExpression":
		case "TSSatisfiesExpression":
		case "TSNonNullExpression":
		case "TSTypeAssertion":
			return isStaticInit(child(node, "expression"));
		case "UnaryExpression":
			return node.operator !== "delete" && isStaticInit(child(node, "argument"));
		case "BinaryExpression":
		case "LogicalExpression":
			return isStaticInit(child(node, "left")) && isStaticInit(child(node, "right"));
		case "ConditionalExpression":
			return isStaticInit(child(node, "test")) && isStaticInit(child(node, "consequent")) && isStaticInit(child(node, "alternate"));
		case "MemberExpression":
			return isStaticInit(child(node, "object")) && (!node.computed || isStaticInit(child(node, "property")));
		case "ArrayExpression":
			return nodes(node.elements).every((el) => (el.type === "SpreadElement" ? isStaticInit(child(el, "argument")) : isStaticInit(el)));
		case "ObjectExpression":
			return nodes(node.properties).every((prop) => {
				if (prop.type === "ObjectMethod") return !prop.computed || isStaticInit(child(prop, "key"));
				if (prop.type === "SpreadElement") return isStaticInit(child(prop, "argument"));
				return (!prop.computed || isStaticInit(child(prop, "key"))) && isStaticInit(child(prop, "value"));
			});
		case "NewExpression":
			return PURE_CONSTRUCTORS.has(calleeName(child(node, "callee")) ?? "") && nodes(node.arguments).every(isStaticInit);
		case "CallExpression":
			return PURE_CALLS.has(calleeName(child(node, "callee")) ?? "") && nodes(node.arguments).every(isStaticInit);
		default:
			return false;
	}
}

/** Where the node's source starts once the comment block directly above it is included, so a helper's doc comment is kept with it. */
function commentStart(node: Node): number {
	const first = nodes(node.leadingComments)[0];
	return first ? Math.min(first.start, node.start) : node.start;
}

/** The definitions among top-level statements of the ORIGINAL (TypeScript) source, later ones winning by name. */
function findDefinitions(code: string, body: readonly Node[]): Definition[] {
	const byName = new Map<string, Definition>();
	for (const node of body) {
		if (node.declare === true) continue;
		if (node.type === "FunctionDeclaration" || node.type === "ClassDeclaration") {
			const name = identName(child(node, "id"));
			if (!name) continue;
			byName.delete(name);
			byName.set(name, { name, kind: node.type === "FunctionDeclaration" ? "function" : "class", source: code.slice(commentStart(node), node.end) });
		} else if (node.type === "VariableDeclaration" && node.kind === "const") {
			const declarators = nodes(node.declarations);
			for (const d of declarators) {
				const name = identName(child(d, "id"));
				if (!name || !isStaticInit(child(d, "init"))) continue;
				const comment = declarators.length === 1 ? code.slice(commentStart(node), node.start) : "";
				byName.delete(name);
				byName.set(name, { name, kind: "const", source: `${comment}const ${code.slice(d.start, d.end)};` });
			}
		}
	}
	return [...byName.values()];
}

/** Keep a replaced span's line breaks, so line numbers after it still match the cell. */
function blankLines(text: string): string {
	return text.replace(/[^\n]/g, "");
}

function ensureGlobal(name: string): string {
	return `if (!(${JSON.stringify(name)} in ${GLOBAL_PARAM})) ${GLOBAL_PARAM}[${JSON.stringify(name)}] = undefined;`;
}

function globalRef(name: string): string {
	return `${GLOBAL_PARAM}[${JSON.stringify(name)}]`;
}

function rewriteImport(js: string, node: Node): string {
	const source = JSON.stringify((child(node, "source")?.value as string) ?? "");
	const specifiers = nodes(node.specifiers);
	if (specifiers.length === 0) return `await ${IMPORT_PARAM}(${source});`;
	const assigns = specifiers.map((s) => {
		const local = identName(child(s, "local"))!;
		if (s.type === "ImportDefaultSpecifier") return `${globalRef(local)} = __ompre_m.default;`;
		if (s.type === "ImportNamespaceSpecifier") return `${globalRef(local)} = __ompre_m;`;
		const imported = child(s, "imported");
		const key = identName(imported) ?? (imported?.value as string);
		return `${globalRef(local)} = __ompre_m[${JSON.stringify(key)}];`;
	});
	return `{ const __ompre_m = await ${IMPORT_PARAM}(${source}); ${assigns.join(" ")} }${blankLines(js.slice(node.start, node.end))}`;
}

function rewriteVariables(js: string, node: Node): string {
	const parts: string[] = [];
	for (const d of nodes(node.declarations)) {
		const id = child(d, "id");
		const init = child(d, "init");
		const name = identName(id);
		if (name) {
			if (init) parts.push(`${globalRef(name)} = (${js.slice(init.start, init.end)});`);
			else if (node.kind === "var") parts.push(ensureGlobal(name));
			else parts.push(`${globalRef(name)} = undefined;`);
		} else if (id && init) {
			parts.push(...bindingNames(id).map(ensureGlobal), `(${js.slice(id.start, id.end)} = ${js.slice(init.start, init.end)});`);
		}
	}
	// The declarator texts carry their own line breaks; anything between them (commas, comments) does not matter.
	const kept = parts.join(" ");
	const missing = blankLines(js.slice(node.start, node.end)).length - blankLines(kept).length;
	return kept + "\n".repeat(Math.max(0, missing));
}

/**
 * Compile one cell. Throws a SyntaxError (with the line and a caret) for code
 * that does not parse, for module syntax a cell has no use for (`export`), and
 * for a top-level declaration of a name in `vocabulary` (the namespace's own
 * read-only names: `re`, `describe`, …).
 */
export async function compileCell(code: string, vocabulary: ReadonlySet<string> = new Set()): Promise<CompiledCell> {
	const original = await parse(code, true);
	for (const node of original.program.body) {
		if (node.type.startsWith("Export")) {
			throw new SyntaxError("omp-re: run: `export` is not needed — top-level declarations persist in the namespace on their own");
		}
		for (const name of topLevelNames(node)) {
			if (name === GLOBAL_PARAM || name === IMPORT_PARAM || name === "__ompre_m") throw new SyntaxError(`omp-re: run: ${name} is reserved by the run tool`);
			if (vocabulary.has(name)) throw new SyntaxError(`omp-re: run: \`${name}\` is part of the namespace (see man()) and cannot be redeclared — pick another name`);
		}
	}
	const definitions = findDefinitions(code, original.program.body);

	const js = stripTypes(code);
	const body = (await parse(js, false)).program.body;
	const prologue: string[] = [];
	const edits: { start: number; end: number; text: string }[] = [];

	let last = body.length - 1;
	while (last >= 0 && body[last]!.type === "EmptyStatement") last--;

	body.forEach((node, index) => {
		const text = js.slice(node.start, node.end);
		switch (node.type) {
			case "FunctionDeclaration": {
				const name = identName(child(node, "id"));
				if (!name) return;
				// Hoisted, like a declaration: callable from anywhere in the cell, published before any statement runs.
				prologue.push(`${globalRef(name)} = ${text};`);
				edits.push({ start: node.start, end: node.end, text: blankLines(text) });
				return;
			}
			case "ClassDeclaration": {
				const name = identName(child(node, "id"));
				if (name) edits.push({ start: node.start, end: node.end, text: `${globalRef(name)} = ${text};` });
				return;
			}
			case "VariableDeclaration":
				edits.push({ start: node.start, end: node.end, text: rewriteVariables(js, node) });
				return;
			case "ImportDeclaration":
				edits.push({ start: node.start, end: node.end, text: rewriteImport(js, node) });
				return;
			case "ExpressionStatement": {
				if (index !== last) return;
				const expression = child(node, "expression")!;
				edits.push({ start: node.start, end: node.end, text: `return (${js.slice(expression.start, expression.end)});` });
				return;
			}
		}
	});

	let rewritten = js;
	for (const edit of edits.sort((a, b) => b.start - a.start)) {
		rewritten = rewritten.slice(0, edit.start) + edit.text + rewritten.slice(edit.end);
	}
	return {
		// Strict, like a module: assigning to a namespace name that is read-only (`re`, `describe`, …) throws instead of silently doing nothing.
		source: `(async (${GLOBAL_PARAM}, ${IMPORT_PARAM}) => {"use strict"; ${prologue.join(" ")}\n${rewritten}\n})`,
		definitions,
	};
}

/**
 * Validate a persisted unit before it is loaded: it must be exactly one
 * top-level statement defining exactly `name`, by the same rule that saved it.
 * Anything else (a file edited into doing work, a name that no longer
 * matches) is refused rather than run.
 */
export async function checkUnit(name: string, source: string): Promise<Definition> {
	const { program } = await parse(source, true);
	const statements = program.body.filter((node) => node.type !== "EmptyStatement");
	const definitions = findDefinitions(source, statements);
	if (statements.length !== 1 || definitions.length !== 1 || definitions[0]!.name !== name) {
		throw new Error(`not a single definition of ${name}`);
	}
	return definitions[0]!;
}
