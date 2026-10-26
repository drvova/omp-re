/**
 * Discovery for the `run` namespace: `describe(x)` and the manual.
 *
 * Signatures come from introspection, never a hand-kept list. A capability's
 * comes from its own parameter schema (JSON Schema, as omp's builder emits
 * it) plus the first sentence of its description; a plain function's from its
 * source text, with the leading doc comment when it is a kept definition; an
 * object's from walking its members. Host objects whose methods are compiled
 * (RzSession) carry a one-line doc each in {@link MEMBER_DOCS}.
 */

export interface JsonSchema {
	type?: string;
	description?: string;
	properties?: Record<string, JsonSchema>;
	required?: string[];
	items?: JsonSchema;
	enum?: unknown[];
	const?: unknown;
	anyOf?: JsonSchema[];
	oneOf?: JsonSchema[];
	additionalProperties?: JsonSchema | boolean;
}

/** What describe() needs to know about one callable operation: a `re` capability, or an MCP server's tool. Plain data, so it crosses to the namespace worker. */
export interface CapabilityInfo {
	name: string;
	/** The full description, as the tool presents itself. */
	description: string;
	/** omp's approval tier the definition declares; descriptive only — the `run` call is what omp approves. */
	tier: "read" | "write" | "exec";
	/** Whether a successful call becomes a `re.evidence` record (evidence.ts). */
	evidence: boolean;
	/** JSON Schema of the parameters, for signatures and validation messages. */
	schema: JsonSchema;
}

/** The parameter a bare (non-object) argument fills: the only required one, or the only one there is. */
export function shorthandParam(cap: CapabilityInfo): string | undefined {
	const required = cap.schema.required ?? [];
	if (required.length === 1) return required[0];
	const props = Object.keys(cap.schema.properties ?? {});
	return required.length === 0 && props.length === 1 ? props[0] : undefined;
}

/** Operation metadata attached to each `re.<name>` (and MCP tool) method, with the object it hangs off, so describe() can tell one from a plain function. */
export const CAPABILITY = new WeakMap<object, { cap: CapabilityInfo; owner: string }>();

/** Objects that describe themselves (`re`, a connected MCP server): describe(x) returns what the describer says. */
export const DESCRIBERS = new WeakMap<object, () => string>();

/** Docs for members whose source says nothing useful (compiled or host-bound): `<Owner>.<member>` → [signature, one line]. */
export const MEMBER_DOCS: Record<string, [string, string]> = {
	"re.rz": ["rz(): Promise<RzSession>", "This session's rizin process (respawned if it died). Raw and unrecorded: nothing it returns is evidence, and it can change the analysis. Use re.rizin_command for citable output."],
	"re.binary": ["binary: { path, sha256 } | null", "The binary open in this session."],
	"re.evidence": ["evidence(): EvidenceRecord[]", "Evidence recorded on this branch, oldest first: { id, tool, args, ea, summary, … }."],
	"re.findings": ["findings(): FindingRecord[]", "Live findings on this branch: { id, claim, evidenceIds, confidence, … }."],
	"RzSession.cmd": ["cmd(command: string): Promise<string>", "Run one rizin command and return its output."],
	"RzSession.cmdj": ["cmdj<T>(command: string): Promise<T | null>", "Run a JSON command (`aflj`, `pdfj`, …) and parse it; null for empty or non-JSON output."],
	"RzSession.cmdWithStderr": ["cmdWithStderr(command: string): Promise<{ output, stderr }>", "Run a command and also return what rizin wrote to stderr while it ran."],
	"RzSession.close": ["close(): Promise<void>", "Kill this rizin process (the next re.* call respawns it and replays annotations)."],
	"RzSession.binaryPath": ["binaryPath: string", "The file this process opened."],
	"mcp.servers": ["servers(): Promise<Record<string, { type, target, enabled }>>", "The MCP servers configured for omp in this project and for the user."],
	"mcp.connect": ["connect(server: string | { command, args?, env?, cwd? } | { url, headers? }): Promise<McpServer>", "Connect to a configured server by name, or to one described inline; its tools become async methods."],
};

function firstSentence(text: string): string {
	const flat = text.replace(/\s+/g, " ").trim();
	// A sentence ends before a capital letter or at the end, so "e.g. `int f(int)`" does not cut it short.
	const end = flat.search(/[.!?](?=\s+[A-Z]|$)/);
	return end === -1 ? flat : flat.slice(0, end + 1);
}

/** A JSON Schema as a TypeScript-ish type: `"a" | "b"`, `string[]`, `{ x: number, y?: string }`. */
export function schemaType(schema: JsonSchema | undefined): string {
	if (!schema) return "unknown";
	if (schema.enum) return schema.enum.map((v) => JSON.stringify(v)).join(" | ");
	if (schema.const !== undefined) return JSON.stringify(schema.const);
	const variants = schema.anyOf ?? schema.oneOf;
	if (variants) return variants.map(schemaType).join(" | ");
	switch (schema.type) {
		case "integer":
			return "number";
		case "array": {
			const item = schemaType(schema.items);
			return item.includes(" ") && !item.startsWith("{") ? `(${item})[]` : `${item}[]`;
		}
		case "object": {
			if (schema.properties) return objectType(schema);
			if (schema.additionalProperties && typeof schema.additionalProperties === "object") return `Record<string, ${schemaType(schema.additionalProperties)}>`;
			return "object";
		}
		default:
			return schema.type ?? "unknown";
	}
}

function objectType(schema: JsonSchema): string {
	const required = new Set(schema.required ?? []);
	const props = Object.entries(schema.properties ?? {}).map(([key, value]) => `${key}${required.has(key) ? "" : "?"}: ${schemaType(value)}`);
	return props.length === 0 ? "{}" : `{ ${props.join(", ")} }`;
}

/** `name({ a: string, b?: number })`, `name(params?: { … })` when nothing is required, `name()` with no params. */
export function capabilitySignature(cap: CapabilityInfo): string {
	const props = Object.keys(cap.schema.properties ?? {});
	if (props.length === 0) return `${cap.name}()`;
	const optional = (cap.schema.required ?? []).length === 0;
	return `${cap.name}(${optional ? "params?: " : ""}${objectType(cap.schema)})`;
}

/** The full page for one operation: signature, tier, description, and every parameter's own doc. `owner` is what it hangs off (`re`, an MCP server's name). */
export function describeCapability(cap: CapabilityInfo, owner = "re"): string {
	const head =
		owner === "re"
			? [`re.${capabilitySignature(cap)} → Promise<string>`, `tier: ${cap.tier}${cap.evidence ? " · recorded as evidence (the result ends with its [evidence xxxxxxxx] id)" : ""}`]
			: [`${owner}.${capabilitySignature(cap)} → Promise<unknown>`, "MCP tool: returns the server's structured content when it sends some, else its text; an error result rejects."];
	const lines = [...head, "", cap.description.trim()];
	const props = Object.entries(cap.schema.properties ?? {});
	if (props.length > 0) {
		const required = new Set(cap.schema.required ?? []);
		lines.push("", "params:");
		for (const [key, value] of props) {
			lines.push(`  ${key}${required.has(key) ? "" : "?"}: ${schemaType(value)}${value.description ? ` — ${value.description.replace(/\s+/g, " ").trim()}` : ""}`);
		}
	}
	const only = shorthandParam(cap);
	if (only) lines.push("", `Shorthand: ${owner}.${cap.name}(${only}) passes just that parameter.`);
	return lines.join("\n");
}

const GROUPS: { title: string; match: (cap: CapabilityInfo) => boolean }[] = [
	{ title: "observe — recorded as evidence; cite the [evidence xxxxxxxx] id in re.record_finding", match: (cap) => cap.evidence },
	{ title: "findings — the conclusions /re report includes", match: (cap) => /finding/.test(cap.name) },
	{ title: "annotate — written to rizin, verified, recorded, undoable with /re undo", match: (cap) => cap.tier === "write" },
	{ title: "act — session setup, analysis passes, triage, emulation, external tools", match: () => true },
];

/** describe(re): every live capability, grouped, one line each, then the workspace's other members. */
export function describeWorkspace(caps: readonly CapabilityInfo[], binary: { path: string; sha256: string | null } | null): string {
	const lines = [
		`re — the reverse-engineering workspace bound to this session (${binary ? `binary: ${binary.path}` : "no binary open: await re.open_binary({ path })"}).`,
		"Every capability is an async method taking one params object, e.g. await re.list_functions({ sort: \"size\", limit: 5 }); describe(re.<name>) shows its parameters.",
	];
	const remaining = new Set(caps);
	for (const group of GROUPS) {
		const members = [...remaining].filter(group.match);
		if (members.length === 0) continue;
		lines.push("", group.title);
		for (const cap of members) {
			remaining.delete(cap);
			lines.push(`  ${capabilitySignature(cap)} — ${firstSentence(cap.description)}`);
		}
	}
	lines.push("", "members");
	for (const key of ["re.rz", "re.binary", "re.evidence", "re.findings"]) {
		const [signature, doc] = MEMBER_DOCS[key]!;
		lines.push(`  ${signature} — ${doc}`);
	}
	return lines.join("\n");
}

/** describe(server) for a connected MCP server: its tools, one line each. */
export function describeMcpServer(name: string, tools: readonly CapabilityInfo[], instructions?: string): string {
	const lines = [`${name} — a connected MCP server; each tool is an async method taking one params object. describe(${name}.<tool>) shows its parameters; close() disconnects.`];
	if (instructions?.trim()) lines.push("", firstSentence(instructions));
	lines.push("", "tools");
	for (const tool of tools) lines.push(`  ${capabilitySignature(tool)}${tool.description ? ` — ${firstSentence(tool.description)}` : ""}`);
	return lines.join("\n");
}

/** A function's signature from its source: `name(a, b = 1)`, `async name(x)`, `(x) => …`. */
export function functionSignature(fn: Function): string {
	const source = Function.prototype.toString.call(fn);
	const header = source.match(/^\s*(async\s+)?(?:function\s*\*?\s*[\w$]*\s*)?(\([^)]*\)|[\w$]+)\s*(?:=>|\{)/);
	if (header) {
		const params = header[2]!.startsWith("(") ? header[2]! : `(${header[2]})`;
		return `${header[1] ?? ""}${fn.name || "anonymous"}${params.replace(/\s+/g, " ")}`;
	}
	const method = source.match(/^\s*(async\s+)?(?:get\s+|set\s+|static\s+)?[\w$]+\s*(\([^)]*\))/);
	if (method) return `${method[1] ?? ""}${fn.name}${method[2]!.replace(/\s+/g, " ")}`;
	return `${fn.name || "anonymous"}(${Array.from({ length: fn.length }, (_, i) => `arg${i}`).join(", ")})`;
}

/** The doc comment at the head of a kept definition's source, flattened to its first sentence. */
export function leadingDoc(source: string): string | undefined {
	const block = source.match(/^\s*\/\*\*([\s\S]*?)\*\//);
	const lines = block ? block[1]!.split("\n").map((line) => line.replace(/^\s*\*\s?/, "")) : source.match(/^(\s*\/\/.*\n)+/)?.[0].split("\n").map((line) => line.replace(/^\s*\/\/\s?/, ""));
	if (!lines) return undefined;
	const text = lines.join(" ").trim();
	return text ? firstSentence(text) : undefined;
}

function ownerName(value: object): string {
	const ctor = (value as { constructor?: { name?: string } }).constructor;
	return ctor?.name && ctor.name !== "Object" ? ctor.name : "object";
}

/** Public members up the prototype chain, stopping at the realm's Object.prototype (cells run in their own realm, so compare by shape, not identity). */
function memberNames(value: object): string[] {
	const names = new Set<string>();
	for (let proto: object | null = value; proto && Object.getPrototypeOf(proto) !== null; proto = Object.getPrototypeOf(proto)) {
		for (const key of Object.getOwnPropertyNames(proto)) {
			if (key !== "constructor" && !key.startsWith("_") && !key.startsWith("#")) names.add(key);
		}
	}
	return [...names];
}

function memberLine(owner: string, value: object, key: string): string {
	const doc = MEMBER_DOCS[`${owner}.${key}`];
	if (doc) return `  ${doc[0]} — ${doc[1]}`;
	let member: unknown;
	try {
		member = (value as Record<string, unknown>)[key];
	} catch (err) {
		return `  ${key}: (getter threw: ${err instanceof Error ? err.message : String(err)})`;
	}
	if (typeof member === "function") return `  ${functionSignature(member)}`;
	const preview = typeof member === "string" ? JSON.stringify(member.length > 60 ? `${member.slice(0, 57)}...` : member) : member === null || typeof member !== "object" ? String(member) : ownerName(member);
	return `  ${key}: ${member === null ? "null" : typeof member} = ${preview}`;
}

/**
 * describe(x) for anything other than `re` itself: a capability method's full
 * page, a function's signature and doc, an object's public members, or a
 * primitive's type and value. `docFor` looks up a kept definition's doc by name.
 */
export function describeValue(value: unknown, docFor: (name: string) => string | undefined): string {
	if (value === null || value === undefined) return String(value);
	if (typeof value === "object" || typeof value === "function") {
		const describer = DESCRIBERS.get(value);
		if (describer) return describer();
	}
	if (typeof value === "function") {
		const attached = CAPABILITY.get(value);
		if (attached) return describeCapability(attached.cap, attached.owner);
		const doc = value.name ? docFor(value.name) : undefined;
		// Own members only: a function's prototype chain is Function.prototype, which says nothing about it.
		const own = Object.getOwnPropertyNames(value).filter((key) => !["length", "name", "prototype", "arguments", "caller"].includes(key) && !key.startsWith("_"));
		const lines = [functionSignature(value), ...(doc ? [doc] : [])];
		if (/^class[\s{]/.test(Function.prototype.toString.call(value))) {
			lines.push("instance members:", ...memberNames(value.prototype as object).map((key) => memberLine(value.name, value.prototype as object, key)));
		} else if (own.length > 0) {
			lines.push("members:", ...own.map((key) => memberLine(value.name, value, key)));
		}
		return lines.join("\n");
	}
	if (typeof value !== "object") return `${typeof value}: ${typeof value === "string" ? JSON.stringify(value) : String(value)}`;
	const owner = ownerName(value);
	const keys = memberNames(value);
	if (Array.isArray(value)) return `array of ${value.length}${value.length > 0 ? `; first item:\n${describeValue(value[0], docFor)}` : ""}`;
	return [`${owner} with ${keys.length} member${keys.length === 1 ? "" : "s"}:`, ...keys.map((key) => memberLine(owner, value, key))].join("\n");
}

export interface ManualState {
	toolName: string;
	binary: { path: string; sha256: string | null } | null;
	capabilityCount: number;
	keptDir: string;
	kept: string[];
	keptFailures: { name: string; error: string }[];
}

/** The manual: what `run` with empty code returns and `man()` prints. */
export function manual(state: ManualState): string {
	return [
		`omp-re ${state.toolName} — one tool that runs TypeScript/JavaScript in this session's persistent namespace.`,
		"",
		"SECURITY: the code runs inside omp with omp's full authority — files, processes, network. That is what this tool is; there is no restricted mode. Run omp sandboxed (a container or VM) when you analyse anything untrusted.",
		"",
		"Namespace",
		"  re                     the RE workspace for this session; every capability is `await re.<name>({ ...params })`",
		"  describe(x)            live capabilities and signatures: describe(re), describe(re.decompile_function), describe(anyValue)",
		"  man()                  this manual",
		"  kept(name?)            definitions persisted across restarts, or one's source",
		"  forget(name)           delete a kept definition (and drop it from the namespace)",
		`  strings                named literal strings passed in this call's \`strings\` argument (no escaping inside code)`,
		"  print(...), console.*  output returned to you",
		"  exec(bin, argv)        run a program (argv, no shell) → { code, stdout, stderr }",
		"  mcp                    MCP servers as functions: await mcp.servers(); const s = await mcp.connect(\"name\"); await s.<tool>({ ... })",
		"  require(id), import    Node modules; timers, Buffer, TextEncoder/TextDecoder, URL, fetch",
		"",
		"Semantics",
		"  - Top-level declarations persist across calls in this session; `await` works at the top level.",
		`  - Top-level functions, classes, and consts with static values are also saved to ${state.keptDir} and reloaded in every new session. Statements that do work are never replayed.`,
		"  - The last expression is the call's value: strings verbatim, other values as JSON.",
		"  - Evidence-tier results end with [evidence xxxxxxxx]; each call's result also lists the evidence it recorded. Cite those ids in re.record_finding — that is how a conclusion reaches /re report.",
		"  - One call runs at a time per session. re.*, exec, and mcp work only while a call is running: await what you start.",
		"  - Cancelling a call stops it at once — even a loop that never awaits — and resets the namespace: kept definitions reload on the next call, other variables are gone. An exception thrown later from a timer is printed, not fatal.",
		"",
		"State",
		`  binary: ${state.binary ? `${state.binary.path}${state.binary.sha256 ? ` (sha256 ${state.binary.sha256.slice(0, 16)}…)` : ""}` : "none — await re.open_binary({ path })"}`,
		`  capabilities: ${state.capabilityCount} live (describe(re) lists them)`,
		`  kept: ${state.kept.length > 0 ? state.kept.join(", ") : "none yet"}`,
		...(state.keptFailures.length > 0 ? [`  not loaded: ${state.keptFailures.map((f) => `${f.name} (${f.error})`).join("; ")}`] : []),
		"",
		"Start",
		'  await re.open_binary({ path: "/path/to/binary" })',
		"  describe(re)",
	].join("\n");
}
