/**
 * The namespace vocabulary for omp-re's omp-native surface.
 *
 * omp-re adds no top-level tools: every RE capability is registered
 * `discoverable`, so omp mounts it as an `xd://<name>` device and the model
 * drives it from omp's own `eval` tool as `await tool.<name>({ ...params })`.
 * omp's `eval` is the single code host — the model composes, loops, and keeps
 * its own helper definitions there across calls; omp owns that namespace, not
 * this extension (the ExtensionAPI exposes no eval-prelude/namespace seam).
 *
 * What this module adds is the two pieces of in-namespace vocabulary a code
 * host wants and omp can't seed for us: a `re_manual` (the entry manual — what
 * the namespace provides, how to open a binary, what omp-re offers) and a
 * `re_describe` (live capability introspection — every callable `tool.<name>`
 * with its signature and one-line doc, or the full parameters of one). Both are
 * pure metadata: they spawn no rizin, need no open binary, record no evidence,
 * and are not gated by `/re off` (they stay readable when the tools are off), so
 * they are deliberately kept out of the RE_*_TOOL_NAMES registries.
 *
 * The rendering is split into pure functions (no host, unit-tested) with the
 * tool wrappers calling `pi.getAllTools()` and handing the result to them.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import {
	RE_ALL_TOOL_NAMES,
	RE_ANALYZE_TOOL_NAMES,
	RE_DEBUG_TOOL_NAMES,
	RE_EMULATE_TOOL_NAMES,
	RE_FINDING_TOOL_NAMES,
	RE_MUTATE_TOOL_NAMES,
	RE_RIZIN_TOOL_NAMES,
	RE_RZCLI_TOOL_NAMES,
	RE_READ_TOOL_NAMES,
	RE_SESSION_TOOL_NAMES,
	RE_SIGNATURE_TOOL_NAMES,
	RE_TRIAGE_TOOL_NAMES,
} from "./audit.ts";
import { plainResult, textResult } from "./format.ts";
import { RE_LOAD_MODE, reRenderers } from "./render.ts";

/** The subset of omp's `ToolInfo` the renderers read. `parameters` is the schema object the tool registered (omptype carries its `.ir`); left `unknown` so the reader narrows defensively. */
export interface ToolMeta {
	name: string;
	description: string;
	parameters?: unknown;
}

/** Capability groups in presentation order, each backed by the same name registry the audit log and `/re off` use, so `re_describe`'s grouping can never drift from the real tiers. */
const GROUPS: readonly { label: string; names: Record<string, true> }[] = [
	{ label: "Session — open/manage the target", names: RE_SESSION_TOOL_NAMES },
	{ label: "Read — observe the binary (recorded as evidence)", names: RE_READ_TOOL_NAMES },
	{ label: "Annotate — rename, type, comment, define", names: RE_MUTATE_TOOL_NAMES },
	{ label: "Signatures — FLIRT match/create", names: RE_SIGNATURE_TOOL_NAMES },
	{ label: "Analysis — extra recovery passes", names: RE_ANALYZE_TOOL_NAMES },
	{ label: "rizin bridge — its own help + any read-only command", names: RE_RIZIN_TOOL_NAMES },
	{ label: "rz-* CLI — the standalone rizin tools", names: RE_RZCLI_TOOL_NAMES },
	{ label: "Triage — external tools (present only when installed)", names: RE_TRIAGE_TOOL_NAMES },
	{ label: "Debugger — dynamic analysis (opt-in; executes the sample)", names: RE_DEBUG_TOOL_NAMES },
	{ label: "Emulator — RzIL interpretation", names: RE_EMULATE_TOOL_NAMES },
	{ label: "Findings — record/adopt/retract gated claims", names: RE_FINDING_TOOL_NAMES },
];

/** One parameter as read from the schema: its name, whether it is optional, a short type label, and its `.describe()` text. */
interface ParamInfo {
	name: string;
	optional: boolean;
	type: string;
	description: string;
}

interface IrNode {
	k?: string;
	/** Literal value, present when `k === "lit"`. */
	v?: unknown;
	desc?: string;
	descAuto?: boolean;
	members?: IrNode[];
}
interface IrProp {
	key?: string;
	opt?: boolean;
	val?: IrNode;
}

/** The label for one IR node: a literal shows its value (`"address"`), anything else its kind (`string`, `number`). */
function nodeLabel(node: IrNode): string {
	if (node.k === "lit") return JSON.stringify(node.v);
	return node.k ?? "";
}

/** A short type label from an IR value node: a union is its non-undefined/null members labelled and joined with `|` (so `rop`/`cop` literals read `"rop" | "cop"`); anything else is its own label. */
function irTypeLabel(val: IrProp["val"]): string {
	if (!val) return "";
	if (val.k === "union" && Array.isArray(val.members)) {
		const labels = val.members.filter((m) => m.k !== "undefined" && m.k !== "null").map(nodeLabel).filter((l) => l.length > 0);
		return [...new Set(labels)].join(" | ");
	}
	return nodeLabel(val);
}

/**
 * The parameters of a tool's schema, read defensively from either shape the
 * host might hand us: omptype's IR (`schema.ir.props`, what the tool
 * registered) first, then a plain JSON-Schema (`properties`/`required`) as a
 * fallback. An unreadable or parameterless schema yields `[]`.
 */
export function readParams(parameters: unknown): ParamInfo[] {
	const schema = parameters as
		| { ir?: { k?: string; props?: IrProp[] }; properties?: Record<string, { type?: string; description?: string }>; required?: string[] }
		| null
		| undefined;
	const props = schema?.ir?.props;
	if (Array.isArray(props)) {
		return props
			.filter((p): p is IrProp & { key: string } => typeof p.key === "string")
			.map((p) => ({
				name: p.key,
				optional: p.opt === true,
				type: irTypeLabel(p.val),
				description: p.val && !p.val.descAuto && typeof p.val.desc === "string" ? p.val.desc : "",
			}));
	}
	if (schema?.properties && typeof schema.properties === "object") {
		const required = new Set(Array.isArray(schema.required) ? schema.required : []);
		return Object.entries(schema.properties).map(([name, v]) => ({
			name,
			optional: !required.has(name),
			type: typeof v?.type === "string" ? v.type : "",
			description: typeof v?.description === "string" ? v.description : "",
		}));
	}
	return [];
}

/** A compact call signature, `name(addr, offset?, limit?)` — a trailing `?` marks an optional parameter. A parameterless tool renders `name()`. */
export function signature(name: string, parameters: unknown): string {
	const params = readParams(parameters)
		.map((p) => `${p.name}${p.optional ? "?" : ""}`)
		.join(", ");
	return `${name}(${params})`;
}

/** The first line of a description, trimmed and clamped, for the one-line listing. */
function firstLine(description: string, max = 140): string {
	const line = description.split("\n", 1)[0]?.trim() ?? "";
	return line.length > max ? `${line.slice(0, max - 1)}…` : line;
}

/** Full detail for one capability: its signature, whole description, and every parameter with type and docs. */
export function describeTool(meta: ToolMeta): string {
	const params = readParams(meta.parameters);
	const lines = [`${signature(meta.name, meta.parameters)}`, "", `drive it with: await tool.${meta.name}({ … })`, "", meta.description];
	if (params.length === 0) {
		lines.push("", "Parameters: none");
	} else {
		lines.push("", "Parameters:");
		for (const p of params) {
			const head = `  ${p.name}${p.optional ? "?" : ""}${p.type ? ` (${p.type})` : ""}`;
			lines.push(p.description ? `${head} — ${p.description}` : head);
		}
	}
	return lines.join("\n");
}

/**
 * Every live capability, grouped by tier, each as `signature — one-line doc`.
 * `tools` is the already-RE-filtered `getAllTools()` result, so a tier shows
 * only the tools actually registered this session (triage/debugger appear only
 * when available); any RE tool not placed in a known group is listed last so
 * the surface is never silently incomplete.
 */
export function describeAll(tools: readonly ToolMeta[]): string {
	const byName = new Map(tools.map((t) => [t.name, t]));
	const shown = new Set<string>();
	const out: string[] = [];
	const render = (name: string): string => {
		shown.add(name);
		const meta = byName.get(name)!;
		return `  ${signature(name, meta.parameters)} — ${firstLine(meta.description)}`;
	};
	for (const group of GROUPS) {
		const names = Object.keys(group.names)
			.filter((n) => byName.has(n))
			.sort();
		if (names.length === 0) continue;
		out.push(`## ${group.label}`, ...names.map(render), "");
	}
	const rest = tools.filter((t) => RE_ALL_TOOL_NAMES[t.name] === true && !shown.has(t.name)).map((t) => t.name);
	if (rest.length > 0) out.push("## Other", ...rest.sort().map(render), "");
	out.push("Full parameters for one: await tool.re_describe({ name: \"<tool>\" }).");
	return out.join("\n").trimEnd();
}

/** The entry manual (`re_manual`): the paradigm, how to start, how to work, the capability map, and config. Static so it reads identically everywhere; live state is `re_describe` and `/re status`. */
export const RE_MANUAL = `omp-re — reverse engineering with rizin, driven from code.

omp-re adds no tools to your top-level tool list. Every capability is a
rizin-backed omp device: omp mounts it as xd://<name>, and you drive it from the
eval tool as \`await tool.<name>({ ...params })\`. omp's eval is the single code
host — define your own helper functions there and reuse them across eval calls
in this session; omp keeps that namespace.

Start here
  1. await tool.open_binary({ path: "/path/to/binary" })
     Opens a binary and runs full analysis (aaa). Every other capability acts on
     the most-recently-opened binary, so call this first — a task subagent starts
     with nothing open.
  2. await tool.re_describe({})
     Lists every live capability with its call signature and one-line purpose.
     await tool.re_describe({ name: "decompile_function" }) — full parameters and
     docs for one.
  3. read xd://<name> shows one device's docs without calling it;
     write xd://<name> calls it directly. Same tool, same results as eval.

How to work
  - Compose in eval: iterate (await tool.list_functions({})), decompile the
    interesting ones, build and keep your own helpers.
  - Every call returns { text, details } and throws on failure.
  - Read-tier calls and rizin_command are recorded as evidence (/re evidence);
    cite an evidence id in record_finding to gate a claim. /re report writes the
    evidence-gated report, and /re verify re-runs cited commands to confirm the
    recorded output still reproduces.

What's here (signatures: re_describe)
  - Session: open_binary, map_file, export_project.
  - Read: functions, xrefs, strings, imports/exports/symbols, segments, graphs,
    types, decompile/disassemble, and byte/string/regex/asm/value/gadget search.
  - Annotate: rename, set prototype/types/comments, define functions/globals,
    flags and hints.
  - rizin bridge: rizin_help searches the installed rizin's own command catalog;
    rizin_command runs any read-only rizin command the dedicated tools don't cover.
  - rz-* CLI, signatures (FLIRT), analysis passes, types, syscalls, triage
    (capa/floss/die/yara, when installed), the RzIL emulator, and findings.
  - Debugger (rizin_debug): opt-in with OMPRE_ENABLE_DEBUGGER — it executes the
    sample, so only inside a sandbox.

Config
  - OMPRE_RIZIN_PATH    the rizin binary, if not on PATH (a GUI launch can strip it).
  - OMPRE_DECOMPILER    decompiler command order (rz-ghidra pdg, jsdec pdd).
  - OMPRE_ENABLE_DEBUGGER  register the debugger (off by default).
  - OMPRE_AUDIT_HMAC_KEY   sign the audit log.
  Run /re status for live rizin, decompiler, binary, and evidence state.`;

/**
 * Register the two guide tools. Discoverable like every RE capability, so they
 * cost no top-level context and are reached as \`tool.re_manual()\` /
 * \`tool.re_describe({...})\` from eval, or \`read xd://re_manual\`.
 */
export function registerGuideTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const noParams = z.object({});

	pi.registerTool({
		name: "re_manual",
		label: "omp-re manual",
		description:
			"START HERE. How omp-re works: every RE capability is an omp xd:// device you drive from the eval tool as `await tool.<name>({ ...params })`. Returns the full manual — the paradigm, how to open a binary, the capability map, the evidence/report workflow, and config. Then use re_describe for signatures. Needs no open binary.",
		approval: "read",
		loadMode: RE_LOAD_MODE,
		parameters: noParams,
		...reRenderers({ title: "omp-re manual", body: "text" }),
		async execute(_id, _params, _signal, _onUpdate, _ctx) {
			return textResult("omp-re manual", RE_MANUAL);
		},
	});

	const describeParams = z.object({
		name: z
			.string()
			.optional()
			.describe("A capability name (e.g. decompile_function) for its full signature, parameters, and docs. Omit to list every live capability grouped by tier."),
	});
	pi.registerTool({
		name: "re_describe",
		label: "omp-re describe",
		description:
			"List every live omp-re capability with its call signature and one-line purpose, or — with `name` — the full parameters and docs for one. The live source of truth for what you can call as `await tool.<name>({ ...params })`: triage and debugger capabilities appear only when actually available. Needs no open binary.",
		approval: "read",
		loadMode: RE_LOAD_MODE,
		parameters: describeParams,
		...reRenderers({ title: "omp-re describe", subject: "name", body: "text" }),
		async execute(_id, params) {
			const reTools = pi.getAllTools().filter((t) => RE_ALL_TOOL_NAMES[t.name] === true);
			if (params.name) {
				const meta = reTools.find((t) => t.name === params.name);
				if (!meta) {
					return {
						...plainResult(`omp-re: no capability named ${JSON.stringify(params.name)}. Call re_describe with no name to list them all.`),
						isError: true,
					};
				}
				return textResult(`describe ${meta.name}`, describeTool(meta));
			}
			return textResult(`omp-re capabilities (${reTools.length})`, describeAll(reTools));
		},
	});
}
