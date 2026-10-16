/**
 * Type tools — the book's "Types" chapter (td/ts/tt/te/tf/tp).
 *
 * Surfaces verified against rizin 0.9.1:
 * - `tsj`/`tej`/`ttj`/`tfj` — JSON listings of loaded structs, enums, typedefs,
 *   and function signatures. rizin ships a rich Windows type base (TCCL) plus
 *   the PE's debug info, so these list far more than user-defined types.
 * - `td <C>` — define types from a C definition, string input (no file access).
 * - `tp <type> @ addr` — print memory interpreted as a type.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { jsonResult, type ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { resolveNumericAddr, validateAddr, type RzSession } from "./rizin.ts";
import { ensureRizin } from "./state.ts";
import { DEFAULT_LIMIT, MAX_LIMIT, markEmpty, pageHeader, paginate } from "./tools-read.ts";

export interface RzTypeListRow {
	name: string;
	/** Structs: member map. Enums: value map. Typedefs: target type. Function defs: signature string. */
	members?: Record<string, string>;
	values?: Record<string, number>;
	type?: string;
}

export interface RzListTypesParams {
	kind: "struct" | "enum" | "typedef" | "function";
	filter?: string;
	offset?: number;
	limit?: number;
}

const KIND_COMMANDS: Record<RzListTypesParams["kind"], string> = {
	struct: "tsj",
	enum: "tej",
	typedef: "ttj",
	function: "tfj",
};

const KIND_LABELS: Record<RzListTypesParams["kind"], string> = {
	struct: "struct types",
	enum: "enum types",
	typedef: "typedef types",
	function: "function types",
};

/** List one type family with an optional name-substring filter, paginated. */
export async function listTypeRows(rz: RzSession, params: RzListTypesParams): Promise<ReToolResult> {
	const rows = (await rz.cmdj<RzTypeListRow[]>(KIND_COMMANDS[params.kind])) ?? [];
	const filter = params.filter?.toLowerCase();
	const filtered = filter ? rows.filter((row) => row.name.toLowerCase().includes(filter)) : rows;
	const { page, total } = paginate(filtered, params.offset, params.limit);
	const result = await jsonResult(pageHeader(KIND_LABELS[params.kind], page, total, params.offset), page);
	return markEmpty(result, page.length === 0);
}

/** Define types from C statements, one td per entry (the transport is line-based). Surfaces rizin's stderr verbatim. */
export async function defineTypeLines(rz: RzSession, definitions: string[]): Promise<ReToolResult> {
	const lines: string[] = [];
	for (const definition of definitions) {
		const { output, stderr } = await rz.cmdWithStderr(`td ${definition}`);
		if (output.trim().length > 0) lines.push(output.trim());
		if (stderr.trim().length > 0) lines.push(stderr.trim());
	}
	if (lines.length === 0) return { content: [{ type: "text", text: `${definitions.length} definition(s) accepted silently (rizin td prints nothing on success). Verify with list_types.` }] };
	return { content: [{ type: "text", text: lines.join("\n") }] };
}

/** Print memory at an address cast as a named type (rizin tp). */
export async function castMemory(rz: RzSession, addr: string, type: string, signal?: AbortSignal): Promise<ReToolResult> {
	const ea = await resolveNumericAddr(rz, validateAddr(addr), signal);
	const { output, stderr } = await rz.cmdWithStderr(`tp ${type} @ ${ea}`, { signal });
	const text = [output.trim(), stderr.trim()].filter((part) => part.length > 0).join("\n");
	return { content: [{ type: "text", text: text.length > 0 ? text : "(no output)" }] };
}

export function registerTypeTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const listTypesParams = z.object({
		kind: z.enum(["struct", "enum", "typedef", "function"]).describe("Which type family to list."),
		filter: z.string().optional().describe("Case-insensitive substring filter on the type name."),
		offset: z.number().int().optional().describe("Skip this many types (default 0)."),
		limit: z.number().int().optional().describe(`Max types to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`),
	});
	const defineTypesParams = z.object({
		definitions: z
			.array(z.string().min(1).trim())
			.min(1)
			.describe('C definitions, one declaration per entry, each ending in ";" (e.g. "struct config { int version; char *name; };").'),
	});
	const castMemoryParams = z.object({
		addr: z.string().describe("Address, flag, or module.symbol to interpret."),
		type: z.string().min(1).describe("Type name to cast the memory as (e.g. \"struct config\")."),
	});

	pi.registerTool({
		name: "list_types",
		label: "List Types",
		description:
			"List types loaded in rizin's type database (structs via tsj, enums via tej, typedefs via ttj, function definitions via tfj). Includes rizin's built-in Windows type base plus debug-info and user-defined types. Filter by name substring; page through large lists.",
		approval: "read",
		loadMode: "essential",
		parameters: listTypesParams,
		...reRenderers({ title: "List types", subject: "kind", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return listTypeRows(rz, params);
		},
	});

	pi.registerTool({
		name: "define_types",
		label: "Define Types",
		description:
			"Define types from C definitions (rizin td). Each statement is one C declaration ending in ';' — structs, unions, enums, typedefs. Type names used but not yet defined must be defined first (td processes statements in order).",
		approval: "read",
		loadMode: "essential",
		parameters: defineTypesParams,
		...reRenderers({ title: "Define types", subject: "count", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return defineTypeLines(rz, params.definitions);
		},
	});

	pi.registerTool({
		name: "cast_memory",
		label: "Cast Memory",
		description:
			"Print memory at an address interpreted as a named type (rizin tp). The type must exist — define it with define_types first, or list existing ones with list_types.",
		approval: "read",
		loadMode: "essential",
		parameters: castMemoryParams,
		...reRenderers({ title: "Cast memory", subject: "addr", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return castMemory(rz, params.addr, params.type, signal);
		},
	});
}
