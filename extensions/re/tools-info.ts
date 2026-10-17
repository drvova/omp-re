/**
 * Binary-info tools — the book's "Basic" info commands (iI/ie/ir/f/ic).
 *
 * Surfaces verified against rizin 0.9.1:
 * - `iIj` — binary info object (arch, bits, base address, compiler, format...).
 * - `iej` — entry points.
 * - `irj` — relocations.
 * - `flj` — all flags (the `f` command family has no bare `fj` in 0.9.1; `flj` lists).
 * - `icj` — classes (RTTI / metadata; empty on plain C binaries).
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { jsonResult, type ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { eaFromOffset, type RzSession } from "./rizin.ts";
import { ensureRizin } from "./state.ts";
import { DEFAULT_LIMIT, MAX_LIMIT, knownAddr, markEmpty, pageHeader, paginate } from "./tools-read.ts";

export interface RzBinaryInfo {
	arch: string;
	bits: number;
	baddr: number;
	binsz: number;
	bintype: string;
	class: string;
	compiler: string;
	format: string;
	[key: string]: unknown;
}

export interface RzEntryPoint {
	vaddr: number;
	paddr: number;
	baddr: number;
	laddr: number;
	haddr: number;
	type: string;
}

export interface RzRelocation {
	name: string;
	type: string;
	vaddr: number;
	paddr: number;
	sym_va: number;
	is_ifunc: boolean;
}

export interface RzFlag {
	name: string;
	realname?: string;
	size: number;
	offset: number;
}

export interface RzClassRow {
	name: string;
	addr?: number;
	methods?: { name: string; addr: number }[];
	fields?: { name: string; addr: number }[];
	[key: string]: unknown;
}

/** Binary info object, keyed by canonical field names where rizin reports them. */
export async function getBinaryInfo(rz: RzSession): Promise<ReToolResult> {
	const info = (await rz.cmdj<RzBinaryInfo>("iIj")) ?? ({} as RzBinaryInfo);
	const rows: Record<string, unknown> = { ...info };
	if (typeof info.baddr === "number" && knownAddr(info.baddr) !== undefined) rows.baseAddress = eaFromOffset(info.baddr);
	const result = await jsonResult("binary info", rows);
	return markEmpty(result, Object.keys(rows).length === 0);
}

/** Entry points with their EAs. */
export async function listEntryPointRows(rz: RzSession): Promise<ReToolResult> {
	const entries = (await rz.cmdj<RzEntryPoint[]>("iej")) ?? [];
	const rows = entries.map((entry) => ({
		ea: eaFromOffset(knownAddr(entry.vaddr) ?? 0),
		type: entry.type,
		...(entry.haddr ? { headerAddr: eaFromOffset(entry.haddr) } : {}),
	}));
	const result = await jsonResult(pageHeader("entrypoints", rows, rows.length, 0), rows);
	return markEmpty(result, rows.length === 0);
}

/** Relocations with type and target EA. */
export async function listRelocationRows(rz: RzSession, params: { offset?: number; limit?: number }): Promise<ReToolResult> {
	const relocs = (await rz.cmdj<RzRelocation[]>("irj")) ?? [];
	const rows = relocs.map((reloc) => ({ ea: eaFromOffset(knownAddr(reloc.vaddr) ?? 0), type: reloc.type }));
	const { page, total } = paginate(rows, params.offset, params.limit);
	const result = await jsonResult(pageHeader("relocations", page, total, params.offset), page);
	return markEmpty(result, page.length === 0);
}

/** All flags (rizin flj), optionally name-filtered, paginated. */
export async function listFlagRows(rz: RzSession, params: { filter?: string; offset?: number; limit?: number }): Promise<ReToolResult> {
	const flags = (await rz.cmdj<RzFlag[]>("flj")) ?? [];
	const filter = params.filter?.toLowerCase();
	const filtered = filter ? flags.filter((flag) => flag.name.toLowerCase().includes(filter)) : flags;
	const { page, total } = paginate(filtered, params.offset, params.limit);
	const rows = page.map((flag) => ({ ea: eaFromOffset(knownAddr(flag.offset) ?? 0), name: flag.name, size: flag.size }));
	const result = await jsonResult(pageHeader("flags", rows, total, params.offset), rows);
	return markEmpty(result, rows.length === 0);
}

/** Classes from binary metadata (RTTI etc.); empty on plain C binaries. */
export async function listClassRows(rz: RzSession, params: { filter?: string; offset?: number; limit?: number }): Promise<ReToolResult> {
	const classes = (await rz.cmdj<RzClassRow[]>("icj")) ?? [];
	const filter = params.filter?.toLowerCase();
	const filtered = filter ? classes.filter((cls) => typeof cls.name === "string" && cls.name.toLowerCase().includes(filter)) : classes;
	const { page, total } = paginate(filtered, params.offset, params.limit);
	const result = await jsonResult(pageHeader("classes", page, total, params.offset), page);
	return markEmpty(result, page.length === 0);
}

export function registerInfoTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const noParams = z.object({});
	const offsetLimit = {
		offset: z.number().int().optional().describe("Skip this many entries (default 0)."),
		limit: z.number().int().optional().describe(`Max entries to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`),
	};
	const relocationsParams = z.object({ ...offsetLimit });
	const listFlagsParams = z.object({
		filter: z.string().optional().describe("Case-insensitive substring filter on the flag name."),
		...offsetLimit,
	});
	const listClassesParams = z.object({
		filter: z.string().optional().describe("Case-insensitive substring filter on the class name."),
		...offsetLimit,
	});

	pi.registerTool({
		name: "get_binary_info",
		label: "Binary Info",
		description:
			"Binary identity: architecture, bits, base address, format, class, compiler, sizes and checksums (rizin iIj). Useful immediately after open_binary as the ground-truth anchor for later claims.",
		approval: "read",
		loadMode: "essential",
		parameters: noParams,
		...reRenderers({ title: "Binary info", subject: "binary", body: "json" }),
		async execute(_id, _params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return getBinaryInfo(rz);
		},
	});

	pi.registerTool({
		name: "list_entrypoints",
		label: "List Entrypoints",
		description: "Binary entry points with their addresses and types (rizin iej).",
		approval: "read",
		loadMode: "essential",
		parameters: noParams,
		...reRenderers({ title: "Entrypoints", subject: "binary", body: "json" }),
		async execute(_id, _params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return listEntryPointRows(rz);
		},
	});

	pi.registerTool({
		name: "list_relocations",
		label: "List Relocations",
		description: "Relocations applied at load time (rizin irj) — relevant when analysing a rebased or patched image.",
		approval: "read",
		loadMode: "essential",
		parameters: relocationsParams,
		...reRenderers({ title: "Relocations", subject: "binary", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return listRelocationRows(rz, params);
		},
	});

	pi.registerTool({
		name: "list_flags",
		label: "List Flags",
		description:
			"Named flags/labels rizin knows about (rizin flj) — analysis flags, reloc.*, section and function labels. Filter by name substring; page through large lists.",
		approval: "read",
		loadMode: "essential",
		parameters: listFlagsParams,
		...reRenderers({ title: "List flags", subject: "filter", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return listFlagRows(rz, params);
		},
	});

	pi.registerTool({
		name: "list_classes",
		label: "List Classes",
		description:
			"Classes recovered from binary metadata — C++ RTTI, Objective-C, Swift metadata (rizin icj). Empty on plain C binaries. Rows can carry methods and fields.",
		approval: "read",
		loadMode: "essential",
		parameters: listClassesParams,
		...reRenderers({ title: "List classes", subject: "filter", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return listClassRows(rz, params);
		},
	});
}
