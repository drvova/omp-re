/**
 * Read-only rizin tools (11 analysis tools + hash_binary).
 *
 * Every tool here returns the real data as tool content, never just a count:
 * a model that never sees function names or addresses has nothing to ground
 * claims on. Because the full list is visible to the model, list tools
 * default to a bounded page (DEFAULT_LIMIT, capped at MAX_LIMIT), always say
 * when a view is partial, and spill anything truncated to a session artifact.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { decompileAt } from "./decompile.ts";
import { disassembleAt } from "./disasm.ts";
import { jsonResult, plainResult, prefixedTextResult, textResult, type ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { addrOf, eaFromOffset, resolveNumericAddr, validateAddr, type RzSession } from "./rizin.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1000;

/** Clamp a user-supplied limit: unset/invalid/non-positive falls back to DEFAULT_LIMIT; everything else caps at MAX_LIMIT. */
function clampLimit(limit: number | undefined): number {
	if (limit === undefined || !Number.isFinite(limit) || limit <= 0) return DEFAULT_LIMIT;
	return Math.min(limit, MAX_LIMIT);
}

/** offset<0 clamps to 0; offset>=len returns an empty page (never null). Always reports total so callers can tell the model the view is partial. */
function paginate<T>(items: T[], offset: number | undefined, limit: number | undefined): { page: T[]; total: number } {
	const start = Math.max(0, offset ?? 0);
	const total = items.length;
	if (start >= total) return { page: [], total };
	return { page: items.slice(start, start + clampLimit(limit)), total };
}

function pageHeader(label: string, page: unknown[], total: number, offset: number | undefined): string {
	if (page.length >= total) return `${page.length} ${label}`;
	return `${page.length} of ${total} ${label} (offset=${offset ?? 0}; use offset/limit to page through the rest)`;
}

/** rizin reports a few "no address" sentinels as UINT64_MAX (e.g. the NULL section in iSj), which a JS number can't even represent exactly. Anything beyond the safe-integer range is treated as unknown, never printed as an address. */
function knownAddr(value: number | undefined): number | undefined {
	return value !== undefined && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

interface RzRef {
	from: number;
	to: number;
	type: string;
}

interface RzVar {
	name: string;
	type: string;
	arg?: boolean;
	storage?: { type?: string; reg?: string; stack?: number };
}

/** aflj/afij rows: rizin reports the function start as `offset`, and every row carries full call/data/xref arrays (hundreds of entries for a big function), which is why rows are slimmed before reaching the model. */
interface RzFunc {
	addr?: number;
	offset?: number;
	name: string;
	size: number;
	nbbs?: number;
	nargs?: number;
	nlocals?: number;
	indegree?: number;
	outdegree?: number;
	signature?: string;
	[key: string]: unknown;
}

/** One function list row: what an analyst scans a function list for, with `callers` (rizin's indegree) as the cheapest "what matters" signal. */
function functionRow(fn: RzFunc): Record<string, unknown> {
	const addr = knownAddr(addrOf(fn));
	return {
		...(addr === undefined ? {} : { ea: eaFromOffset(addr) }),
		name: fn.name,
		size: fn.size,
		...(fn.nbbs === undefined ? {} : { blocks: fn.nbbs }),
		...(fn.indegree === undefined ? {} : { callers: fn.indegree }),
		...(fn.outdegree === undefined ? {} : { callees: fn.outdegree }),
		...(fn.signature ? { signature: fn.signature.replace(/;\s*$/, "") } : {}),
	};
}

const SORTERS: Record<string, (a: RzFunc, b: RzFunc) => number> = {
	address: (a, b) => (addrOf(a) ?? 0) - (addrOf(b) ?? 0),
	size: (a, b) => b.size - a.size,
	callers: (a, b) => (b.indegree ?? 0) - (a.indegree ?? 0),
};

const REF_CAP = 100;

function storageOf(v: RzVar): string | undefined {
	if (v.storage?.type === "reg" && v.storage.reg) return v.storage.reg;
	if (v.storage?.type === "stack" && typeof v.storage.stack === "number") {
		const off = v.storage.stack;
		return `stack${off < 0 ? "-" : "+"}0x${Math.abs(off).toString(16)}`;
	}
	return v.storage?.type;
}

/**
 * get_function's payload: the function's metrics and signature, its
 * arguments and locals, the unique functions it calls (named via rizin's
 * flags), and the call sites that reach it. Raw intra-function CODE xrefs and
 * immediate-operand DATA refs are reduced to counts: they are hundreds of
 * entries of noise for a model, and disassemble_function/get_xrefs_* expose
 * them precisely when needed.
 */
async function functionSummary(rz: RzSession, fn: RzFunc, ea: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
	const refs = (key: string): RzRef[] => (Array.isArray(fn[key]) ? (fn[key] as RzRef[]) : []);
	const vars = [...(Array.isArray(fn.regvars) ? (fn.regvars as RzVar[]) : []), ...(Array.isArray(fn.stackvars) ? (fn.stackvars as RzVar[]) : [])];
	const describeVar = (v: RzVar) => ({ name: v.name, type: v.type, ...(storageOf(v) ? { storage: storageOf(v) } : {}) });

	const callTargets = [...new Set(refs("callrefs").filter((r) => r.type === "CALL").map((r) => r.to))];
	const calls: { ea: string; name?: string }[] = [];
	for (const to of callTargets.slice(0, REF_CAP)) {
		const flag = await rz.cmdj<{ name?: string; offset?: number }>(`fdj @ ${eaFromOffset(to)}`, { signal });
		calls.push({ ea: eaFromOffset(to), ...(flag?.name && flag.offset === to ? { name: flag.name } : {}) });
	}
	const callers = [...new Set(refs("codexrefs").filter((r) => r.type === "CALL").map((r) => r.from))];

	const omitted = new Set(["offset", "addr", "callrefs", "datarefs", "codexrefs", "dataxrefs", "regvars", "stackvars", "minbound", "maxbound"]);
	const metrics = Object.fromEntries(Object.entries(fn).filter(([key]) => !omitted.has(key)));
	return {
		ea,
		...metrics,
		...(typeof fn.signature === "string" ? { signature: fn.signature.replace(/;\s*$/, "") } : {}),
		args: vars.filter((v) => v.arg).map(describeVar),
		locals: vars.filter((v) => !v.arg).map(describeVar),
		calls,
		...(callTargets.length > REF_CAP ? { callsOmitted: callTargets.length - REF_CAP } : {}),
		callers: callers.slice(0, REF_CAP).map(eaFromOffset),
		...(callers.length > REF_CAP ? { callersOmitted: callers.length - REF_CAP } : {}),
		refCounts: {
			calls: refs("callrefs").length,
			dataRefs: refs("datarefs").length,
			codeXrefs: refs("codexrefs").length,
			dataXrefs: refs("dataxrefs").length,
		},
	};
}

/** axtj rows carry `from` and `to`; rizin adds no function name. Never fabricate a missing side. */
interface RzXref {
	from?: number;
	to?: number;
	type: string;
}

/** iij: `plt` is the PLT stub address, absent for symbols with no stub (weak/unresolved). */
interface RzImport {
	ordinal: number;
	bind: string;
	type: string;
	name: string;
	plt?: number;
}

/** iEj/izj/iSj: addresses live in `vaddr`/`paddr`. */
interface RzVaddrRow {
	vaddr?: number;
	paddr?: number;
}

interface RzExport extends RzVaddrRow {
	name: string;
	ordinal: number;
	bind: string;
	size: number;
	type: string;
}

interface RzString extends RzVaddrRow {
	ordinal?: number;
	size: number;
	length: number;
	section: string;
	type: string;
	string: string;
}

interface RzSegment extends RzVaddrRow {
	name: string;
	size: number;
	vsize: number;
	perm: string;
}

/** Annotate each row with a hex `ea` so the model quotes the address rizin computed, not one it derived from a decimal offset. Omit `ea` rather than fabricate when no address is known. */
function withVaddrEa<T extends RzVaddrRow>(items: T[]): (T & { ea?: string })[] {
	return items.map((item) => {
		const addr = knownAddr(item.vaddr) ?? knownAddr(item.paddr);
		return addr === undefined ? { ...item } : { ...item, ea: eaFromOffset(addr) };
	});
}

/** plt 0/absent means no PLT stub — omit `ea` rather than emit "0x0". */
function withPltEa(items: RzImport[]): (RzImport & { ea?: string })[] {
	return items.map((item) => (item.plt ? { ...item, ea: eaFromOffset(item.plt) } : { ...item }));
}

function withXrefEa(items: RzXref[]): (RzXref & { fromEa?: string; toEa?: string })[] {
	return items.map((item) => {
		const out: RzXref & { fromEa?: string; toEa?: string } = { ...item };
		if (typeof item.from === "number") out.fromEa = eaFromOffset(item.from);
		if (typeof item.to === "number") out.toEa = eaFromOffset(item.to);
		return out;
	});
}

/** An empty page is still evidence ("no xrefs to X" is a finding), but omp may elide it from context once consumed. */
function markEmpty(result: ReToolResult, empty: boolean): ReToolResult {
	return empty ? { ...result, useless: true } : result;
}

export function registerReadTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const offsetLimit = {
		offset: z.number().int().optional().describe("Skip this many results (default 0)."),
		limit: z.number().int().optional().describe(`Max results to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`),
	};

	pi.registerTool({
		name: "list_functions",
		label: "List Functions",
		description:
			"List the functions rizin detected in the open binary: ea, name, size, basic blocks, callers/callees counts, and signature. Sort by `callers` to find the most-used helpers or by `size` to find the biggest logic first.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			...offsetLimit,
			sort: z.enum(["address", "size", "callers"]).optional().describe("Row order (default address)."),
		}),
		...reRenderers({ title: "Functions", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const fns = (await rz.cmdj<RzFunc[]>("aflj", { signal })) ?? [];
			const sorted = params.sort ? [...fns].sort(SORTERS[params.sort]) : fns;
			const { page, total } = paginate(sorted, params.offset, params.limit);
			const label = params.sort && params.sort !== "address" ? `functions by ${params.sort}` : "functions";
			const result = await jsonResult(pageHeader(label, page, total, params.offset), page.map(functionRow), { ctx, tool: "list_functions" });
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "search_functions",
		label: "Search Functions",
		description: "Search functions in the open binary by substring match on name.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			query: z.string().describe("Substring to match against function names."),
			...offsetLimit,
		}),
		...reRenderers({ title: "Search functions", subject: "query", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const fns = (await rz.cmdj<RzFunc[]>("aflj", { signal })) ?? [];
			const filtered = fns.filter((fn) => fn.name.includes(params.query));
			const { page, total } = paginate(filtered, params.offset, params.limit);
			const result = await jsonResult(
				pageHeader(`functions matching ${JSON.stringify(params.query)}`, page, total, params.offset),
				page.map(functionRow),
				{ ctx, tool: "search_functions" },
			);
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "get_function",
		label: "Get Function",
		description:
			"Get one function by name or address: signature, size and complexity metrics, arguments and locals, the functions it calls (by name), and the call sites that reach it.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			target: z.string().describe("Function name or address (e.g. main, sym.foo, 0x4da0)."),
		}),
		...reRenderers({ title: "Function", subject: "target", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const target = validateAddr(params.target);
			const fns = (await rz.cmdj<RzFunc[]>(`afij @ ${target}`, { signal })) ?? [];
			const fn = fns[0];
			const addr = fn ? knownAddr(addrOf(fn)) : undefined;
			if (!fn || addr === undefined) throw new Error(`omp-re: function not found: ${params.target}`);
			const ea = eaFromOffset(addr);
			return jsonResult(`${fn.name} at ${ea} (size ${fn.size})`, await functionSummary(rz, fn, ea, signal), { ea, ctx, tool: "get_function" });
		},
	});

	pi.registerTool({
		name: "decompile_function",
		label: "Decompile Function",
		description:
			"Decompile a function to pseudo-C with the best decompiler plugin loaded in rizin (rz-ghidra's pdg, then jsdec's pdd). When none is available — or it produces nothing for this function — returns annotated disassembly instead, labeled `(disassembly only — …)` at the very start of the output.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({ addr: z.string().describe("Function address or name.") }),
		...reRenderers({ title: "Decompile", subject: "addr", body: "code" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const outcome = await decompileAt(rz, ea, signal);
			if (!outcome) throw new Error(`omp-re: decompile_function: no function at ${params.addr}`);
			const options = { ea, ctx, tool: "decompile_function", decompiler: outcome.kind };
			if (outcome.kind === "disasm") return prefixedTextResult(outcome.prefix ?? "", `disassembly of ${ea}\n${outcome.code}`, options);
			return textResult(`decompiled ${ea} (${outcome.kind})`, outcome.code, options);
		},
	});

	pi.registerTool({
		name: "disassemble_function",
		label: "Disassemble Function",
		description:
			"Disassemble a function to annotated instructions: comments, flags/labels, and incoming cross-references are folded in where rizin reports them.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({ addr: z.string().describe("Function address or name.") }),
		...reRenderers({ title: "Disassemble", subject: "addr", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const disasm = await disassembleAt(rz, ea, signal);
			if (!disasm) throw new Error(`omp-re: disassemble_function: no instructions at ${params.addr}`);
			return textResult(`${disasm.opCount} instructions at ${ea}`, disasm.lines.join("\n"), { ea, ctx, tool: "disassemble_function" });
		},
	});

	const xrefParams = z.object({
		addr: z.string().describe("Address or name to query cross-references for."),
		...offsetLimit,
	});

	pi.registerTool({
		name: "get_xrefs_to",
		label: "Get Xrefs To",
		description: "List cross-references pointing to an address (calls, jumps, and data reads/writes that target it).",
		approval: "read",
		loadMode: "essential",
		parameters: xrefParams,
		...reRenderers({ title: "Xrefs to", subject: "addr", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const addr = validateAddr(params.addr);
			const xrefs = (await rz.cmdj<RzXref[]>(`axtj @ ${addr}`, { signal })) ?? [];
			const { page, total } = paginate(xrefs, params.offset, params.limit);
			const result = await jsonResult(pageHeader(`xrefs to ${params.addr}`, page, total, params.offset), withXrefEa(page), {
				ctx,
				tool: "get_xrefs_to",
			});
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "get_xrefs_from",
		label: "Get Xrefs From",
		description:
			"List cross-references originating from the instruction at an address (what it calls, jumps to, or reads/writes). This is per-instruction: at a function's entry it only covers the first instruction — use get_function's callrefs/datarefs for a whole function.",
		approval: "read",
		loadMode: "essential",
		parameters: xrefParams,
		...reRenderers({ title: "Xrefs from", subject: "addr", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const addr = validateAddr(params.addr);
			const xrefs = (await rz.cmdj<RzXref[]>(`axfj @ ${addr}`, { signal })) ?? [];
			const { page, total } = paginate(xrefs, params.offset, params.limit);
			const result = await jsonResult(pageHeader(`xrefs from ${params.addr}`, page, total, params.offset), withXrefEa(page), {
				ctx,
				tool: "get_xrefs_from",
			});
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "list_imports",
		label: "List Imports",
		description: "List imported symbols in the open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		...reRenderers({ title: "Imports", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const items = (await rz.cmdj<RzImport[]>("iij", { signal })) ?? [];
			const { page, total } = paginate(items, params.offset, params.limit);
			const result = await jsonResult(pageHeader("imports", page, total, params.offset), withPltEa(page), { ctx, tool: "list_imports" });
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "list_exports",
		label: "List Exports",
		description: "List exported symbols in the open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		...reRenderers({ title: "Exports", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const items = (await rz.cmdj<RzExport[]>("iEj", { signal })) ?? [];
			const { page, total } = paginate(items, params.offset, params.limit);
			const result = await jsonResult(pageHeader("exports", page, total, params.offset), withVaddrEa(page), { ctx, tool: "list_exports" });
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "list_strings",
		label: "List Strings",
		description: "List strings found in the open binary's data sections, optionally filtered by substring.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({
			...offsetLimit,
			filter: z.string().optional().describe("Only include strings containing this substring."),
		}),
		...reRenderers({ title: "Strings", subject: "filter", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const items = (await rz.cmdj<RzString[]>("izj", { signal })) ?? [];
			const filter = params.filter;
			const filtered = filter ? items.filter((s) => s.string.includes(filter)) : items;
			const { page, total } = paginate(filtered, params.offset, params.limit);
			const result = await jsonResult(pageHeader("strings", page, total, params.offset), withVaddrEa(page), { ctx, tool: "list_strings" });
			return markEmpty(result, page.length === 0);
		},
	});

	pi.registerTool({
		name: "list_segments",
		label: "List Segments",
		description: "List sections of the open binary with their permissions, sizes, and addresses.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object(offsetLimit),
		...reRenderers({ title: "Sections", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const items = (await rz.cmdj<RzSegment[]>("iSj", { signal })) ?? [];
			const { page, total } = paginate(items, params.offset, params.limit);
			return jsonResult(pageHeader("segments", page, total, params.offset), withVaddrEa(page), { ctx, tool: "list_segments" });
		},
	});

	pi.registerTool({
		name: "hash_binary",
		label: "Hash Binary",
		description: "Compute SHA-256, SHA-1, and MD5 digests of the session's open binary.",
		approval: "read",
		loadMode: "essential",
		parameters: z.object({}),
		...reRenderers({ title: "Hash", body: "text" }),
		async execute(_id, _params, signal, _onUpdate, ctx) {
			const binaryPath = requireBinary(getState(ctx));
			const digest = await hashFile(binaryPath, signal);
			return plainResult(`sha256=${digest.sha256}\nsha1=${digest.sha1}\nmd5=${digest.md5}\nsize=${digest.size}`, "0x0");
		},
	});
}

interface FileDigest {
	sha256: string;
	sha1: string;
	md5: string;
	size: number;
}

function hashFile(path: string, signal?: AbortSignal): Promise<FileDigest> {
	const { promise, resolve, reject } = Promise.withResolvers<FileDigest>();
	const sha256 = createHash("sha256");
	const sha1 = createHash("sha1");
	const md5 = createHash("md5");
	let size = 0;
	const stream = createReadStream(path, { signal });
	stream.on("data", (chunk: string | Buffer) => {
		const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
		size += bytes.length;
		sha256.update(bytes);
		sha1.update(bytes);
		md5.update(bytes);
	});
	stream.on("end", () => {
		resolve({ sha256: sha256.digest("hex"), sha1: sha1.digest("hex"), md5: md5.digest("hex"), size });
	});
	stream.on("error", (err) => reject(new Error(`omp-re: hash_binary: read failed: ${err.message}`)));
	return promise;
}
