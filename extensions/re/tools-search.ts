/**
 * Byte search tools — the book's "Searching" chapter, exposed to the model.
 *
 * `/xj` (raw hex search, JSON) and `/xrj` (regex bytes search, JSON) are the
 * two JSON-carrying search surfaces in rizin 0.9.x; both return rows of
 * `{ address, size, flag }`. String search is hex-encoded client-side and run
 * through `/xj`, which keeps one row shape and avoids quoting hazards in the
 * persistent-session transport.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { jsonResult, type ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { eaFromOffset, type RzSession } from "./rizin.ts";
import { ensureRizin } from "./state.ts";
import { DEFAULT_LIMIT, MAX_LIMIT, knownAddr, markEmpty, pageHeader, paginate } from "./tools-read.ts";

export interface RzSearchHit {
	address: number;
	size: number;
	flag: string;
}

interface SearchHitRow {
	ea: string;
	size: number;
	flag: string;
}

function hitRow(hit: RzSearchHit): SearchHitRow {
	return { ea: eaFromOffset(knownAddr(hit.address) ?? 0), size: hit.size, flag: hit.flag };
}

/** Core shared by the three search tools: run one JSON search command and render its hits as paginated rows. */
export async function searchCommand(rz: RzSession, command: string, label: string, params: { offset?: number; limit?: number }): Promise<ReToolResult> {
	const hits = (await rz.cmdj<RzSearchHit[]>(command)) ?? [];
	const { page, total } = paginate(hits, params.offset, params.limit);
	const rows = page.map(hitRow);
	const result = await jsonResult(pageHeader(label, rows, total, params.offset), rows);
	return markEmpty(result, rows.length === 0);
}

export function registerSearchTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const offsetLimit = {
		offset: z.number().int().optional().describe("Skip this many results (default 0)."),
		limit: z.number().int().optional().describe(`Max results to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`),
	};

	const searchBytesParams = z.object({
		// Hex pairs, spaces optional; rizin's `..` byte-mask wildcard is honored (e.g. "8b 4f ..").
		pattern: z
			.string()
			.regex(/^[0-9a-fA-F.?]+(?:\s+[0-9a-fA-F.?]+)*$/)
			.describe('Raw hex bytes to search for, spaces optional; ".." masks one nibble (e.g. "8b 4f ..").'),
		...offsetLimit,
	});
	const searchStringParams = z.object({
		pattern: z.string().min(1).describe("Literal string to search for in the binary's raw bytes."),
		...offsetLimit,
	});
	const searchRegexParams = z.object({
		pattern: z.string().min(1).describe("Regex over raw bytes (rizin /xr syntax)."),
		...offsetLimit,
	});

	pi.registerTool({
		name: "search_bytes",
		label: "Search Bytes",
		description:
			"Search the open binary's raw bytes for a hex pattern (rizin /xj). '..' masks one nibble for wildcard matching. Returns each hit's address, length, and flag name.",
		approval: "read",
		loadMode: "essential",
		parameters: searchBytesParams,
		...reRenderers({ title: "Search bytes", subject: "pattern", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const hex = params.pattern.replace(/\s+/g, "");
			return searchCommand(rz, `/xj ${hex}`, `hits for ${params.pattern}`, params);
		},
	});

	pi.registerTool({
		name: "search_string",
		label: "Search String",
		description:
			"Search the open binary's raw bytes for a literal string (hex-encoded client-side, then rizin /xj). Finds matches everywhere, including code pages — unlike list_strings, which only reports rizin's detected string metadata.",
		approval: "read",
		loadMode: "essential",
		parameters: searchStringParams,
		...reRenderers({ title: "Search string", subject: "pattern", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const hex = Buffer.from(params.pattern, "utf8").toString("hex");
			return searchCommand(rz, `/xj ${hex}`, `hits for ${JSON.stringify(params.pattern)}`, params);
		},
	});

	pi.registerTool({
		name: "search_regex_bytes",
		label: "Search Regex Bytes",
		description:
			"Search the open binary's raw bytes with a rizin /xr regex over bytes. Use for shaped patterns (e.g. an instruction encoding with a variable displacement).",
		approval: "read",
		loadMode: "essential",
		parameters: searchRegexParams,
		...reRenderers({ title: "Search regex", subject: "pattern", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			return searchCommand(rz, `/xrj ${params.pattern}`, `regex hits for ${JSON.stringify(params.pattern)}`, params);
		},
	});
}
