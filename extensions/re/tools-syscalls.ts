/**
 * Syscall tools — the book's "Syscalls" chapter (as/asn/asr/aslj).
 *
 * rizin 0.9.x ships syscall profiles per OS; on a PE binary the active profile
 * is Windows (swi=46 in our fixture), which covers the Nt* interface. Rows are
 * `{ name, swi, num }` — `num` is the syscall number within the `swi` module.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { jsonResult, type ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { ensureRizin } from "./state.ts";
import type { RzSession } from "./rizin.ts";
import { DEFAULT_LIMIT, MAX_LIMIT, markEmpty, pageHeader, paginate } from "./tools-read.ts";

export interface RzSyscallRow {
	name: string;
	swi: number;
	num: number;
}

export interface RzListSyscallsParams {
	filter?: string;
	offset?: number;
	limit?: number;
}

export interface RzSyscallLookupParams {
	name?: string;
	number?: number;
}

/** List the active syscall profile, optionally name-filtered, paginated. */
export async function listSyscallRows(rz: RzSession, params: RzListSyscallsParams): Promise<ReToolResult> {
	const rows = (await rz.cmdj<RzSyscallRow[]>("aslj")) ?? [];
	const filter = params.filter?.toLowerCase();
	const filtered = filter ? rows.filter((row) => row.name.toLowerCase().includes(filter)) : rows;
	const { page, total } = paginate(filtered, params.offset, params.limit);
	const result = await jsonResult(pageHeader("syscalls", page, total, params.offset), page);
	return markEmpty(result, page.length === 0);
}

/** Resolve one syscall by name (asn) or number (asr); exactly one of the two must be given. */
export async function syscallLookupText(rz: RzSession, params: RzSyscallLookupParams, signal?: AbortSignal): Promise<ReToolResult> {
	if (params.name !== undefined && params.number !== undefined) {
		throw new Error("Pass exactly one of name or number.");
	}
	const command = params.name !== undefined ? `asn ${params.name}` : `asr ${params.number}`;
	const { output, stderr } = await rz.cmdWithStderr(command, { signal });
	const text = [output.trim(), stderr.trim()].filter((part) => part.length > 0).join("\n");
	return { content: [{ type: "text", text: text.length > 0 ? text : "(no match)" }] };
}

export function registerSyscallTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const listSyscallsParams = z.object({
		filter: z.string().optional().describe("Case-insensitive substring filter on the syscall name."),
		offset: z.number().int().optional().describe("Skip this many syscalls (default 0)."),
		limit: z.number().int().optional().describe(`Max syscalls to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`),
	});
	const syscallLookupParams = z.object({
		name: z.string().optional().describe("Syscall name to resolve to its number (e.g. NtOpenProcess)."),
		number: z.number().int().min(0).optional().describe("Syscall number to resolve to its name."),
	});

	pi.registerTool({
		name: "list_syscalls",
		label: "List Syscalls",
		description:
			"List the active syscall profile's syscalls (rizin aslj) — on a PE binary this is the Windows Nt* profile. Rows carry the syscall name and its number (num) within the OS module id (swi). Filter by name substring; page through large lists.",
		approval: "read",
		loadMode: "essential",
		parameters: listSyscallsParams,
		...reRenderers({ title: "List syscalls", subject: "filter", body: "json" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return listSyscallRows(rz, params);
		},
	});

	pi.registerTool({
		name: "syscall_lookup",
		label: "Syscall Lookup",
		description:
			"Resolve one syscall: by name to its number (rizin asn) or by number to its name (rizin asr). Supply exactly one of name or number.",
		approval: "read",
		loadMode: "essential",
		parameters: syscallLookupParams,
		...reRenderers({ title: "Syscall lookup", subject: "name", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
			const rz = await ensureRizin(ctx, { signal });
			return syscallLookupText(rz, params, signal);
		},
	});
}
