/**
 * The bridge to the rest of rizin: `rizin_help` reads the installed rizin's
 * own command catalog (`?*j`), and `rizin_command` runs read-only commands
 * the dedicated tools don't cover — function summaries (`pdsf`), call graphs
 * (`agc`), hexdumps (`px`), entropy (`ph entropy`), byte and ROP searches
 * (`/x`, `/R`), ESIL (`aoe`), headers (`iH`), and the rest of rizin's ~700
 * read-only commands. See catalog.ts for the policy and its reasons.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { checkRizinCommand, loadCatalog, searchCatalog } from "./catalog.ts";
import { plainResult, textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { eaFromOffset, resolveNumericAddr } from "./rizin.ts";
import { ensureRizin } from "./state.ts";

const RIZIN_COMMAND_TIMEOUT_MS = 120_000;

/**
 * rizin's stderr with terminal control sequences removed. Searches redraw a
 * progress line on stderr even with `scr.color=0` and leave a bare
 * clear-line escape (`ESC[2K`) behind when they find nothing; that is not an
 * error message.
 */
export function cleanStderr(stderr: string): string {
	return stderr
		.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")
		.replace(/\r/g, "\n")
		.split("\n")
		.map((line) => line.trimEnd())
		.filter((line) => line.trim() !== "")
		.join("\n");
}

function describeCommand(args: unknown): string {
	const record = args && typeof args === "object" ? (args as Record<string, unknown>) : {};
	const command = typeof record.command === "string" ? record.command : "?";
	const addr = typeof record.addr === "string" && record.addr ? ` @ ${record.addr}` : "";
	const line = `${command}${addr}`;
	return JSON.stringify(line.length > 120 ? `${line.slice(0, 117)}...` : line);
}

export function registerRizinTools(pi: ExtensionAPI): void {
	// Named const schemas: see registerReadTools for why they stay outside registerTool({...}).
	const z = pi.zod;
	const helpParams = z.object({
		query: z
			.string()
			.describe("A command or prefix (`pd`, `afv`, `/R`, `ph`) for its usage and arguments, or keywords (`entropy`, `rop gadgets`, `call graph`) to find commands."),
	});
	const commandParams = z.object({
		command: z.string().describe("One read-only rizin command with its arguments, e.g. `pdsf`, `agc ascii`, `px 64`, `/x 4889e5`, `ph entropy 4096`. No `;`, `|`, `>`, `@`, or `~`."),
		addr: z.string().optional().describe("Address or name to run the command at (sent as `@ <addr>`)."),
	});

	pi.registerTool({
		name: "rizin_help",
		label: "rizin help",
		description:
			"Look up rizin commands in the installed rizin's own help: the usage, typed arguments, and summary of a command or command family, or a keyword search across every command. Each entry says whether rizin_command can run it. Use before rizin_command when unsure of a command or its arguments.",
		approval: "read",
		loadMode: "essential",
		parameters: helpParams,
		...reRenderers({ title: "rizin help", subject: "query", body: "text" }),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const catalog = await loadCatalog();
			const { header, lines } = searchCatalog(catalog, params.query);
			return textResult(header, lines.join("\n"), { ctx, tool: "rizin_help" });
		},
	});

	pi.registerTool({
		name: "rizin_command",
		label: "rizin command",
		description:
			"Run one read-only rizin command against the open binary, for anything the dedicated tools don't cover: function summaries (pdsf), call and block graphs (agc, agf), hexdumps (px), entropy (ph entropy), byte/string/ROP searches (/x, /, /R), ESIL (aoe), headers (iH), and the rest of rizin's print, info, search, graph, and listing commands. Also reads config (e asm.arch, el, elj), analysis hints (ahl), metadata and strings (C, Csl), classes (acl, aci), address info (ai), unions and type cross-references (tu, tx), calling-convention lists (tcc), and plugin lists (Ll, La, LD). Commands that write, set config (e key=value), open files, run shell commands, or change analysis are refused; annotate with the dedicated tools instead. If rizin rejects the arguments, its own error and usage text are returned. Check syntax with rizin_help first.",
		approval: (args) => ({ tier: "exec", reason: `Run the rizin command ${describeCommand(args)} on the open binary.` }),
		loadMode: "essential",
		parameters: commandParams,
		...reRenderers({ title: "rizin", subject: "command", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const catalog = await loadCatalog();
			const check = checkRizinCommand(catalog, params.command, params.addr);
			if (!check.ok) throw new Error(check.reason);
			const rz = await ensureRizin(ctx, { signal });
			const ea = params.addr ? await resolveNumericAddr(rz, params.addr, signal).then(eaFromOffset, () => undefined) : undefined;
			const { output, stderr } = await rz.cmdWithStderr(check.line, { timeoutMs: RIZIN_COMMAND_TIMEOUT_MS, signal });
			const header = `rizin> ${check.line}`;
			if (output.trim() === "") {
				const errors = cleanStderr(stderr);
				return errors
					? { ...plainResult(`${header}\n(no output; rizin said:)\n${errors}`, ea), isError: true }
					: plainResult(`${header}\n(no output)`, ea);
			}
			return textResult(header, output.replace(/\n+$/, ""), { ea, ctx, tool: "rizin_command" });
		},
	});
}
