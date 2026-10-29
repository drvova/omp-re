/**
 * The bridge to the rest of rizin: `rizin_help` reads the installed rizin's
 * own command catalog (`?*j`), and `rizin_command` runs read-only commands
 * the dedicated tools don't cover — function summaries (`pdsf`), call graphs
 * (`agc`), hexdumps (`px`), entropy (`ph entropy`), byte and ROP searches
 * (`/x`, `/R`), ESIL (`aoe`), headers (`iH`), and the rest of rizin's ~700
 * read-only commands. See catalog.ts for the policy and its reasons.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { checkRizinCommand, loadCatalog, searchCatalog } from "./catalog.ts";
import { canonicalExcerpt, canonicalHash, plainResult, type ReToolResult, shiftHash, textResult } from "./format.ts";
import { RE_LOAD_MODE, reRenderers } from "./render.ts";
import { eaFromOffset, resolveNumericAddr } from "./rizin.ts";
import { ensureRizin, getState } from "./state.ts";

const RIZIN_COMMAND_TIMEOUT_MS = 120_000;

/**
 * The manual `rizin_command` returns for an empty command. omp-re's model-facing
 * surface is one observational tool — this one — plus a few stateful tools;
 * everything you read about the binary is a rizin command you run here and
 * compose in omp's `eval`. (The typed read wrappers of earlier versions live on
 * in the codebase but are no longer registered.)
 */
export const RIZIN_MANUAL = `omp-re — reverse engineering with rizin, driven from code.

You observe the binary by running rizin's own commands through this one tool,
\`rizin_command\`, and composing them in omp's \`eval\` as
\`await tool.rizin_command({ command, addr? })\`. omp's eval is the single code
host — define helper functions there and reuse them across calls this session.

Start here
  1. await tool.open_binary({ path: "/path/to/binary" })  — spawn rizin + analyze (aaa).
     Every command acts on the most-recently-opened binary; a task subagent opens its own.
  2. await tool.rizin_help({ query: "<prefix or keywords>" })  — find the command
     (e.g. "entropy", "call graph", "pdf") and its exact arguments for THIS rizin.
  3. await tool.rizin_command({ command: "aflj" })  — run it. Put an address in
     \`addr\` (sent as \`@ addr\`), never \`@\` in the command.

Reading the binary (prefer the JSON \`*j\` forms; they canonicalize for /re verify)
  functions   aflj            one function  afij  @ <fn>     decompile  pdg  @ <fn>  (or pdd)
  disassemble pdfj  @ <fn>     xrefs to      axtj @ <addr>   xrefs from axfj @ <addr>
  strings     izj              imports       iij             exports    iEj
  symbols     isj              sections      iSj             headers    iHj
  types       tsj              entropy       ph entropy      hexdump    px <n> @ <addr>
  search      /xj <hex>  /Rj (ROP)  /vj (value)             info       ij
  Anything else: rizin_help first, then rizin_command. Read-only; writes are refused here.

Render in eval (display vs print)
  A call returns { text, details } to your code — not a card. display(value) shows a
  highlighted block, print(x) monospace text. A read is recorded as evidence, so its
  \`.text\` is: the header line, the JSON (\`*j\`) body, then a trailing [evidence …] tag
  line — parse the body by dropping the first and last lines. A helper that falls back
  to print (so truncated/non-JSON output never throws):
    const show = (r) => { try { display(JSON.parse(r.text.split("\\n").slice(1, -1).join("\\n"))); } catch { print(r.text); } };
    show(await tool.rizin_command({ command: "afij", addr: "main" }));   // highlighted JSON
    print((await tool.rizin_command({ command: "pdg", addr: "main" })).text);   // C/text
  A big list (aflj, izj on a large binary) is cut at the size cap and ends with
  [Output truncated … artifact://N]: read that artifact, or run a narrower command.

The other (stateful) tools — reach them the same way, await tool.<name>({…})
  open_binary, map_file, export_project            — session: open/overlay/save.
  rename_function, rename_variable, set_comment, set_prototype, set_variable_type,
  define_function, define_global, set_flag, set_calling_convention, set_arch_hint, …
                                                   — annotate; recorded and REPLAYED on resume.
  apply_signatures, create_signature               — FLIRT.        analyze — extra recovery passes.
  record_finding, adopt_finding, retract_finding   — gate report claims on evidence ids.
  rizin_cli                                        — the rz-* programs (rz-bin, rz-diff, rz-hash, …).
  triage_capa/floss/die/yara                       — external triage (present only when installed).
  rizin_debug (opt-in, executes the sample), rizin_emulate (RzIL)  — dynamic analysis.

Evidence & reports
  Every rizin_command read is recorded as evidence (/re evidence); cite its
  [evidence xxxxxxxx] id in record_finding to gate a claim. /re report writes the
  evidence-gated report; /re verify re-runs cited commands to confirm they still reproduce.

Config
  OMPRE_RIZIN_PATH (rizin if not on PATH) · OMPRE_DECOMPILER (pdg/pdd order) ·
  OMPRE_ENABLE_DEBUGGER · OMPRE_AUDIT_HMAC_KEY.  Run /re status for live state.`;

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
		command: z.string().describe("One read-only rizin command with its arguments, e.g. `aflj`, `pdg`, `izj`, `agc ascii`, `px 64`, `/xj 4889e5`, `ph entropy 4096`. No `;`, `|`, `>`, `@`, or `~`. Pass an empty string to get the omp-re manual."),
		addr: z.string().optional().describe("Address or name to run the command at (sent as `@ <addr>`)."),
	});

	pi.registerTool({
		name: "rizin_help",
		label: "rizin help",
		description:
			"Look up rizin commands in the installed rizin's own help: the usage, typed arguments, and summary of a command or command family, or a keyword search across every command. Each entry says whether rizin_command can run it. Use before rizin_command when unsure of a command or its arguments.",
		approval: "read",
		loadMode: RE_LOAD_MODE,
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
			"omp-re's primary way to read a binary: run one read-only rizin command against the open binary and compose calls in eval. This is how you list functions (aflj), decompile (pdg/pdd), read strings/imports/exports/symbols/sections (izj, iij, iej, isj, iSj), xrefs (axtj, axfj), types (tsj), headers (iHj), hexdumps (px), entropy (ph entropy), and run byte/string/ROP searches (/xj, /Rj) — plus the rest of rizin's print, info, search, graph, and listing commands. Prefer the JSON `*j` forms. Commands that write, set config, open files, run shell commands, or change analysis are refused; annotate with the dedicated tools instead. Call rizin_help first for a command's exact arguments. Pass an empty command for the omp-re manual (needs no open binary).",
		approval: (args) => ({ tier: "exec", reason: `Run the rizin command ${describeCommand(args)} on the open binary.` }),
		loadMode: RE_LOAD_MODE,
		parameters: commandParams,
		...reRenderers({ title: "rizin", subject: "command", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			// Empty command → the manual: the one-tool entry point, usable before any binary is open.
			if (params.command.trim() === "") return textResult("omp-re manual", RIZIN_MANUAL);
			return runRizinCommand(ctx, params.command, params.addr, signal);
		},
	});
}

/**
 * The body of `rizin_command`: gate the line through the read-only catalog check,
 * run it, and build the result with its reproducibility fields (commands,
 * reproHash, canonicalExcerpt, shiftHash). Exported so `/re carry --inherit` can
 * re-run a carried command and record it exactly as the tool would.
 */
export async function runRizinCommand(ctx: ExtensionContext, command: string, addr: string | undefined, signal?: AbortSignal): Promise<ReToolResult> {
	// Fail fast on no binary — before loadCatalog spawns rizin — so the "no binary open" guidance
	// fires without a rizin install (and matches the message the typed read tools used to give).
	if (!getState(ctx).binaryPath) {
		throw new Error("omp-re: no binary open — use /re open <path>, open_binary, or --binary <path> first");
	}
	const catalog = await loadCatalog();
	const check = checkRizinCommand(catalog, command, addr);
	if (!check.ok) throw new Error(check.reason);
	const rz = await ensureRizin(ctx, { signal });
	const ea = addr ? await resolveNumericAddr(rz, addr, signal).then(eaFromOffset, () => undefined) : undefined;
	const { output, stderr } = await rz.cmdWithStderr(check.line, { timeoutMs: RIZIN_COMMAND_TIMEOUT_MS, signal });
	const header = `rizin> ${check.line}`;
	if (output.trim() === "") {
		const errors = cleanStderr(stderr);
		return errors
			? { ...plainResult(`${header}\n(no output; rizin said:)\n${errors}`, ea), isError: true }
			: plainResult(`${header}\n(no output)`, ea);
	}
	// reproHash is over the RAW output (pre-trim/pre-truncation), canonicalized and bound to the
	// open binary's path, so `/re verify` can re-run this exact line and hash-compare. The body
	// sent to the model is still the trimmed/truncated text; only the verification key sees raw.
	const binaryPath = getState(ctx).binaryPath ?? undefined;
	return textResult(header, output.replace(/\n+$/, ""), {
		ea,
		ctx,
		tool: "rizin_command",
		commands: [check.line],
		reproHash: canonicalHash(output, binaryPath),
		canonicalExcerpt: canonicalExcerpt(output, binaryPath),
		shiftHash: shiftHash(output, binaryPath),
	});
}
