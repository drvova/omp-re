/**
 * omp-re wiring hub. This is the sole auto-loaded extension for the `re/`
 * subdirectory (omp's directory-with-index.ts convention); every sibling file
 * here is a plain module imported below, never a separate extension.
 *
 * The factory runs once per omp session — the main session and each task
 * subagent get their own ExtensionAPI — so closure state below is per-session.
 */
import { basename } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Text, type AutocompleteItem } from "@oh-my-pi/pi-tui";
import { liveAnnotations } from "./annotations.ts";
import { composeApp } from "./app.ts";
import { RE_ALL_TOOL_NAMES, registerAuditLog } from "./audit.ts";
import { loadCatalog, missingRequiredCommands, REQUIRED_COMMANDS } from "./catalog.ts";
import { decompilerCommands, decompilerLabel } from "./decompile.ts";
import { registerPreservation } from "./preserve.ts";
import { debuggerEnabled, registerDebugTools } from "./tools-debug.ts";
import { registerAnalyzeTools } from "./tools-analyze.ts";
import { registerDeobfuscateTools } from "./tools-deobfuscate.ts";
import { registerEmulateTools } from "./tools-emulate.ts";
import { registerSignatureTools } from "./tools-signatures.ts";
import { branchEntries, lastRecordedBinaryPath, lastRecordedBinarySha256, lastRecordedLoadOptions } from "./entries.ts";
import { rebuildEvidenceIndex, registerEvidenceStore } from "./evidence.ts";
import { plainResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { writeReport } from "./report.ts";
import { sha256File, verifyEvidence } from "./verify.ts";
import { carryManifest } from "./carry.ts";
import type { AuditMode } from "./audit-claims.ts";
import { type LoadOptions, resolveBinaryPath, resolveRizinPath, rizinVersion } from "./rizin.ts";
import { ensureRizin, getState, rekeyState, shutdownState, spawnRizin, syncAnnotationsToBranch } from "./state.ts";
import { registerMutateTools, undoLastAnnotation } from "./tools-mutate.ts";
import { registerInfoTools } from "./tools-info.ts";
import { registerMapFileTools } from "./tools-mapfile.ts";
import { registerProjectTools } from "./tools-project.ts";
import { registerReadTools } from "./tools-read.ts";
import { registerSearchTools } from "./tools-search.ts";
import { registerSyscallTools } from "./tools-syscalls.ts";
import { registerTypeTools } from "./tools-types.ts";
import { registerRizinTools } from "./tools-rizin.ts";
import { registerRzCliTools } from "./tools-rzcli.ts";
import { registerTriageTools } from "./tools-triage.ts";
import { liveFindings, registerFindingTools } from "./findings.ts";
import {
	citeEvidence,
	evidenceRecords,
	findEvidence,
	showFindingsPanel,
	refreshStatusBand,
	registerUI,
	showEvidencePanel,
	showFunctionsPanel,
	showImportsPanel,
	showStringsPanel,
} from "./ui.ts";

interface OpenOptions {
	signal?: AbortSignal;
	onProgress?: (elapsedMs: number) => void;
	loadOptions?: LoadOptions;
}

/** Collect the open_binary load params into a LoadOptions, or undefined when none were given (ordinary header autodetection). */
function toLoadOptions(params: { arch?: string; bits?: 8 | 16 | 32 | 64; base?: string; map?: string; format?: string }): LoadOptions | undefined {
	const load: LoadOptions = {};
	if (params.arch !== undefined) load.arch = params.arch;
	if (params.bits !== undefined) load.bits = params.bits;
	if (params.base !== undefined) load.base = params.base;
	if (params.map !== undefined) load.map = params.map;
	if (params.format !== undefined) load.format = params.format;
	return Object.keys(load).length > 0 ? load : undefined;
}

/**
 * Open a binary for this session: resolve the path, verify rizin is
 * available, spawn and analyze a fresh process (replaying any annotations
 * this branch already recorded for the same binary), and record the choice
 * so `--continue`/`--session` can restore it. Two writes, deliberately:
 * appendEntry persists a CustomEntry that later restores scan (never sent to
 * the LLM); sendMessage feeds the `re.binary` renderer, which only fires for
 * role:"custom" messages.
 */
async function openBinary(pi: ExtensionAPI, ctx: ExtensionContext, inputPath: string, options: OpenOptions = {}): Promise<OpenResult> {
	const resolved = await resolveBinaryPath(inputPath);
	// SHA-256 of the exact bytes, streamed with Node crypto (no rizin spawn). Bound into every
	// evidence record taken this session so `/re verify` confirms it is re-running against the same
	// binary. A hash failure must never block opening — degrade to an unbound (unverifiable) session.
	const sha256 = await sha256File(resolved).catch(() => undefined);
	const { replayFailures } = await spawnRizin(ctx, resolved, options);
	if (sha256) getState(ctx).binarySha256 = sha256;
	const replayed = liveAnnotations(branchEntries(ctx), resolved).length;
	// Persist the load settings and binary hash in the entry too, so a resume reopens a raw blob the same way (header autodetection carries nothing) and restores the evidence binding.
	const details = {
		path: resolved,
		...(options.loadOptions ? { load: options.loadOptions } : {}),
		...(sha256 ? { sha256 } : {}),
	};
	pi.appendEntry("re.binary", details);
	pi.sendMessage({ customType: "re.binary", content: `[re: opened ${resolved}]`, display: true, details });
	await refreshStatusBand(ctx);
	// rizin is the user's own install: say so up front if it lacks a command omp-re's tools send.
	const missingCommands = await loadCatalog().then(missingRequiredCommands, () => []);
	return { path: resolved, replayed, replayFailures, missingCommands };
}

interface OpenResult {
	path: string;
	replayed: number;
	replayFailures: string[];
	missingCommands: string[];
}

/** Footer status while rizin analyzes, cleared when done. */
function analysisStatus(ctx: ExtensionContext, name: string): OpenOptions["onProgress"] {
	if (!ctx.hasUI) return undefined;
	ctx.ui.setStatus("re", `rizin: analyzing ${name}…`);
	return (elapsedMs) => ctx.ui.setStatus("re", `rizin: analyzing ${name}… ${Math.round(elapsedMs / 1000)}s`);
}

function clearAnalysisStatus(ctx: ExtensionContext): void {
	if (ctx.hasUI) ctx.ui.setStatus("re", undefined);
}

function describeOpen(result: OpenResult & { loadOptions?: LoadOptions }): string {
	const lines = [`Binary opened: ${result.path}`];
	if (result.loadOptions) {
		const parts = Object.entries(result.loadOptions).map(([k, v]) => `${k}=${v}`);
		if (parts.length > 0) lines.push(`Loaded with forced settings (${parts.join(", ")}).`);
	}
	if (result.replayed > 0) lines.push(`Re-applied ${result.replayed - result.replayFailures.length} of ${result.replayed} annotation(s) recorded earlier for this binary.`);
	for (const failure of result.replayFailures) lines.push(`  could not re-apply ${failure}`);
	if (result.missingCommands.length > 0) lines.push(missingCommandsWarning(result.missingCommands));
	return lines.join("\n");
}

function missingCommandsWarning(missing: string[]): string {
	return `Warning: this rizin build lacks ${missing.join(", ")}, which omp-re's tools send; the tools that use them will fail. Upgrade rizin (omp-re is tested with 0.9.1).`;
}

const SUBCOMMANDS: readonly { name: string; usage?: string; description: string }[] = [
	{ name: "open", usage: "<path>", description: "open a binary and analyze it with rizin" },
	{ name: "functions", description: "function navigator (alt+g)" },
	{ name: "strings", description: "string list (alt+s)" },
	{ name: "imports", description: "import list (alt+i)" },
	{ name: "evidence", usage: "[id]", description: "evidence recorded on this branch" },
	{ name: "cite", usage: "<id>", description: "cite an evidence entry in your next message" },
	{ name: "findings", usage: "[id]", description: "findings the model recorded on this branch" },
	{ name: "undo", description: "revert the last annotation" },
	{ name: "report", usage: "[path] [--audit=strict]", description: "write the evidence-gated report (claim-support audit advisory by default; --audit=strict gates it, --no-audit skips)" },
	{ name: "verify", usage: "[--strict]", description: "re-run cited rizin commands and check recorded output hashes" },
	{ name: "carry", usage: "<manifest.json> [--against <binary>] [--inherit | --resolve] [--strict] [--out <path>]", description: "replay a report on another build: which claims hold, relocated, drifted, or broke; --inherit re-proves its findings here, --resolve also sends the model what changed" },
	{ name: "status", description: "rizin, decompiler, binary, and evidence status" },
	{ name: "on", description: "enable the RE tools for this session" },
	{ name: "off", description: "disable the RE tools for this session" },
	{ name: "help", description: "show this list" },
];

const HELP_TEXT = [
	"/re open <path>      open a binary        alt+g  function navigator",
	"/re functions        function navigator   alt+s  strings",
	"/re strings          string list          alt+i  imports; in code view:",
	"/re imports          import list             d  toggle decompile",
	"/re evidence [id]    evidence log            x  follow xrefs",
	"/re cite <id>        cite evidence in chat   a  ask the model",
	"/re findings [id]    recorded findings",
	"/re undo             revert annotation",
	"/re report [path]    write report (--audit=strict gates claim support)",
	"/re verify [--strict] re-verify evidence is reproducible",
	"/re carry <manifest>  replay a report on another build (--against, --inherit, --resolve, --strict, --out)",
	"/re status           rizin, decompiler, and session status",
	"/re on               enable RE tools",
	"/re off              disable RE tools (quick toggle, no restart)",
].join("\n");

async function statusText(ctx: ExtensionContext): Promise<string> {
	const state = getState(ctx);
	const version = await rizinVersion();
	const lines = [`rizin: ${version ?? `not found (${resolveRizinPath()})`}`];
	const catalog = await loadCatalog().catch(() => null);
	if (catalog) {
		const missing = missingRequiredCommands(catalog);
		lines.push(
			missing.length === 0
				? `rizin commands: all ${REQUIRED_COMMANDS.length} omp-re sends are present (${catalog.size} in this build; rizin_help searches them)`
				: missingCommandsWarning(missing),
		);
		// Decompiler availability from the catalog (?*j lists plugin commands), in the configured probe order; a live session would resolve the same first entry.
		const present = decompilerCommands().filter((command) => catalog.has(command));
		lines.push(`decompiler: ${decompilerLabel(present[0] ?? null)}`);
		if (present.length > 1) lines.push(`  also available: ${present.slice(1).map(decompilerLabel).join(", ")} (reorder with OMPRE_DECOMPILER)`);
	}
	if (state.binaryPath) {
		lines.push(`binary: ${state.binaryPath}`);
		if (!state.rz || state.rz.isClosed) lines.push("rizin process: not running (starts on next use)");
		lines.push(`annotations in effect: ${liveAnnotations(branchEntries(ctx), state.binaryPath).length}`);
	} else {
		lines.push("binary: none — /re open <path>");
	}
	lines.push(
		debuggerEnabled()
			? `debugger: enabled${state.dbg && !state.dbg.isClosed ? " — a process is running under it" : " (OMPRE_ENABLE_DEBUGGER); executes the sample"}`
			: "debugger: off (set OMPRE_ENABLE_DEBUGGER to enable dynamic analysis — it executes the sample)",
	);
	lines.push(`evidence on this branch: ${evidenceRecords(ctx).length}`);
	const findings = liveFindings(ctx);
	const inherited = findings.filter((f) => f.inherited).length;
	lines.push(`findings on this branch: ${findings.length}${inherited ? ` (${inherited} inherited)` : ""}`);
	lines.push(`audit log signing: ${process.env.OMPRE_AUDIT_HMAC_KEY ? "HMAC-SHA256" : "unsigned (set OMPRE_AUDIT_HMAC_KEY)"}`);
	return lines.join("\n");
}

/**
 * The command shell subsystem: the `re.binary` renderer, the `open_binary`
 * tool and `--binary` flag, the session-lifecycle handlers, argument
 * completion, and the `/re` command. Applied like every other subsystem (see
 * the default export), with the host handed to it.
 */
function registerShell(pi: ExtensionAPI): void {
	/** Session id this instance last saw, to tell a branch into a new session file apart from navigation within one. */
	let lastSessionId: string | undefined;
	/** Latest context, for argument completion (which receives no ctx of its own). */
	let latestCtx: ExtensionContext | undefined;

	pi.registerMessageRenderer<{ path?: string }>("re.binary", (message, _options, theme) => {
		const path = message.details?.path;
		return new Text(theme.fg("accent", `[re: opened ${typeof path === "string" ? path : "?"}]`), 0, 0);
	});

	const openBinaryParams = pi.zod.object({
		path: pi.zod.string().describe("Path to the binary file to open."),
		arch: pi.zod.string().optional().describe("Force the architecture for a raw/headerless target (rizin -a), e.g. x86, arm, mips. Omit for a normal file with a header."),
		bits: pi.zod.union([pi.zod.literal(8), pi.zod.literal(16), pi.zod.literal(32), pi.zod.literal(64)]).optional().describe("Force the word size (rizin -b): 8, 16, 32, or 64. Pair with arch for flat shellcode."),
		base: pi.zod.string().optional().describe("Rebase a formatted image (PE/ELF) at this address (rizin -B), e.g. 0x400000. For a raw/headerless file use `map` instead."),
		map: pi.zod.string().optional().describe("Map a raw/flat file at this address (rizin -m), e.g. 0x400000 — the right option for headerless shellcode or firmware dumps."),
		format: pi.zod.string().optional().describe("Force the bin plugin (rizin -F), e.g. elf, pe, mach0, or `any` to open raw bytes with no format."),
	});
	pi.registerTool({
		name: "open_binary",
		label: "Open binary",
		description:
			"Open a binary for analysis in this session's rizin backend and run full analysis (aaa). Every other RE tool (hash_binary, list_functions, decompile_function, ...) acts on whichever binary was most recently opened here — call this first, especially in a task subagent, which starts with no binary open. For a raw/headerless target (flat shellcode, firmware, a ROM dump) pass arch/bits/base/format so rizin loads it correctly instead of autodetecting from a header it doesn't have.",
		approval: "read",
		loadMode: "essential",
		parameters: openBinaryParams,
		...reRenderers({ title: "Open binary", subject: "path", body: "text" }),
		execute: async (_toolCallId, params, signal, onUpdate, ctx) => {
			const name = basename(params.path);
			const progress = (elapsedMs: number) =>
				onUpdate?.(plainResult(`Analyzing ${name} with rizin… ${Math.round(elapsedMs / 1000)}s`));
			onUpdate?.(plainResult(`Analyzing ${name} with rizin…`));
			const loadOptions = toLoadOptions(params);
			const result = await openBinary(pi, ctx, params.path, { signal, onProgress: progress, loadOptions });
			return plainResult(describeOpen({ ...result, loadOptions }));
		},
	});

	pi.registerFlag("binary", {
		description: "Path to a binary to open with rizin at startup",
		type: "string",
	});

	/**
	 * Bring this session's rizin state in line with the active branch: rebuild
	 * the evidence index, then make sure the binary this branch last opened is
	 * the one loaded. A restore never appends a new `re.binary` entry (the
	 * branch already records it) and runs in the background so a large binary
	 * never blocks session startup.
	 */
	function syncToBranch(ctx: ExtensionContext, opts: { flag?: string } = {}): void {
		latestCtx = ctx;
		lastSessionId = ctx.sessionManager.getSessionId();
		rebuildEvidenceIndex(ctx);
		const state = getState(ctx);
		const recorded = lastRecordedBinaryPath(branchEntries(ctx));
		// Restore the open binary's hash from the branch so evidence recorded after a resume/branch/tree stays bound (openBinary recomputes it when it actually reopens a file below).
		state.binarySha256 = lastRecordedBinarySha256(branchEntries(ctx)) ?? null;

		if (opts.flag && opts.flag !== recorded) {
			const onProgress = analysisStatus(ctx, basename(opts.flag));
			void openBinary(pi, ctx, opts.flag, { onProgress })
				.then((result) => {
					if (result.replayFailures.length > 0 && ctx.hasUI) ctx.ui.notify(describeOpen(result), "warning");
				})
				.catch((err) => ctx.ui.notify(err instanceof Error ? err.message : String(err), "error"))
				.finally(() => clearAnalysisStatus(ctx));
			return;
		}

		if (recorded !== state.binaryPath) {
			state.rz?.close();
			state.rz = null;
			state.binaryPath = recorded ?? null;
			// Recover how this binary was loaded (raw-blob arch/bits/base) so the respawn below reloads it the same way. Applied FLIRT files are recomputed from the branch entries in spawn(), like annotations.
			state.loadOptions = recorded ? (lastRecordedLoadOptions(branchEntries(ctx)) ?? null) : null;
		} else {
			syncAnnotationsToBranch(ctx);
		}
		if (!state.binaryPath || (state.rz && !state.rz.isClosed)) {
			void refreshStatusBand(ctx);
			return;
		}
		const onProgress = analysisStatus(ctx, basename(state.binaryPath));
		void ensureRizin(ctx, { onProgress })
			.then(() => refreshStatusBand(ctx))
			.catch((err) => ctx.ui.notify(err instanceof Error ? err.message : String(err), "error"))
			.finally(() => clearAnalysisStatus(ctx));
	}

	pi.on("session_start", (_event, ctx) => {
		const flag = pi.getFlag("binary");
		syncToBranch(ctx, { flag: typeof flag === "string" && flag.length > 0 ? flag : undefined });
	});

	// A switch (/new, /resume, fork, handoff) leaves this session for another: free its rizin process first.
	pi.on("session_before_switch", (_event, ctx) => {
		shutdownState(ctx.sessionManager.getSessionId());
	});
	pi.on("session_switch", (_event, ctx) => syncToBranch(ctx));

	// A branch writes a new session file with the same history up to the branch point: carry the process over.
	pi.on("session_branch", (_event, ctx) => {
		if (lastSessionId) rekeyState(lastSessionId, ctx.sessionManager.getSessionId());
		syncToBranch(ctx);
	});
	pi.on("session_tree", (_event, ctx) => syncToBranch(ctx));

	pi.on("session_shutdown", (_event, ctx) => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	function completeArguments(prefix: string): AutocompleteItem[] | null {
		const space = prefix.indexOf(" ");
		if (space === -1) {
			const lower = prefix.toLowerCase();
			const matches = SUBCOMMANDS.filter((s) => s.name.startsWith(lower)).map((s) => ({
				value: `${s.name} `,
				label: s.name,
				description: s.description,
				hint: s.usage,
			}));
			return matches.length > 0 ? matches : null;
		}
		const sub = prefix.slice(0, space).toLowerCase();
		if ((sub !== "cite" && sub !== "evidence") || !latestCtx) return null;
		const idPrefix = prefix.slice(space + 1).trim();
		try {
			const matches = evidenceRecords(latestCtx)
				.reverse()
				.filter((e) => e.id.startsWith(idPrefix))
				.slice(0, 50)
				.map((e) => ({ value: `${sub} ${e.id.slice(0, 8)} `, label: e.id.slice(0, 8), description: `${e.tool} @ ${e.ea ?? "?"}` }));
			return matches.length > 0 ? matches : null;
		} catch {
			return null;
		}
	}

	async function runOpen(ctx: ExtensionCommandContext, path: string): Promise<void> {
		const onProgress = analysisStatus(ctx, basename(path));
		try {
			const result = await openBinary(pi, ctx, path, { onProgress });
			if (result.replayed > 0) ctx.ui.notify(describeOpen(result), result.replayFailures.length > 0 ? "warning" : "info");
		} finally {
			clearAnalysisStatus(ctx);
		}
	}

	pi.registerCommand("re", {
		description: "reverse engineering with rizin: open <path> | functions | strings | imports | evidence [id] | cite <id> | findings [id] | undo | report [path] | verify [--strict] | carry <manifest> | status | on | off | help",
		getArgumentCompletions: completeArguments,
		handler: async (args, ctx) => {
			latestCtx = ctx;
			const [sub, ...rest] = args.trim().split(/\s+/).filter(Boolean);
			try {
				switch (sub) {
					case "open": {
						const path = rest.join(" ");
						if (!path) ctx.ui.notify("Usage: /re open <path>", "error");
						else await runOpen(ctx, path);
						return;
					}
					case "functions":
						return await showFunctionsPanel(ctx);
					case "strings":
						return await showStringsPanel(ctx);
					case "imports":
						return await showImportsPanel(ctx);
					case "evidence":
						return await showEvidencePanel(ctx, rest[0]);
					case "findings":
						return await showFindingsPanel(ctx, rest[0]);
					case "cite": {
						const id = rest[0];
						if (!id) {
							ctx.ui.notify("Usage: /re cite <id>", "error");
							return;
						}
						const rec = findEvidence(ctx, id);
						if (!rec) ctx.ui.notify(`omp-re: no evidence found with id ${id}`, "error");
						else citeEvidence(ctx, rec);
						return;
					}
					case "undo":
						ctx.ui.notify(await undoLastAnnotation(pi, ctx), "info");
						return;
					case "report": {
						// --audit[=advisory|strict] / --no-audit (--audit=off) toggle the claim-support audit;
						// strip the flag token so the rest joins back into the output path (mirrors verify's flag parse).
						let audit: AuditMode = "advisory";
						const pathTokens: string[] = [];
						for (const tok of rest) {
							if (tok === "--no-audit" || tok === "--audit=off") audit = "off";
							else if (tok === "--audit" || tok === "--audit=advisory") audit = "advisory";
							else if (tok === "--audit=strict") audit = "strict";
							else pathTokens.push(tok);
						}
						await writeReport(ctx, pathTokens.join(" ") || undefined, { audit });
						return;
					}
					case "verify":
						await verifyEvidence(ctx, { strict: rest.includes("--strict") });
						return;
					case "carry": {
						// /re carry <manifest> [--against <binary>] [--strict] [--out <path>]: flags take the next
						// token as their value; everything else joins back into the manifest path.
						let against: string | undefined;
						let out: string | undefined;
						let strict = false;
						let inherit = false;
						let resolve = false;
						const pathTokens: string[] = [];
						for (let i = 0; i < rest.length; i++) {
							const tok = rest[i]!;
							if (tok === "--strict") strict = true;
							else if (tok === "--inherit") inherit = true;
							else if (tok === "--resolve") resolve = true;
							else if (tok === "--against") against = rest[++i];
							else if (tok === "--out") out = rest[++i];
							else pathTokens.push(tok);
						}
						const manifestPath = pathTokens.join(" ");
						if (!manifestPath) {
							ctx.ui.notify("Usage: /re carry <report.md.manifest.json> [--against <binary>] [--inherit | --resolve] [--strict] [--out <path>]", "error");
							return;
						}
						if (against) await runOpen(ctx, against);
						// --resolve implies --inherit: re-prove what holds, then hand the agenda to the model as a turn.
						await carryManifest(ctx, manifestPath, { strict, out, ...(inherit || resolve ? { inherit: pi } : {}), resolve });
						return;
					}
					case "status":
						ctx.ui.notify(await statusText(ctx), "info");
						return;
					case "off": {
						const active = pi.getActiveTools();
						await pi.setActiveTools(active.filter((name) => !RE_ALL_TOOL_NAMES[name]));
						ctx.ui.notify("omp-re: RE tools disabled for this session — /re on to re-enable", "info");
						return;
					}
					case "on": {
						const all = new Set(pi.getAllTools().map((tool) => tool.name));
						const active = new Set(pi.getActiveTools());
						for (const name of Object.keys(RE_ALL_TOOL_NAMES)) {
							if (all.has(name)) active.add(name);
						}
						await pi.setActiveTools([...active]);
						ctx.ui.notify("omp-re: RE tools enabled for this session", "info");
						return;
					}
					case "help":
					case undefined:
						ctx.ui.notify(HELP_TEXT, "info");
						return;
					default:
						ctx.ui.notify(`omp-re: unknown /re subcommand ${JSON.stringify(sub)} — try /re help`, "error");
				}
			} catch (err) {
				ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
			}
		},
	});
}

/**
 * Extension entry: apply every omp-re subsystem in order. The tool groups,
 * evidence, audit, UI, and the command shell each take the host (`pi`);
 * `composeApp` awaits their registration (the triage/CLI probes are async)
 * before init completes. See app.ts.
 */
export default async function (pi: ExtensionAPI): Promise<void> {
	await composeApp(pi, [
		{ name: "re:read-tools", apply: registerReadTools },
		{ name: "re:info-tools", apply: registerInfoTools },
		{ name: "re:search-tools", apply: registerSearchTools },
		{ name: "re:deobfuscate", apply: registerDeobfuscateTools },
		{ name: "re:type-tools", apply: registerTypeTools },
		{ name: "re:syscall-tools", apply: registerSyscallTools },
		{ name: "re:mutate-tools", apply: registerMutateTools },
		{ name: "re:signature-tools", apply: registerSignatureTools },
		{ name: "re:analyze-tools", apply: registerAnalyzeTools },
		{ name: "re:project-tools", apply: registerProjectTools },
		{ name: "re:finding-tools", apply: registerFindingTools },
		{ name: "re:mapfile-tools", apply: registerMapFileTools },
		{ name: "re:rizin-repl", apply: registerRizinTools },
		{ name: "re:rizin-cli", apply: registerRzCliTools },
		{ name: "re:triage-tools", apply: registerTriageTools },
		{ name: "re:debugger", apply: registerDebugTools },
		{ name: "re:emulator", apply: registerEmulateTools },
		{ name: "re:evidence", apply: registerEvidenceStore },
		{ name: "re:audit", apply: registerAuditLog },
		{ name: "re:preserve", apply: registerPreservation },
		{ name: "re:ui", apply: registerUI },
		{ name: "re:shell", apply: registerShell },
	]);
}
