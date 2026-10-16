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
import { branchEntries, lastRecordedBinaryPath } from "./entries.ts";
import { rebuildEvidenceIndex, registerEvidenceStore } from "./evidence.ts";
import { plainResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { writeReport } from "./report.ts";
import { resolveBinaryPath, resolveRizinPath, rizinVersion } from "./rizin.ts";
import { ensureRizin, getState, rekeyState, shutdownState, spawnRizin, syncAnnotationsToBranch } from "./state.ts";
import { registerMutateTools, undoLastAnnotation } from "./tools-mutate.ts";
import { registerInfoTools } from "./tools-info.ts";
import { registerReadTools } from "./tools-read.ts";
import { registerSearchTools } from "./tools-search.ts";
import { registerSyscallTools } from "./tools-syscalls.ts";
import { registerTypeTools } from "./tools-types.ts";
import { registerRizinTools } from "./tools-rizin.ts";
import { registerRzCliTools } from "./tools-rzcli.ts";
import { registerTriageTools } from "./tools-triage.ts";
import {
	citeEvidence,
	evidenceRecords,
	findEvidence,
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
	const { replayFailures } = await spawnRizin(ctx, resolved, options);
	const replayed = liveAnnotations(branchEntries(ctx), resolved).length;
	pi.appendEntry("re.binary", { path: resolved });
	pi.sendMessage({ customType: "re.binary", content: `[re: opened ${resolved}]`, display: true, details: { path: resolved } });
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

function describeOpen(result: OpenResult): string {
	const lines = [`Binary opened: ${result.path}`];
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
	{ name: "undo", description: "revert the last annotation" },
	{ name: "report", usage: "[path]", description: "write the evidence-gated report" },
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
	"/re undo             revert annotation",
	"/re report [path]    write report",
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
	lines.push(`audit log signing: ${process.env.OMPRE_AUDIT_HMAC_KEY ? "HMAC-SHA256" : "unsigned (set OMPRE_AUDIT_HMAC_KEY)"}`);
	return lines.join("\n");
}

/**
 * The command shell subsystem: the `re.binary` renderer, the `open_binary`
 * tool and `--binary` flag, the session-lifecycle handlers, argument
 * completion, and the `/re` command. Registered like every other subsystem as
 * a cordis plugin (see the default export), so it activates once the host
 * service is available.
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

	const openBinaryParams = pi.zod.object({ path: pi.zod.string().describe("Path to the binary file to open.") });
	pi.registerTool({
		name: "open_binary",
		label: "Open binary",
		description:
			"Open a binary for analysis in this session's rizin backend and run full analysis (aaa). Every other RE tool (hash_binary, list_functions, decompile_function, ...) acts on whichever binary was most recently opened here — call this first, especially in a task subagent, which starts with no binary open.",
		approval: "read",
		loadMode: "essential",
		parameters: openBinaryParams,
		...reRenderers({ title: "Open binary", subject: "path", body: "text" }),
		execute: async (_toolCallId, params, signal, onUpdate, ctx) => {
			const name = basename(params.path);
			const progress = (elapsedMs: number) =>
				onUpdate?.(plainResult(`Analyzing ${name} with rizin… ${Math.round(elapsedMs / 1000)}s`));
			onUpdate?.(plainResult(`Analyzing ${name} with rizin…`));
			const result = await openBinary(pi, ctx, params.path, { signal, onProgress: progress });
			return plainResult(describeOpen(result));
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
		description: "reverse engineering with rizin: open <path> | functions | strings | imports | evidence [id] | cite <id> | undo | report [path] | status | on | off | help",
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
					case "report":
						await writeReport(ctx, rest.join(" ") || undefined);
						return;
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
 * Extension entry: compose every omp-re subsystem onto one cordis context.
 * The tool groups, evidence, audit, UI, and the command shell are each a
 * plugin node; `composeApp` provides the host (`pi`) as a service they inject
 * and awaits their activation (the triage/CLI probes are async) before init
 * completes. See app.ts for the paradigm.
 */
export default async function (pi: ExtensionAPI): Promise<void> {
	await composeApp(pi, [
		{ name: "re:read-tools", apply: registerReadTools },
		{ name: "re:info-tools", apply: registerInfoTools },
		{ name: "re:search-tools", apply: registerSearchTools },
		{ name: "re:type-tools", apply: registerTypeTools },
		{ name: "re:syscall-tools", apply: registerSyscallTools },
		{ name: "re:mutate-tools", apply: registerMutateTools },
		{ name: "re:rizin-repl", apply: registerRizinTools },
		{ name: "re:rizin-cli", apply: registerRzCliTools },
		{ name: "re:triage-tools", apply: registerTriageTools },
		{ name: "re:debugger", apply: registerDebugTools },
		{ name: "re:evidence", apply: registerEvidenceStore },
		{ name: "re:audit", apply: registerAuditLog },
		{ name: "re:preserve", apply: registerPreservation },
		{ name: "re:ui", apply: registerUI },
		{ name: "re:shell", apply: registerShell },
	]);
}
