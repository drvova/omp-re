/**
 * Dynamic analysis: a bridge to rizin's debugger, which LAUNCHES and runs the
 * target process so it can be stepped and inspected at runtime.
 *
 * This is the one capability that executes the sample, so it is off by
 * default and the static analysis session never touches it. It registers only
 * when `OMPRE_ENABLE_DEBUGGER` is set, runs in its own rizin `-d` session
 * (state.dbg, killed with the debuggee on `stop` or shutdown), and every
 * action is exec-tier with a reason that says plainly when execution happens.
 *
 * It is a plain debugger — breakpoints, stepping, registers, memory,
 * backtrace — with no facilities for evading detection or hiding the
 * debuggee. Run untrusted samples only in an isolated, disposable environment;
 * see SECURITY.md.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { plainResult, textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { debugTimeoutMs, validateAddr } from "./rizin.ts";
import { getState, requireBinary, requireDebug, startDebug, stopDebug } from "./state.ts";

/** Whether the debugger subsystem is enabled. Off unless the user opts in, because it executes the sample. */
export function debuggerEnabled(): boolean {
	return /^(1|true|yes|on)$/i.test((process.env.OMPRE_ENABLE_DEBUGGER ?? "").trim());
}

/** The loud banner shown when a debug session launches; the model (and the transcript) should never miss that a real process started. */
export const DEBUG_LAUNCH_WARNING =
	"⚠ The target is now RUNNING under a debugger on this machine. Only debug untrusted samples in an isolated, disposable VM or container.";

const DEBUG_ACTIONS = [
	"start",
	"continue",
	"continue_until",
	"step",
	"step_over",
	"registers",
	"read_memory",
	"break_add",
	"break_remove",
	"break_list",
	"backtrace",
	"maps",
	"modules",
	"libraries",
	"sections",
	"processes",
	"threads",
	"fds",
	"signals",
	"windows",
	"stop",
] as const;
type DebugAction = (typeof DEBUG_ACTIONS)[number];

/** Actions that resume the debuggee (versus inspect it or manage breakpoints). */
const EXECUTING_ACTIONS = new Set<DebugAction>(["start", "continue", "continue_until", "step", "step_over"]);

function approvalReason(action: DebugAction): string {
	if (action === "start") return "Launch the target under a debugger — this EXECUTES it on this machine.";
	if (action === "stop") return "Terminate the debugged process.";
	if (EXECUTING_ACTIONS.has(action)) return `Resume execution of the debugged process (${action}).`;
	return `Inspect the debugged process (${action}).`;
}

/** Clamp a positive integer parameter to a sane range. */
function clampInt(value: number | undefined, fallback: number, max: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.max(1, Math.min(Math.floor(value), max));
}

export function registerDebugTools(pi: ExtensionAPI): void {
	if (!debuggerEnabled()) return; // opt-in only: without OMPRE_ENABLE_DEBUGGER the sample is never executed

	// Named const schema: see registerReadTools for why it stays outside registerTool({...}).
	const z = pi.zod;
	const debugParams = z.object({
		action: z.enum(DEBUG_ACTIONS).describe(
			[
				"start: launch the open binary under the debugger, stopped at entry (EXECUTES it).",
				"continue: resume until a breakpoint, signal, or exit. continue_until: resume to `addr`.",
				"step: one instruction (or `count`). step_over: step over calls.",
				"registers: all register values. read_memory: `size` bytes at `addr`.",
				"break_add / break_remove: breakpoint at `addr`. break_list: list them. backtrace: call stack.",
				"stop: kill the process and end the debug session.",
			].join("\n"),
		),
		addr: z.string().optional().describe("Address or symbol for continue_until, read_memory, break_add, break_remove."),
		count: z.number().optional().describe("Instruction count for step / step_over (default 1)."),
		size: z.number().optional().describe("Bytes to read for read_memory (default 64)."),
	});

	pi.registerTool({
		name: "rizin_debug",
		label: "debugger",
		description:
			"Dynamic analysis: launch the open binary under rizin's debugger and drive it — breakpoints, continue, single-step, read registers and memory, backtrace, and inspect maps, modules, libraries, sections, processes, threads, file descriptors, signals, and windows. This EXECUTES the target process; use only in an isolated, disposable environment. Start with action 'start', then set breakpoints and continue/step; 'stop' kills it. The static analysis tools are unaffected.",
		approval: (args) => {
			const action = (args && typeof args === "object" ? (args as { action?: unknown }).action : undefined) as DebugAction | undefined;
			return { tier: "exec", reason: action ? approvalReason(action) : "Drive the debugged process." };
		},
		loadMode: "essential",
		parameters: debugParams,
		...reRenderers({ title: "debugger", subject: "action", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const dbgTimeout = debugTimeoutMs();

			if (params.action === "start") {
				const existing = getState(ctx).dbg;
				if (existing && !existing.isClosed) {
					const pc = (await existing.cmd("dr rip", { signal })).trim() || (await existing.cmd("dr PC", { signal })).trim();
					return plainResult(`debug: already running\n${pc}`);
				}
				const binary = requireBinary(getState(ctx));
				if (ctx.hasUI) ctx.ui.notify(`omp-re: ${DEBUG_LAUNCH_WARNING}`, "warning");
				const dbg = await startDebug(ctx, { signal }); // the debug process is a revertible effect on the session scope
				const pc = (await dbg.cmd("dr rip", { signal })).trim();
				return textResult(`debug: started ${binary}`, `${DEBUG_LAUNCH_WARNING}\nStopped at entry. ${pc}\nSet breakpoints (break_add), then continue or step.`);
			}

			if (params.action === "stop") {
				const dbg = getState(ctx).dbg;
				if (dbg && !dbg.isClosed) {
					try {
						await dbg.cmd("dk 9", { timeoutMs: 5_000, signal });
					} catch {
						// Best effort: disposing the effect below kills the debuggee regardless.
					}
				}
				return (await stopDebug(ctx))
					? plainResult("debug: stopped — process killed and debug session closed")
					: plainResult("debug: no debug session to stop");
			}

			const dbg = requireDebug(ctx);
			const ea = params.addr !== undefined ? validateAddr(params.addr) : undefined;

			switch (params.action) {
				case "continue": {
					const out = (await dbg.cmd("dc", { timeoutMs: dbgTimeout, signal })).trim();
					const pc = (await dbg.cmd("dr rip", { signal })).trim();
					return textResult("debug: continue", `${out || "(resumed)"}\n${pc}`);
				}
				case "continue_until": {
					if (!ea) throw new Error("omp-re: debug continue_until needs addr");
					const out = (await dbg.cmd(`dcu ${ea}`, { timeoutMs: dbgTimeout, signal })).trim();
					const pc = (await dbg.cmd("dr rip", { signal })).trim();
					return textResult(`debug: continue_until ${ea}`, `${out || "(resumed)"}\n${pc}`);
				}
				case "step": {
					const n = clampInt(params.count, 1, 100_000);
					await dbg.cmd(`ds ${n}`, { timeoutMs: dbgTimeout, signal });
					const pc = (await dbg.cmd("dr rip", { signal })).trim();
					return textResult(`debug: step ${n}`, pc);
				}
				case "step_over": {
					const n = clampInt(params.count, 1, 100_000);
					await dbg.cmd(`dso ${n}`, { timeoutMs: dbgTimeout, signal });
					const pc = (await dbg.cmd("dr rip", { signal })).trim();
					return textResult(`debug: step_over ${n}`, pc);
				}
				case "registers": {
					const out = (await dbg.cmd("drj", { signal })).trim();
					return textResult("debug: registers", out || "(no registers)", { ctx, tool: "rizin_debug" });
				}
				case "read_memory": {
					if (!ea) throw new Error("omp-re: debug read_memory needs addr");
					const n = clampInt(params.size, 64, 4096);
					const out = (await dbg.cmd(`pxj ${n} @ ${ea}`, { signal })).trim();
					return textResult(`debug: read_memory ${n} @ ${ea}`, out || "(no output)", { ctx, tool: "rizin_debug" });
				}
				case "break_add": {
					if (!ea) throw new Error("omp-re: debug break_add needs addr");
					await dbg.cmd(`db @ ${ea}`, { signal });
					const list = (await dbg.cmd("dblj", { signal })).trim();
					return textResult(`debug: break_add ${ea}`, list || "(no breakpoints)", { ctx, tool: "rizin_debug" });
				}
				case "break_remove": {
					if (!ea) throw new Error("omp-re: debug break_remove needs addr");
					await dbg.cmd(`db- @ ${ea}`, { signal });
					const list = (await dbg.cmd("dblj", { signal })).trim();
					return textResult(`debug: break_remove ${ea}`, list || "(no breakpoints)", { ctx, tool: "rizin_debug" });
				}
				case "break_list": {
					const list = (await dbg.cmd("dblj", { signal })).trim();
					return textResult("debug: break_list", list || "(no breakpoints)", { ctx, tool: "rizin_debug" });
				}
				case "backtrace": {
					const bt = (await dbg.cmd("dbtj", { signal })).trim();
					return textResult("debug: backtrace", bt || "(no backtrace)", { ctx, tool: "rizin_debug" });
				}
				// Inspection actions from the book's debugger chapters — each one
				// read-only command, no parameters, JSON where rizin offers it.
				case "maps": {
					const out = (await dbg.cmd("dmj", { signal })).trim();
					return textResult("debug: maps", out || "(no maps)", { ctx, tool: "rizin_debug" });
				}
				case "modules": {
					const out = (await dbg.cmd("dmmj", { signal })).trim();
					return textResult("debug: modules", out || "(no modules — continue past the loader to see them)", { ctx, tool: "rizin_debug" });
				}
				case "libraries": {
					const out = (await dbg.cmd("dmij", { signal })).trim();
					return textResult("debug: libraries", out || "(no libraries)", { ctx, tool: "rizin_debug" });
				}
				case "sections": {
					const out = (await dbg.cmd("dmSj", { signal })).trim();
					return textResult("debug: sections", out || "(no sections)", { ctx, tool: "rizin_debug" });
				}
				case "processes": {
					const out = (await dbg.cmd("dpj", { signal })).trim();
					return textResult("debug: processes", out || "(no processes)", { ctx, tool: "rizin_debug" });
				}
				case "threads": {
					const out = (await dbg.cmd("dpTj", { signal })).trim();
					return textResult("debug: threads", out || "(no threads)", { ctx, tool: "rizin_debug" });
				}
				case "fds": {
					const out = (await dbg.cmd("ddlj", { signal })).trim();
					return textResult("debug: fds", out || "(no file descriptors)", { ctx, tool: "rizin_debug" });
				}
				case "signals": {
					const out = (await dbg.cmd("dklj", { signal })).trim();
					return textResult("debug: signals", out || "(no signal info)", { ctx, tool: "rizin_debug" });
				}
				case "windows": {
					const out = (await dbg.cmd("dW", { signal })).trim();
					return textResult("debug: windows", out || "(no windows)", { ctx, tool: "rizin_debug" });
				}
				default:
					throw new Error(`omp-re: debug: unknown action ${JSON.stringify(params.action)}`);
			}
		},
	});
}
