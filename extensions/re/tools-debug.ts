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
import { debugTimeoutMs, rizinBitsMismatch, validateAddr, type RzSession } from "./rizin.ts";
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
	"continue_to_syscall",
	"continue_to_call",
	"continue_to_ret",
	"step",
	"step_over",
	"trace_start",
	"trace_stop",
	"step_back",
	"continue_back",
	"registers",
	"write_register",
	"read_memory",
	"write_memory",
	"disassemble",
	"break_add",
	"break_remove",
	"break_list",
	"watch_add",
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
	"heaps",
	"heap_blocks",
	"heap_arenas",
	"heap_chunks",
	"heap_bins",
	"stop",
] as const;
type DebugAction = (typeof DEBUG_ACTIONS)[number];

/** Actions that resume the debuggee (versus inspect it, manage breakpoints, or modify its state while stopped). */
const EXECUTING_ACTIONS = new Set<DebugAction>(["start", "continue", "continue_until", "continue_to_syscall", "continue_to_call", "continue_to_ret", "step", "step_over", "step_back", "continue_back"]);

/** Actions that move the process BACKWARD through a recorded trace (reverse debugging). */
const REVERSE_ACTIONS = new Set<DebugAction>(["step_back", "continue_back"]);

/** Actions that modify the live process (registers or memory) or arm a watchpoint, as opposed to resuming or inspecting it. */
const MODIFYING_ACTIONS = new Set<DebugAction>(["write_register", "write_memory", "watch_add"]);

function approvalReason(action: DebugAction): string {
	if (action === "start") return "Launch the target under a debugger — this EXECUTES it on this machine.";
	if (action === "stop") return "Terminate the debugged process.";
	if (action === "trace_start") return "Start recording a debug trace session (enables stepping backward).";
	if (action === "trace_stop") return "Stop the debug trace session.";
	if (REVERSE_ACTIONS.has(action)) return `Move the debugged process backward through the recorded trace (${action}).`;
	if (EXECUTING_ACTIONS.has(action)) return `Resume execution of the debugged process (${action}).`;
	if (MODIFYING_ACTIONS.has(action)) return `Modify the debugged process (${action}).`;
	return `Inspect the debugged process (${action}).`;
}

/** A register name for `dr <reg>=...`. */
function validateRegName(reg: string): string {
	if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(reg)) throw new Error(`omp-re: debug: bad register name ${JSON.stringify(reg)}`);
	return reg;
}

/** A register value for `dr <reg>=<value>`: decimal or 0x hex. */
function validateRegValue(value: string): string {
	if (!/^0x[0-9a-fA-F]+$|^[0-9]+$/.test(value)) throw new Error(`omp-re: debug: bad register value ${JSON.stringify(value)} — use decimal or 0x hex`);
	return value;
}

/** Hex bytes for `wx <bytes>`: an even-length string of hex digits, no spaces. */
function validateHexBytes(bytes: string): string {
	const b = bytes.replace(/\s+/g, "");
	if (!/^[0-9a-fA-F]+$/.test(b) || b.length % 2 !== 0) throw new Error(`omp-re: debug: bad hex bytes ${JSON.stringify(bytes)} — an even number of hex digits, e.g. 9090 or 4889e5`);
	return b;
}

/** A watchpoint permission for `dbw <perm>`. */
function validateWatchPerm(perm: string | undefined): string {
	const p = (perm ?? "rw").toLowerCase();
	if (p !== "r" && p !== "w" && p !== "rw") throw new Error(`omp-re: debug: watch perm must be r, w, or rw (got ${JSON.stringify(perm)})`);
	return p;
}

const REMOTE_URI = /^(gdb|windbg):\/\/[A-Za-z0-9._:\-[\]/]+$/;

/**
 * Turn an `attach` object into the rizin `-d <target>` string: a pid
 * (`"1234"`) or a remote stub URI (`gdb://host:port`, `windbg://...`).
 * Exactly one of pid/remote; the URI is charset-validated (it reaches rizin
 * through argv, no shell, but a flag-shaped or spaced value is rejected here
 * with a clear message). Returns undefined when no attach was requested.
 */
export function buildDebugTarget(attach: unknown): string | undefined {
	if (attach === undefined) return undefined;
	if (typeof attach !== "object" || attach === null || Array.isArray(attach)) {
		throw new Error("omp-re: debug: attach must be an object with a pid or remote");
	}
	const a = attach as { pid?: unknown; remote?: unknown };
	const hasPid = a.pid !== undefined;
	const hasRemote = a.remote !== undefined;
	if (hasPid === hasRemote) throw new Error("omp-re: debug: attach needs exactly one of pid or remote");
	if (hasPid) {
		if (typeof a.pid !== "number" || !Number.isInteger(a.pid) || a.pid <= 0) {
			throw new Error(`omp-re: debug: attach.pid must be a positive integer (got ${JSON.stringify(a.pid)})`);
		}
		return String(a.pid);
	}
	if (typeof a.remote !== "string" || !REMOTE_URI.test(a.remote)) {
		throw new Error(`omp-re: debug: attach.remote must be a gdb:// or windbg:// URI (got ${JSON.stringify(a.remote)})`);
	}
	return a.remote;
}

/** Clamp a positive integer parameter to a sane range. */
function clampInt(value: number | undefined, fallback: number, max: number): number {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.max(1, Math.min(Math.floor(value), max));
}

/**
 * The debuggee's program counter as a `<reg> = 0x…` line. `dr rip` is the
 * x86-64 name; `dr PC` is rizin's arch-agnostic alias (eip on x86-32, pc on
 * ARM/MIPS), tried as a fallback so the result is meaningful on every target.
 * Empty string when neither resolves (e.g. the process already exited).
 */
async function programCounter(dbg: RzSession, signal?: AbortSignal): Promise<string> {
	const rip = (await dbg.cmd("dr rip", { signal })).trim();
	if (rip) return rip;
	return (await dbg.cmd("dr PC", { signal })).trim();
}

/**
 * Build rz-run directives for the debug launch (book: tools/rz-run — rizin
 * loads them as `-R directive` flags). One directive per argv element, so
 * values with spaces need no quoting; newlines would break the profile
 * format and are refused everywhere. `!`-prefixed stdio targets execute
 * shell commands on this machine and stay out of the contract.
 */
export function buildRunDirectives(run: unknown): string[] | undefined {
	if (run === undefined) return undefined;
	if (typeof run !== "object" || run === null || Array.isArray(run)) {
		throw new Error("omp-re: debug: run must be an object of rz-run settings");
	}
	const clean = (key: string, value: string): string => {
		if (/[\r\n]/.test(value)) throw new Error(`omp-re: debug: run.${key} must not contain line breaks`);
		return value;
	};
	const directives: string[] = [];
	const r = run as Record<string, unknown>;
	for (const [key, raw] of Object.entries(r)) {
		switch (key) {
			case "args": {
				if (!Array.isArray(raw) || raw.some((a) => typeof a !== "string")) {
					throw new Error("omp-re: debug: run.args must be a list of strings");
				}
				if (raw.length > 64) throw new Error("omp-re: debug: run.args supports at most 64 arguments");
				raw.forEach((a, i) => directives.push(`arg${i}=${clean(key, a)}`));
				break;
			}
			case "env": {
				if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
					throw new Error("omp-re: debug: run.env must be an object");
				}
				for (const [k, v] of Object.entries(raw)) {
					if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) throw new Error(`omp-re: debug: run.env: bad variable name ${JSON.stringify(k)}`);
					if (typeof v !== "string") throw new Error(`omp-re: debug: run.env.${k} must be a string`);
					directives.push(`setenv=${k}=${clean(key, v)}`);
				}
				break;
			}
			case "cwd":
				if (typeof raw !== "string") throw new Error("omp-re: debug: run.cwd must be a string");
				directives.push(`chdir=${clean(key, raw)}`);
				break;
			case "stdin":
			case "stdout":
			case "stderr": {
				if (typeof raw !== "string") throw new Error(`omp-re: debug: run.${key} must be a file path`);
				if (raw.startsWith("!")) throw new Error(`omp-re: debug: run.${key} does not accept command targets`);
				directives.push(`${key}=${clean(key, raw)}`);
				break;
			}
			case "input": {
				if (typeof raw !== "string") throw new Error("omp-re: debug: run.input must be a string");
				if (raw.length > 65_536) throw new Error("omp-re: debug: run.input is limited to 64 KiB");
				directives.push(`input=${clean(key, raw)}`);
				break;
			}
			case "aslr": {
				if (typeof raw !== "boolean") throw new Error("omp-re: debug: run.aslr must be true or false");
				directives.push(`aslr=${raw ? "yes" : "no"}`);
				break;
			}
			case "maxstack":
			case "maxfd":
			case "maxproc":
			case "timeout": {
				if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) {
					throw new Error(`omp-re: debug: run.${key} must be a positive number`);
				}
				directives.push(`${key}=${Math.floor(raw)}`);
				break;
			}
			default:
				throw new Error(`omp-re: debug: run.${key} is not a supported rz-run setting (args, env, cwd, stdin, stdout, stderr, input, aslr, maxstack, maxfd, maxproc, timeout)`);
		}
	}
	return directives.length > 0 ? directives : undefined;
}

export function registerDebugTools(pi: ExtensionAPI): void {
	if (!debuggerEnabled()) return; // opt-in only: without OMPRE_ENABLE_DEBUGGER the sample is never executed

	// Named const schema: see registerReadTools for why it stays outside registerTool({...}).
	const z = pi.zod;
	const debugParams = z.object({
		action: z.enum(DEBUG_ACTIONS).describe(
			[
				"start: launch the open binary under the debugger, stopped at entry (EXECUTES it); or, with `attach`, control a running pid or a remote gdb/windbg stub instead.",
				"continue: resume until a breakpoint, signal, or exit. continue_until: resume to `addr`.",
				"continue_to_syscall / continue_to_call / continue_to_ret: resume until the next syscall, call, or return.",
				"step: one instruction (or `count`). step_over: step over calls.",
				"trace_start / trace_stop: record a trace so you can go backward. step_back / continue_back: step or continue BACKWARD through the recorded trace (reverse debugging).",
				"registers: all register values. write_register: set `reg` to `value`.",
				"read_memory: `size` bytes at `addr`. write_memory: write `bytes` (hex) at `addr`. disassemble: `count` instructions at `addr` (default PC) from live memory.",
				"break_add / break_remove: breakpoint at `addr`. break_list: list breakpoints and watchpoints. watch_add: watchpoint at `addr` (perm r/w/rw, size). backtrace: call stack.",
				"maps / modules / libraries / sections / processes / threads / fds / signals / windows: inspect process state.",
				"heaps / heap_blocks: Windows heaps. heap_arenas / heap_chunks / heap_bins: glibc heap (arena in `addr`/`bin` where relevant).",
				"stop: kill the process and end the debug session.",
			].join("\n"),
		),
		addr: z.string().optional().describe("Address or symbol for continue_until, read_memory, write_memory, disassemble, break_add, break_remove, watch_add, heap_chunks/heap_bins (arena/bin)."),
		count: z.number().optional().describe("Instruction count for step / step_over (default 1), or instructions to show for disassemble (default 16)."),
		size: z.number().optional().describe("Bytes to read for read_memory (default 64), or watchpoint size for watch_add (1/2/4/8)."),
		reg: z.string().optional().describe("Register name for write_register, e.g. rip, rax, eflags."),
		value: z.string().optional().describe("New register value for write_register (decimal or 0x hex)."),
		bytes: z.string().optional().describe("Hex bytes for write_memory, e.g. 9090 or 4889e5 (written to the live process at addr)."),
		perm: z.string().optional().describe("Watchpoint access for watch_add: r, w, or rw (default rw)."),
		run: z
			.object({
				args: z.array(z.string()).optional().describe("Program arguments (arg0..argN)."),
				env: z.record(z.string(), z.string()).optional().describe("Environment variables for the debuggee."),
				cwd: z.string().optional().describe("Working directory for the debuggee."),
				stdin: z.string().optional().describe("File to read the debuggee's stdin from."),
				stdout: z.string().optional().describe("File to write the debuggee's stdout to."),
				stderr: z.string().optional().describe("File to write the debuggee's stderr to."),
				input: z.string().optional().describe("String passed to the debuggee via stdin."),
				aslr: z.boolean().optional().describe("Enable or disable ASLR for the debuggee."),
				maxstack: z.number().optional().describe("Maximum stack size (bytes)."),
				maxfd: z.number().optional().describe("Maximum number of file descriptors."),
				maxproc: z.number().optional().describe("Maximum number of processes."),
				timeout: z.number().optional().describe("Seconds before the debuggee is killed."),
			})
			.optional()
			.describe("rz-run environment for start: the target's arguments, env, cwd, stdio redirections, and limits. Only read alongside action 'start' when launching (not with attach)."),
		attach: z
			.object({
				pid: z.number().optional().describe("Attach to this already-running process id instead of launching the open binary."),
				remote: z.string().optional().describe("Connect to a remote debug stub instead of launching: a gdb:// or windbg:// URI (e.g. a sample running in an isolated VM)."),
			})
			.optional()
			.describe("For action 'start': attach to a running pid or a remote stub instead of launching the open binary. Exactly one of pid/remote; not combined with run. The open binary is used as the symbol source."),
	});

	pi.registerTool({
		name: "rizin_debug",
		label: "debugger",
		description:
			"Dynamic analysis: launch the open binary under rizin's debugger and drive it — breakpoints and watchpoints, continue (incl. to the next syscall/call/return), single-step, reverse-step (record a trace with trace_start, then step_back / continue_back), read and write registers and memory, disassemble live (post-unpacking) memory, backtrace, and inspect maps, modules, libraries, sections, processes, threads, file descriptors, signals, Windows and glibc heaps. 'start' can instead attach to a running pid or connect to a remote gdb/windbg stub (via `attach`) — e.g. a sample running in an isolated VM. This drives a live process; use only in an isolated, disposable environment. Start with action 'start', then set breakpoints and continue/step; 'stop' ends it. The static analysis tools are unaffected.",
		approval: (args) => {
			const record = args && typeof args === "object" ? (args as { action?: unknown; attach?: { pid?: unknown; remote?: unknown } }) : {};
			const action = record.action as DebugAction | undefined;
			if (action === "start" && record.attach && typeof record.attach === "object") {
				const { pid, remote } = record.attach;
				if (typeof pid === "number") return { tier: "exec", reason: `Attach the debugger to running PID ${pid} — it will control that process.` };
				if (typeof remote === "string") return { tier: "exec", reason: `Connect the debugger to the remote target ${JSON.stringify(remote)}.` };
			}
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
					const pc = await programCounter(existing, signal);
					return plainResult(`debug: already running\n${pc}`);
				}
				const binary = requireBinary(getState(ctx));
				const debugTarget = buildDebugTarget(params.attach); // throws on a bad pid/URI, before anything starts
				if (debugTarget !== undefined && params.run !== undefined) {
					throw new Error("omp-re: debug: attach cannot be combined with run (there is no new process to configure)");
				}
				if (ctx.hasUI) ctx.ui.notify(`omp-re: ${DEBUG_LAUNCH_WARNING}`, "warning");
				const runDirectives = buildRunDirectives(params.run); // throws on bad settings, before anything launches
				const dbg = await startDebug(ctx, { signal, runDirectives, debugTarget }); // the debug process is a revertible effect on the session scope
				const pc = await programCounter(dbg, signal);
				if (debugTarget !== undefined) {
					const how = /^\d+$/.test(debugTarget) ? `attached to PID ${debugTarget}` : `connected to ${debugTarget}`;
					return textResult(`debug: ${how}`, `${DEBUG_LAUNCH_WARNING}\nControlling the live process (${how}), symbols from ${binary}.${pc ? `\n${pc}` : ""}\nSet breakpoints (break_add), then continue or step.`);
				}
				const runNote = runDirectives ? ` Target env: ${runDirectives.join(", ")}.` : "";
				// Already surfaced as a warning by startDebug; repeat in the result so
				// the text record carries it.
				const bitsNote = (await rizinBitsMismatch(binary)) ?? "";
				return textResult(`debug: started ${binary}`, `${DEBUG_LAUNCH_WARNING}\nStopped at entry.${runNote}${bitsNote ? `\n${bitsNote}` : ""}${pc ? `\n${pc}` : ""}\nSet breakpoints (break_add), then continue or step.`);
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
					const pc = await programCounter(dbg, signal);
					return textResult("debug: continue", `${out || "(resumed)"}\n${pc}`);
				}
				case "continue_until": {
					if (!ea) throw new Error("omp-re: debug continue_until needs addr");
					const out = (await dbg.cmd(`dcu ${ea}`, { timeoutMs: dbgTimeout, signal })).trim();
					const pc = await programCounter(dbg, signal);
					return textResult(`debug: continue_until ${ea}`, `${out || "(resumed)"}\n${pc}`);
				}
				case "continue_to_syscall": {
					const out = (await dbg.cmd("dcs", { timeoutMs: dbgTimeout, signal })).trim();
					const pc = await programCounter(dbg, signal);
					return textResult("debug: continue_to_syscall", `${out || "(resumed)"}\n${pc}`);
				}
				case "continue_to_call": {
					const out = (await dbg.cmd("dcc", { timeoutMs: dbgTimeout, signal })).trim();
					const pc = await programCounter(dbg, signal);
					return textResult("debug: continue_to_call", `${out || "(resumed)"}\n${pc}`);
				}
				case "continue_to_ret": {
					const out = (await dbg.cmd("dcr", { timeoutMs: dbgTimeout, signal })).trim();
					const pc = await programCounter(dbg, signal);
					return textResult("debug: continue_to_ret", `${out || "(resumed)"}\n${pc}`);
				}
				case "step": {
					const n = clampInt(params.count, 1, 100_000);
					await dbg.cmd(`ds ${n}`, { timeoutMs: dbgTimeout, signal });
					const pc = await programCounter(dbg, signal);
					return textResult(`debug: step ${n}`, pc);
				}
				case "step_over": {
					const n = clampInt(params.count, 1, 100_000);
					await dbg.cmd(`dso ${n}`, { timeoutMs: dbgTimeout, signal });
					const pc = await programCounter(dbg, signal);
					return textResult(`debug: step_over ${n}`, pc);
				}
				// Reverse debugging (book: debugger/revdebug): record a trace with
				// trace_start, then step/continue backward through it. The reverse
				// actions error until a trace session exists — rizin's own message surfaces.
				case "trace_start": {
					const out = (await dbg.cmd("dts+", { timeoutMs: dbgTimeout, signal })).trim();
					return textResult("debug: trace_start", `${out || "trace session started"}\nStep backward with step_back / continue_back; stop recording with trace_stop.`);
				}
				case "trace_stop": {
					await dbg.cmd("dts-", { signal });
					return plainResult("debug: trace_stop — trace session ended");
				}
				case "step_back": {
					const n = clampInt(params.count, 1, 100_000);
					const out = (await dbg.cmd(`dsb ${n}`, { timeoutMs: dbgTimeout, signal })).trim();
					const pc = await programCounter(dbg, signal);
					return textResult(`debug: step_back ${n}`, `${out ? `${out}\n` : ""}${pc || "(no trace session — run trace_start first)"}`);
				}
				case "continue_back": {
					const out = (await dbg.cmd("dcb", { timeoutMs: dbgTimeout, signal })).trim();
					const pc = await programCounter(dbg, signal);
					return textResult("debug: continue_back", `${out ? `${out}\n` : ""}${pc || "(no trace session — run trace_start first)"}`);
				}
				case "registers": {
					const out = (await dbg.cmd("drj", { signal })).trim();
					return textResult("debug: registers", out || "(no registers)", { ctx, tool: "rizin_debug" });
				}
				case "write_register": {
					if (params.reg === undefined || params.value === undefined) throw new Error("omp-re: debug write_register needs reg and value");
					const reg = validateRegName(params.reg);
					const value = validateRegValue(params.value);
					await dbg.cmd(`dr ${reg}=${value}`, { signal });
					const readBack = (await dbg.cmd(`dr ${reg}`, { signal })).trim();
					return textResult(`debug: write_register ${reg}=${value}`, readBack || "(set)", { ctx, tool: "rizin_debug" });
				}
				case "read_memory": {
					if (!ea) throw new Error("omp-re: debug read_memory needs addr");
					const n = clampInt(params.size, 64, 4096);
					const out = (await dbg.cmd(`pxj ${n} @ ${ea}`, { signal })).trim();
					return textResult(`debug: read_memory ${n} @ ${ea}`, out || "(no output)", { ctx, tool: "rizin_debug" });
				}
				case "write_memory": {
					if (!ea) throw new Error("omp-re: debug write_memory needs addr");
					if (params.bytes === undefined) throw new Error("omp-re: debug write_memory needs bytes (hex)");
					const hex = validateHexBytes(params.bytes);
					await dbg.cmd(`wx ${hex} @ ${ea}`, { signal });
					const readBack = (await dbg.cmd(`p8 ${hex.length / 2} @ ${ea}`, { signal })).trim();
					return textResult(`debug: write_memory ${hex.length / 2} bytes @ ${ea}`, `wrote ${hex}; now reads ${readBack}`, { ctx, tool: "rizin_debug" });
				}
				case "disassemble": {
					// Live memory: shows self-modified / unpacked code that the static view can't.
					const n = clampInt(params.count, 16, 1024);
					const at = ea ?? (await programCounter(dbg, signal)).split("=")[1]?.trim() ?? undefined;
					const out = (await dbg.cmd(`pdj ${n}${at ? ` @ ${at}` : ""}`, { signal })).trim();
					return textResult(`debug: disassemble ${n}${at ? ` @ ${at}` : " @ pc"}`, out || "(no output)", { ctx, tool: "rizin_debug" });
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
				case "watch_add": {
					// `dbw <perm> [<size>]` arms a hardware watchpoint at the seek; remove it with break_remove (it lives in the breakpoint list).
					if (!ea) throw new Error("omp-re: debug watch_add needs addr");
					const perm = validateWatchPerm(params.perm);
					const sizeArg = params.size !== undefined ? ` ${clampInt(params.size, 4, 8)}` : "";
					await dbg.cmd(`dbw ${perm}${sizeArg} @ ${ea}`, { signal });
					const list = (await dbg.cmd("dblj", { signal })).trim();
					return textResult(`debug: watch_add ${perm} @ ${ea}`, list || "(no watchpoints)", { ctx, tool: "rizin_debug" });
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
				// Windows heap inspection (book: debugger/heap — dmhw* display
				// commands, no mutation subcommand). heaps lists the process heaps;
				// heap_blocks lists allocated blocks in a heap (optional addr).
				case "heaps": {
					const out = (await dbg.cmd("dmhwj", { signal })).trim();
					return textResult("debug: heaps", out || "(no heap info)", { ctx, tool: "rizin_debug" });
				}
				case "heap_blocks": {
					const out = (await dbg.cmd(`dmhwbj${ea ? ` @ ${ea}` : ""}`, { signal })).trim();
					return textResult(`debug: heap_blocks${ea ? ` @ ${ea}` : ""}`, out || "(no blocks)", { ctx, tool: "rizin_debug" });
				}
				// glibc heap inspection (book: debugger/heap — dmhg* display
				// commands). These report "Can't find glibc mapped in memory" until
				// the loader has run and something has allocated; continue first.
				case "heap_arenas": {
					const out = (await dbg.cmd("dmhga", { signal })).trim();
					return textResult("debug: heap_arenas", out || "(no arenas — continue until glibc is mapped and has allocated)", { ctx, tool: "rizin_debug" });
				}
				case "heap_chunks": {
					const out = (await dbg.cmd(`dmhgj${ea ? ` @ ${ea}` : ""}`, { signal })).trim();
					return textResult(`debug: heap_chunks${ea ? ` @ ${ea}` : ""}`, out || "(no chunks — continue until glibc is mapped and has allocated)", { ctx, tool: "rizin_debug" });
				}
				case "heap_bins": {
					// `dmhgd [<bin_type>]`: all bins, or one of tcache/fast/unsorted/small/large via `bin` (reuses addr as the bin selector).
					const bin = params.addr !== undefined && /^(tcache|fast|unsorted|small|large)$/.test(params.addr) ? ` ${params.addr}` : "";
					const out = (await dbg.cmd(`dmhgd${bin}`, { signal })).trim();
					return textResult(`debug: heap_bins${bin}`, out || "(no bin info — continue until glibc is mapped and has allocated)", { ctx, tool: "rizin_debug" });
				}
				default:
					throw new Error(`omp-re: debug: unknown action ${JSON.stringify(params.action)}`);
			}
		},
	});
}
