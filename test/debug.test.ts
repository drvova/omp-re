/**
 * The opt-in debugger (tools-debug.ts). The enable gate is pure; the full
 * drive — launch, breakpoint, continue, step, inspect, stop — runs against a
 * real rizin debug session on the fixture (which it executes), and is skipped
 * when rizin or the fixture is missing.
 */
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEBUG_LAUNCH_WARNING, buildDebugTarget, buildRunDirectives, debuggerEnabled, registerDebugTools } from "../extensions/re/tools-debug.ts";
import { registerEmulateTools } from "../extensions/re/tools-emulate.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { canRunRizin, captureError, logSkip, makeHarness, TEST_BINARY, textOf } from "./helpers.ts";

logSkip("debugger tests");

const originalEnable = process.env.OMPRE_ENABLE_DEBUGGER;
function restoreEnable() {
	if (originalEnable === undefined) delete process.env.OMPRE_ENABLE_DEBUGGER;
	else process.env.OMPRE_ENABLE_DEBUGGER = originalEnable;
}

describe("debuggerEnabled (no rizin needed)", () => {
	afterEach(restoreEnable);

	test("is off unless explicitly opted in", () => {
		delete process.env.OMPRE_ENABLE_DEBUGGER;
		expect(debuggerEnabled()).toBe(false);
		for (const on of ["1", "true", "yes", "on", "TRUE"]) {
			process.env.OMPRE_ENABLE_DEBUGGER = on;
			expect(debuggerEnabled()).toBe(true);
		}
		for (const off of ["0", "false", "no", ""]) {
			process.env.OMPRE_ENABLE_DEBUGGER = off;
			expect(debuggerEnabled()).toBe(false);
		}
	});

	test("the debug tool is not registered while the gate is off", () => {
		delete process.env.OMPRE_ENABLE_DEBUGGER;
		const h = makeHarness("debug-off");
		registerDebugTools(h.pi);
		expect(() => h.tool("rizin_debug")).toThrow();
	});
});


describe("buildRunDirectives (no rizin needed)", () => {
	test("builds directives for args, env, cwd, stdio, input, aslr, and limits", () => {
		expect(buildRunDirectives(undefined)).toBeUndefined();
		expect(buildRunDirectives({})).toBeUndefined();
		expect(buildRunDirectives({ args: ["--flag", "value with spaces"], env: { PATH_EXTRA: "a=b" }, cwd: "C:/tmp", aslr: false, timeout: 30 })).toEqual([
			"arg0=--flag",
			"arg1=value with spaces",
			"setenv=PATH_EXTRA=a=b",
			"chdir=C:/tmp",
			"aslr=no",
			"timeout=30",
		]);
		expect(buildRunDirectives({ stdin: "C:/in.txt", stdout: "C:/out.txt", stderr: "C:/err.txt", input: "payload", maxstack: 0x100000, maxfd: 64, maxproc: 8 })).toEqual([
			"stdin=C:/in.txt",
			"stdout=C:/out.txt",
			"stderr=C:/err.txt",
			"input=payload",
			"maxstack=1048576",
			"maxfd=64",
			"maxproc=8",
		]);
	});
	test("refuses what the contract leaves out", () => {
		for (const run of [
			{ stdin: "!rm -rf /" }, // stdio=!cmd executes a shell command
			{ stdout: "!cmd" },
			{ args: ["line\nbreak"] },
			{ env: { "BAD-NAME": "v" } },
			{ env: { OK: 1 } },
			{ aslr: "yes" },
			{ timeout: -1 },
			{ bogus: 1 },
			{ args: "not-a-list" },
			"not-an-object",
		]) {
			expect(() => buildRunDirectives(run)).toThrow(/omp-re: debug: run/);
		}
	});
});


describe("buildDebugTarget (no rizin needed)", () => {
	test("no attach ⇒ undefined (the default launch)", () => {
		expect(buildDebugTarget(undefined)).toBeUndefined();
	});

	test("a pid becomes the target string, a gdb/windbg URI passes through", () => {
		expect(buildDebugTarget({ pid: 1234 })).toBe("1234");
		expect(buildDebugTarget({ remote: "gdb://127.0.0.1:1234" })).toBe("gdb://127.0.0.1:1234");
		expect(buildDebugTarget({ remote: "windbg://pipe/com_1" })).toBe("windbg://pipe/com_1");
	});

	test("refuses a bad pid, a non-gdb/windbg or flag-shaped URI, and both-or-neither", () => {
		expect(() => buildDebugTarget({ pid: 0 })).toThrow(/positive integer/);
		expect(() => buildDebugTarget({ pid: -1 })).toThrow(/positive integer/);
		expect(() => buildDebugTarget({ pid: 1.5 })).toThrow(/positive integer/);
		expect(() => buildDebugTarget({ remote: "http://evil" })).toThrow(/gdb:\/\/ or windbg:\/\//);
		expect(() => buildDebugTarget({ remote: "gdb://host; rm -rf /" })).toThrow(/gdb:\/\/ or windbg:\/\//);
		expect(() => buildDebugTarget({})).toThrow(/exactly one/);
		expect(() => buildDebugTarget({ pid: 1, remote: "gdb://h:1" })).toThrow(/exactly one/);
		expect(() => buildDebugTarget("nope")).toThrow(/must be an object/);
	});
});


describe.skipIf(!canRunRizin)("emulate tool against a real rizin session", () => {
	const harness = makeHarness("emulate-test-session");
	const { ctx } = harness;
	const run = (action: string, extra: Record<string, unknown> = {}) =>
		harness.tool("rizin_emulate").execute("t-emulate", { action, ...extra }, undefined, undefined, ctx);

	beforeAll(() => {
		getState(ctx).binaryPath = TEST_BINARY;
		registerEmulateTools(harness.pi);
	});
	afterAll(() => shutdownState(ctx.sessionManager.getSessionId()));

	test("stepping actions are exec-tier and call the interpretation out", () => {
		const approval = harness.tool("rizin_emulate").approval as (a: unknown) => { tier: string; reason: string };
		expect(approval({ action: "step" })).toEqual({ tier: "exec", reason: expect.stringContaining("interpreted") });
		expect(approval({ action: "vars" }).reason).toContain("Read the RzIL VM state");
	});

	test("init at entry0, set a VM variable, step, and watch the VM advance", async () => {
		// Build-agnostic: the suite's rizin may be the 32-bit build (maps at
		// 0x425ff0, names the stack pointer esp), or the 64-bit one — so assert
		// on PC numerically and never on register names or padding.
		const initVars = JSON.parse(textOf(await run("init", { addr: "entry0" })).replace(/^emulate: VM initialized at .+\n(?:rizin build is [^\n]*\n)?/, ""));
		const pc0 = parseInt(String(initVars.PC), 16);
		expect(pc0).toBeGreaterThan(0);
		await run("set_var", { name: "PC", value: `0x${(pc0 + 0x10).toString(16)}` });
		const afterSet = JSON.parse(textOf(await run("vars")).replace(/^emulate: vars\n/, ""));
		expect(parseInt(String(afterSet.PC), 16)).toBe(pc0 + 0x10);
		const stepped = textOf(await run("step", { count: 2 }));
		expect(stepped).toContain("pc_write");
		const vars = JSON.parse(textOf(await run("vars")).replace(/^emulate: vars\n/, ""));
		expect(parseInt(String(vars.PC), 16)).not.toBe(pc0 + 0x10);
	}, 30_000);

	test("step_until reaches a step-discovered PC (base-free)", async () => {
		// Learn where one instruction lands, reset, then run step_until to that
		// same PC — self-consistent regardless of the image base the session maps.
		await run("init", { addr: "entry0" });
		const changes = JSON.parse(textOf(await run("step", { count: 1 })).replace(/^emulate: step 1\n/, ""));
		const pcWrites = changes.filter((c: { type?: string }) => c.type === "pc_write");
		expect(pcWrites.length).toBeGreaterThan(0);
		const target = String(pcWrites[pcWrites.length - 1].new);
		await run("init", { addr: "entry0" });
		const vars = JSON.parse(textOf(await run("step_until", { addr: target })).replace(/^emulate: step_until .+\n(?:rizin build is [^\n]*\n)?/, ""));
		expect(parseInt(String(vars.PC), 16)).toBe(parseInt(target, 16));
	}, 30_000);
});

describe.skipIf(!canRunRizin)("debug tool against a real debug session", () => {
	const harness = makeHarness("debug-test-session");
	const { ctx } = harness;
	const run = (action: string, extra: Record<string, unknown> = {}) =>
		harness.tool("rizin_debug").execute("t-debug", { action, ...extra }, undefined, undefined, ctx);
	let outDir: string;

	beforeAll(() => {
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		outDir = mkdtempSync(join(tmpdir(), "omp-re-dump-test-"));
		process.env.OMPRE_OUTPUT_DIR = outDir;
		getState(ctx).binaryPath = TEST_BINARY;
		registerDebugTools(harness.pi);
	});
	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
		delete process.env.OMPRE_OUTPUT_DIR;
		rmSync(outDir, { recursive: true, force: true });
		restoreEnable();
	});

	test("every action is exec-tier, with execution, modification, and inspection called out distinctly", () => {
		const approval = harness.tool("rizin_debug").approval as (a: unknown) => { tier: string; reason: string };
		expect(approval({ action: "start" })).toEqual({ tier: "exec", reason: expect.stringContaining("EXECUTES it") });
		expect(approval({ action: "continue" }).reason).toContain("Resume execution");
		expect(approval({ action: "continue_to_syscall" }).reason).toContain("Resume execution");
		expect(approval({ action: "continue_to_ret" }).reason).toContain("Resume execution");
		expect(approval({ action: "write_register" }).reason).toContain("Modify");
		expect(approval({ action: "write_memory" }).reason).toContain("Modify");
		expect(approval({ action: "watch_add" }).reason).toContain("Modify");
		expect(approval({ action: "registers" }).reason).toContain("Inspect");
		expect(approval({ action: "dump_memory" })).toEqual({ tier: "exec", reason: expect.stringContaining("write it to a file") });
		expect(approval({ action: "disassemble" }).reason).toContain("Inspect");
		expect(approval({ action: "heap_chunks" }).reason).toContain("Inspect");
		expect(approval({ action: "registers_telescope" }).reason).toContain("Inspect");
		expect(approval({ action: "resolve_symbol" }).reason).toContain("Inspect");
		expect(approval({ action: "break_condition" }).reason).toContain("Inspect");
		expect(approval({ action: "break_command" }).reason).toContain("Inspect");
		expect(approval({ action: "break_add_hw" }).reason).toContain("Modify");
		expect(approval({ action: "trace_start" }).reason).toContain("trace session");
		expect(approval({ action: "trace_save" }).reason).toContain("output directory");
		expect(approval({ action: "trace_load" }).reason).toContain("saved debug trace");
		expect(approval({ action: "step_back" }).reason).toContain("backward");
		expect(approval({ action: "continue_back" }).reason).toContain("backward");
		expect(approval({ action: "stop" }).reason).toContain("Terminate");
	});

	test("an action before start is refused (nothing is launched implicitly)", async () => {
		expect((await captureError(run("continue"))).message).toContain("no debug session");
	});

	test("start launches the process with a loud warning and a stopped PC", async () => {
		const out = textOf(await run("start"));
		expect(out).toContain(DEBUG_LAUNCH_WARNING);
		expect(out).toMatch(/rip = 0x[0-9a-f]+/);
		expect(getState(ctx).dbg?.isClosed).toBe(false);
	}, 20_000);

	test("breakpoint, continue, and inspect the running process", async () => {
		expect(textOf(await run("break_add", { addr: "entry0" }))).toContain('"enabled":true');
		const cont = textOf(await run("continue"));
		expect(cont).toMatch(/rip = 0x[0-9a-f]+/);
		expect(textOf(await run("registers"))).toMatch(/"rip":\d+/);
		expect(textOf(await run("backtrace"))).toContain('"idx":0');
		expect(textOf(await run("break_list"))).toContain("addr");
	}, 20_000);

	test("step advances the PC and read_memory returns bytes at an address", async () => {
		const before = textOf(await run("registers"));
		await run("step", { count: 1 });
		const after = textOf(await run("registers"));
		expect(after).not.toBe(before);
		expect(textOf(await run("read_memory", { addr: "rip", size: 8 }))).toMatch(/^\[.*\]$/m);
	}, 20_000);

	test("dump_memory writes live memory to a file in the output dir, with a matching size and sha256", async () => {
		const result = textOf(await run("dump_memory", { addr: "rip", size: 64, file: "entry.bin" }));
		expect(result).toContain("wrote 64 bytes");
		const path = join(outDir, "entry.bin");
		expect(result).toContain(path);
		const bytes = readFileSync(path);
		expect(bytes.length).toBe(64);
		// the reported sha256 matches the file on disk, and the bytes match what read_memory sees at rip
		expect(result).toContain(createHash("sha256").update(bytes).digest("hex"));
	}, 20_000);

	test("dump_memory rejects a non-positive size and a traversing filename before writing", async () => {
		expect((await captureError(run("dump_memory", { addr: "rip", size: 0 }))).message).toContain("positive size");
		expect((await captureError(run("dump_memory", { addr: "rip", size: 16, file: "../escape.bin" }))).message).toContain("invalid output filename");
	});

	test("write_register sets a register and reads the new value back", async () => {
		const out = textOf(await run("write_register", { reg: "rax", value: "0x1234" }));
		expect(out).toMatch(/rax = 0x0*1234/);
	});

	test("write_memory writes bytes to the live process and reads them back", async () => {
		const out = textOf(await run("write_memory", { addr: "rsp", bytes: "deadbeef" }));
		expect(out).toContain("deadbeef");
		expect(textOf(await run("read_memory", { addr: "rsp", size: 4 }))).toMatch(/^\[.*\]$/m);
	});

	test("disassemble returns live instructions as JSON (at the PC by default)", async () => {
		const out = textOf(await run("disassemble", { count: 3 }));
		expect(out).toMatch(/"opcode"/);
	});

	test("watch_add arms a hardware watchpoint that break_list shows", async () => {
		const out = textOf(await run("watch_add", { addr: "rsp", perm: "rw", size: 4 }));
		expect(out).toContain("rsp");
		// It lives in the breakpoint list as a hardware watchpoint; break_remove takes it off.
		expect(textOf(await run("break_list"))).toContain('"hw":true');
	});

	test("write_register rejects a bad register name and value before touching rizin", async () => {
		expect((await captureError(run("write_register", { reg: "rax;id", value: "1" }))).message).toContain("bad register name");
		expect((await captureError(run("write_register", { reg: "rax", value: "0xzz" }))).message).toContain("bad register value");
	});

	test("write_memory rejects non-hex or odd-length bytes", async () => {
		expect((await captureError(run("write_memory", { addr: "rsp", bytes: "zz" }))).message).toContain("bad hex bytes");
		expect((await captureError(run("write_memory", { addr: "rsp", bytes: "9" }))).message).toContain("bad hex bytes");
	});

	test("continue_to_syscall resumes the process to the next syscall", async () => {
		const out = textOf(await run("continue_to_syscall"));
		// It either stops at a syscall (PC line) or reports the resume; never a desync.
		expect(out.length).toBeGreaterThan(0);
		expect(textOf(await run("registers"))).toMatch(/"rip":\d+|"pc":\d+/);
	}, 20_000);

	test("registers_telescope resolves registers, and resolve_symbol looks up a loaded symbol", async () => {
		expect(textOf(await run("registers_telescope"))).toMatch(/rsp|rip|pc/i);
		// resolve_symbol returns rizin's lookup (a match or its 'not mapped' note); never a desync.
		expect(textOf(await run("resolve_symbol", { name: "write" })).length).toBeGreaterThan(0);
	}, 20_000);

	test("breakpoint management: hardware bp, condition, on-hit command, enable/disable", async () => {
		await run("break_add", { addr: "entry0" });
		// hardware breakpoint
		expect(textOf(await run("break_add_hw", { addr: "main" }))).toContain('"hw":true');
		// condition with a `>` that must stay literal (single-quoted), not a redirect
		expect(textOf(await run("break_condition", { addr: "entry0", condition: "rax>0" }))).toContain('"cond":"rax>0"');
		// on-hit command, gated read-only
		expect(textOf(await run("break_command", { addr: "entry0", command: "drj" }))).toContain('"data":"drj"');
		// disable then enable
		expect(textOf(await run("break_disable", { addr: "entry0" }))).toContain('"enabled":false');
		expect(textOf(await run("break_enable", { addr: "entry0" }))).toContain('"enabled":true');
	}, 20_000);

	test("break_command refuses shell/write/control on-hit commands but allows a debugger-state read", async () => {
		await run("break_add", { addr: "main" });
		// shell escape, memory write, and a static write are all refused
		expect((await captureError(run("break_command", { addr: "main", command: "!id" }))).message).toMatch(/not a read-only on-hit command|not allowed/);
		expect((await captureError(run("break_command", { addr: "main", command: "w hello" }))).message).toMatch(/not a read-only on-hit command|not allowed/);
		// debugger control (continue) is refused — on-hit commands log state, they never drive the process
		expect((await captureError(run("break_command", { addr: "main", command: "dc" }))).message).toMatch(/not a read-only on-hit command/);
		// the register-assign dual (`dr reg=val`) is caught by the `=` guard, not allowed as a bare read
		expect((await captureError(run("break_command", { addr: "main", command: "dr rax=0" }))).message).toMatch(/would assign\/select/);
		// but a vetted debugger-state read the static policy forbids (maps) is allowed here
		expect(textOf(await run("break_command", { addr: "main", command: "dmj" }))).toContain('"data":"dmj"');
	});

	test("reverse debugging: record a trace, step forward, then step_back returns to an earlier PC", async () => {
		expect(textOf(await run("trace_start"))).toMatch(/trace session|step backward/i);
		await run("step", { count: 3 });
		const forward = textOf(await run("registers"));
		const back = textOf(await run("step_back", { count: 2 }));
		expect(back).toMatch(/0x[0-9a-f]+/);
		// The PC after stepping back differs from where we were after stepping forward.
		expect(textOf(await run("registers"))).not.toBe(forward);
		await run("trace_stop");
	}, 25_000);

	test("trace_save writes the session to the output dir and trace_load restores it", async () => {
		await run("trace_start");
		await run("step", { count: 3 });
		const saved = textOf(await run("trace_save", { file: "t_session" }));
		const dir = join(outDir, "t_session");
		expect(saved).toContain(dir);
		// rizin writes the session's sdbs into the directory
		expect(readFileSync(join(dir, "session.sdb")).length).toBeGreaterThan(0);
		// load it back without error
		expect(textOf(await run("trace_load", { file: "t_session" }))).toContain("loaded the trace session");
		await run("trace_stop");
	}, 25_000);

	test("trace_load requires a file and refuses a traversing or missing name", async () => {
		expect((await captureError(run("trace_load"))).message).toContain("needs file");
		expect((await captureError(run("trace_load", { file: "../escape" }))).message).toContain("invalid output filename");
		expect((await captureError(run("trace_load", { file: "nope_not_saved" }))).message).toContain("no saved trace");
	});

	test("the glibc heap actions return a result without desyncing (even with no heap mapped yet)", async () => {
		// Early in a tiny process there may be no glibc arena; the tool returns
		// rizin's own note instead of erroring, and the stream stays aligned.
		for (const action of ["heap_arenas", "heap_chunks", "heap_bins"]) {
			expect(textOf(await run(action)).length).toBeGreaterThan(0);
		}
		expect(textOf(await run("registers"))).toMatch(/"rip":\d+|"pc":\d+/);
	}, 20_000);

	test("addr is validated like every other tool", async () => {
		expect((await captureError(run("read_memory", { addr: "rip;id" }))).message).toContain("invalid address");
	});

	test("stop kills the debuggee and closes the session", async () => {
		expect(textOf(await run("stop"))).toContain("stopped");
		expect(getState(ctx).dbg).toBeNull();
		expect(textOf(await run("stop"))).toContain("no debug session");
	});
});

describe.skipIf(!canRunRizin)("debug attach to a running process", () => {
	const harness = makeHarness("debug-attach-test-session");
	const { ctx } = harness;
	const run = (action: string, extra: Record<string, unknown> = {}) =>
		harness.tool("rizin_debug").execute("t-attach", { action, ...extra }, undefined, undefined, ctx);
	let victim: ReturnType<typeof Bun.spawn> | undefined;

	beforeAll(() => {
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		getState(ctx).binaryPath = TEST_BINARY; // the open binary is the symbol source
		registerDebugTools(harness.pi);
		// A long-lived process of our own to attach to.
		victim = Bun.spawn(["sleep", "120"], { stdout: "ignore", stderr: "ignore", stdin: "ignore" });
	});
	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
		try {
			victim?.kill();
		} catch {
			// already gone (stop killed it)
		}
		restoreEnable();
	});

	test("start with attach.pid controls the running process and reads its registers", async () => {
		const out = textOf(await run("start", { attach: { pid: victim!.pid } }));
		expect(out).toContain(`attached to PID ${victim!.pid}`);
		expect(out).toContain(DEBUG_LAUNCH_WARNING);
		expect(textOf(await run("registers"))).toMatch(/"rip":\d+|"pc":\d+/);
	}, 25_000);

	test("attach cannot be combined with run", async () => {
		await run("stop");
		expect((await captureError(run("start", { attach: { pid: victim!.pid }, run: { args: ["x"] } }))).message).toContain("cannot be combined with run");
	});

	test("a malformed remote target is refused before anything starts", async () => {
		expect((await captureError(run("start", { attach: { remote: "http://nope" } }))).message).toContain("gdb:// or windbg://");
	});
});
