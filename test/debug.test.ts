/**
 * The opt-in debugger (tools-debug.ts). The enable gate is pure; the full
 * drive — launch, breakpoint, continue, step, inspect, stop — runs against a
 * real rizin debug session on the fixture (which it executes), and is skipped
 * when rizin or the fixture is missing.
 */
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { DEBUG_LAUNCH_WARNING, buildRunDirectives, debuggerEnabled, registerDebugTools } from "../extensions/re/tools-debug.ts";
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

	beforeAll(() => {
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		getState(ctx).binaryPath = TEST_BINARY;
		registerDebugTools(harness.pi);
	});
	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
		restoreEnable();
	});

	test("every action is exec-tier, with execution called out for resumes", () => {
		const approval = harness.tool("rizin_debug").approval as (a: unknown) => { tier: string; reason: string };
		expect(approval({ action: "start" })).toEqual({ tier: "exec", reason: expect.stringContaining("EXECUTES it") });
		expect(approval({ action: "continue" }).reason).toContain("Resume execution");
		expect(approval({ action: "registers" }).reason).toContain("Inspect");
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

	test("addr is validated like every other tool", async () => {
		expect((await captureError(run("read_memory", { addr: "rip;id" }))).message).toContain("invalid address");
	});

	test("stop kills the debuggee and closes the session", async () => {
		expect(textOf(await run("stop"))).toContain("stopped");
		expect(getState(ctx).dbg).toBeNull();
		expect(textOf(await run("stop"))).toContain("no debug session");
	});
});
