/**
 * The opt-in debugger (tools-debug.ts). The enable gate is pure; the full
 * drive — launch, breakpoint, continue, step, inspect, stop — runs against a
 * real rizin debug session on the fixture (which it executes), and is skipped
 * when rizin or the fixture is missing.
 */
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { DEBUG_LAUNCH_WARNING, debuggerEnabled, registerDebugTools } from "../extensions/re/tools-debug.ts";
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
	});

	test("breakpoint, continue, and inspect the running process", async () => {
		expect(textOf(await run("break_add", { addr: "entry0" }))).toContain('"enabled":true');
		const cont = textOf(await run("continue"));
		expect(cont).toMatch(/rip = 0x[0-9a-f]+/);
		expect(textOf(await run("registers"))).toMatch(/"rip":\d+/);
		expect(textOf(await run("backtrace"))).toContain('"idx":0');
		expect(textOf(await run("break_list"))).toContain("addr");
	});

	test("step advances the PC and read_memory returns bytes at an address", async () => {
		const before = textOf(await run("registers"));
		await run("step", { count: 1 });
		const after = textOf(await run("registers"));
		expect(after).not.toBe(before);
		expect(textOf(await run("read_memory", { addr: "rip", size: 8 }))).toMatch(/^\[.*\]$/m);
	});

	test("addr is validated like every other tool", async () => {
		expect((await captureError(run("read_memory", { addr: "rip;id" }))).message).toContain("invalid address");
	});

	test("stop kills the debuggee and closes the session", async () => {
		expect(textOf(await run("stop"))).toContain("stopped");
		expect(getState(ctx).dbg).toBeNull();
		expect(textOf(await run("stop"))).toContain("no debug session");
	});
});
