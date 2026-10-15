/**
 * The rizin CLI-suite bridge (tools-rzcli.ts): the flag policy checked purely
 * (no binaries needed), then the `rizin_cli` tool run against the real `rz-*`
 * executables that ship with rizin.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { access, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BINARY_PLACEHOLDER, checkRzCli, type RzCliToolDef, RZ_CLI_TOOLS, registerRzCliTools } from "../extensions/re/tools-rzcli.ts";

import { getState, shutdownState } from "../extensions/re/state.ts";
import { captureError, canRunRizin, isRzToolAvailable, logSkip, makeHarness, TEST_BINARY, textOf } from "./helpers.ts";

logSkip("rizin CLI (rz-*) tests");

const def = (tool: string): RzCliToolDef => {
	const found = RZ_CLI_TOOLS.find((d) => d.tool === tool);
	if (!found) throw new Error(`no such rz-cli tool def: ${tool}`);
	return found;
};

function refusal(tool: string, args: string[]): string {
	const check = checkRzCli(def(tool), args);
	if (check.ok) throw new Error(`expected ${tool} ${args.join(" ")} to be refused`);
	return check.reason;
}

describe("checkRzCli (no binaries needed)", () => {
	test("allows ordinary read-only invocations", () => {
		expect(checkRzCli(def("rz-bin"), ["-I", "-j"])).toEqual({ ok: true });
		expect(checkRzCli(def("rz-bin"), ["-c"])).toEqual({ ok: true }); // -c (classes) is NOT the denied -C (create)
		expect(checkRzCli(def("rz-asm"), ["-a", "x86", "-b", "64", "-o", "0x1000", "-d", "90"])).toEqual({ ok: true }); // -o here is start address, allowed
		expect(checkRzCli(def("rz-hash"), ["-a", "sha256,entropy", BINARY_PLACEHOLDER])).toEqual({ ok: true });
		expect(checkRzCli(def("rz-diff"), ["-t", "functions", "a", "b"])).toEqual({ ok: true });
		expect(checkRzCli(def("rz-ax"), ["0xdead"])).toEqual({ ok: true });
	});

	test("refuses flags that execute code", () => {
		expect(refusal("rz-find", ["-E", "id", "f"])).toContain("rz-find -E");
		expect(refusal("rz-find", ["-R", "w0", "f"])).toContain("rz-find -R");
		expect(refusal("rz-find", ["-jR", "w0", "f"])).toContain("rz-find -R"); // hidden in a short cluster
		expect(refusal("rz-diff", ["-t", "command", "a", "b"])).toContain("executes commands");
		expect(refusal("rz-diff", ["-t", "commands", "a", "b"])).toContain("executes commands");
	});

	test("refuses flags that write files", () => {
		expect(refusal("rz-bin", ["-O", "d/s/1"])).toContain("rz-bin -O");
		expect(refusal("rz-bin", ["-o", "/tmp/x"])).toContain("rz-bin -o");
		expect(refusal("rz-bin", ["-C", "elf:90:"])).toContain("rz-bin -C");
		expect(refusal("rz-asm", ["-O", "/tmp/out", "nop"])).toContain("rz-asm -O");
	});

	test("refuses network fetch and interactive views", () => {
		expect(refusal("rz-bin", ["-dd"])).toContain("rz-bin -dd");
		expect(refusal("rz-bin", ["-PP"])).toContain("rz-bin -PP");
		expect(checkRzCli(def("rz-bin"), ["-d"])).toEqual({ ok: true }); // -d (local dwarf) is allowed; only the doubled -dd fetches over the network
		expect(refusal("rz-diff", ["-H", "a", "b"])).toContain("rz-diff -H");
		expect(refusal("rz-diff", ["-S", "80x25", "a", "b"])).toContain("rz-diff -S");
	});

	test("refuses newlines and NUL in an argument", () => {
		expect(refusal("rz-ax", ["0x1\n0x2"])).toContain("line break or NUL");
		expect(refusal("rz-ax", ["a\0b"])).toContain("line break or NUL");
	});
});

const harness = makeHarness("rzcli-test-session");
const { ctx } = harness;
const run = (tool: string, args: string[]) => harness.tool("rizin_cli").execute("t-cli", { tool, args }, undefined, undefined, ctx);

describe.skipIf(!canRunRizin || !isRzToolAvailable("rz-bin"))("rizin_cli against the real rz-* tools", () => {
	beforeAll(async () => {
		getState(ctx).binaryPath = TEST_BINARY;
		await registerRzCliTools(harness.pi);
	});
	afterAll(() => shutdownState(ctx.sessionManager.getSessionId()));

	test("is exec-tier with the full command line in the reason", () => {
		const approval = harness.tool("rizin_cli").approval as (a: unknown) => { tier: string; reason: string };
		expect(approval({ tool: "rz-ax", args: ["0xdead"] })).toEqual({ tier: "exec", reason: 'Run "rz-ax 0xdead".' });
	});

	test("rz-ax converts without touching any file", async () => {
		expect(textOf(await run("rz-ax", ["0xdead"]))).toBe("rz-ax 0xdead\n57005");
	});

	test("rz-bin reports info on the open binary (@binary auto-appended)", async () => {
		const out = textOf(await run("rz-bin", ["-I", "-j"]));
		expect(out).toContain(TEST_BINARY);
		expect(out).toContain('"bintype"');
	});

	test("@binary is substituted in place for tools that take explicit files", async () => {
		const out = textOf(await run("rz-hash", ["-a", "sha256", BINARY_PLACEHOLDER]));
		expect(out).toContain(TEST_BINARY);
		expect(out).toMatch(/sha256: [0-9a-f]{64}/);
	});

	test("rz-asm disassembles a hexpair string", async () => {
		expect(textOf(await run("rz-asm", ["-a", "x86", "-b", "64", "-d", "4889e5"]))).toContain("mov rbp, rsp");
	});

	test("a refused flag never spawns the tool", async () => {
		const marker = join(tmpdir(), `ompre-rzcli-should-not-exist-${process.pid}`);
		const err = await captureError(run("rz-bin", ["-O", `d/s/${marker}`, "-o", marker]));
		expect(err.message).toContain("rz-bin -O");
		await expect(access(marker)).rejects.toThrow();
		await rm(marker, { force: true });
	});
});
