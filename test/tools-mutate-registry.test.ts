/**
 * Coverage for the 5 mutate-tier tools and `/re undo`, against real rizin.
 *
 * Every case asserts real success plus an independent read-back via raw
 * rz.cmd/cmdj (bypassing the tool's own verification), so a regression in a
 * command template fails here even if the tool's self-check were also wrong.
 * Tests share one rizin process and undo their own mutation before the next
 * block runs. Targets are picked from whatever the fixture contains (default
 * /bin/ls): `main`, its first local variable, and its first instruction.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { liveAnnotations } from "../extensions/re/annotations.ts";
import { addrOf, eaFromOffset, RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { ensureRizin, getState, shutdownState } from "../extensions/re/state.ts";
import { registerMutateTools, undoLastAnnotation } from "../extensions/re/tools-mutate.ts";
import { canRunRizin, captureError, logSkip, makeHarness, rizinPath, TEST_BINARY, textOf } from "./helpers.ts";

logSkip("tools-mutate-registry tests");

interface AfvlVar {
	name: string;
	type: string;
}

describe.skipIf(!canRunRizin)("mutate tool registry + undo coverage", () => {
	const harness = makeHarness("omp-re-tools-mutate-registry-test");
	const { pi, ctx, entries } = harness;
	const run = (name: string, params: Record<string, unknown>) => harness.tool(name).execute(`call-${name}`, params, undefined, undefined, ctx);
	let rz: RzSession;
	let binaryPath: string;
	let mainEa: string;
	let mainName: string;
	let firstVar: AfvlVar;

	async function vars(): Promise<AfvlVar[]> {
		const grouped = (await rz.cmdj<Record<string, AfvlVar[]>>(`afvlj @ ${mainEa}`)) ?? {};
		return Object.values(grouped).flat();
	}
	const fnName = async (): Promise<string | undefined> => (await rz.cmdj<{ name: string }[]>(`afij @ ${mainEa}`))?.[0]?.name;

	registerMutateTools(pi);

	beforeAll(async () => {
		binaryPath = await resolveBinaryPath(TEST_BINARY);
		entries.push({ type: "custom", id: "bin-0", customType: "re.binary", data: { path: binaryPath } });
		rz = await RzSession.spawn(rizinPath, binaryPath);
		const state = getState(ctx);
		state.binaryPath = binaryPath;
		state.rz = rz;
		const main = (await rz.cmdj<{ offset: number; name: string }[]>("afij @ main"))![0]!;
		mainEa = eaFromOffset(addrOf(main)!);
		mainName = main.name;
		const all = await vars();
		if (all.length === 0) throw new Error(`fixture ${TEST_BINARY}: main has no variables to rename`);
		firstVar = all[0]!;
	});

	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	test("every mutate tool declares write approval with a per-call reason", () => {
		for (const name of ["rename_function", "rename_variable", "set_comment", "set_prototype", "set_variable_type"]) {
			const approval = harness.tool(name).approval as (args: unknown) => { tier: string; reason?: string };
			expect(typeof approval).toBe("function");
			const decision = approval({ addr: "main", new: "x", old: "y", text: "t", sig: "int f(void)", var: "v", type: "int" });
			expect(decision.tier).toBe("write");
			expect(decision.reason).toContain("main");
		}
	});

	describe("rename_function", () => {
		test("an invalid name throws the validateIdent literal before touching rizin", async () => {
			expect((await captureError(run("rename_function", { addr: "main", new: "1bad" }))).message).toBe('omp-re: invalid new: "1bad"');
		});

		test("lands, is keyed on the function's start ea, records an annotation, and /re undo reverts it", async () => {
			const result = await run("rename_function", { addr: "main", new: "omp_re_main" });
			expect(textOf(result)).toBe(`rename_function: ${JSON.stringify(mainName)} -> "omp_re_main" @ ${mainEa}`);
			expect(await fnName()).toBe("omp_re_main");

			const live = liveAnnotations(entries as never, binaryPath);
			expect(live.at(-1)?.data).toMatchObject({ kind: "rename_function", ea: mainEa, oldValue: mainName, newValue: "omp_re_main", ungrounded: true });

			expect(await undoLastAnnotation(pi, ctx)).toBe(`omp-re: undid rename_function @ ${mainEa} (restored ${JSON.stringify(mainName)})`);
			expect(await fnName()).toBe(mainName);
			expect(liveAnnotations(entries as never, binaryPath)).toHaveLength(0);
		});
	});

	describe("rename_variable", () => {
		test("a malformed new name throws the validateIdent literal before touching rizin", async () => {
			expect((await captureError(run("rename_variable", { addr: "main", old: firstVar.name, new: "1bad" }))).message).toBe(
				'omp-re: invalid new: "1bad"',
			);
		});

		test("an unknown variable is reported with the variables that do exist", async () => {
			const err = await captureError(run("rename_variable", { addr: "main", old: "no_such_var", new: "x" }));
			expect(err.message).toContain('has no variable "no_such_var"');
			expect(err.message).toContain(firstVar.name);
		});

		test("lands, independently verified, and /re undo reverts it", async () => {
			const result = await run("rename_variable", { addr: "main", old: firstVar.name, new: "omp_re_var" });
			expect(textOf(result)).toBe(`rename_variable: ${JSON.stringify(firstVar.name)} -> "omp_re_var" @ ${mainEa}`);
			const after = (await vars()).map((v) => v.name);
			expect(after).toContain("omp_re_var");
			expect(after).not.toContain(firstVar.name);

			await undoLastAnnotation(pi, ctx);
			const reverted = (await vars()).map((v) => v.name);
			expect(reverted).toContain(firstVar.name);
			expect(reverted).not.toContain("omp_re_var");
		});
	});

	describe("set_comment", () => {
		test("replaces rather than appends, independently verified via CC.", async () => {
			await run("set_comment", { addr: mainEa, text: "first" });
			await run("set_comment", { addr: mainEa, text: "second" });
			expect((await rz.cmd(`CC. @ ${mainEa}`)).trim()).toBe("second");
		});

		test("rizin metacharacters in the text are stored literally and execute nothing", async () => {
			const text = "x; echo INJECTED @ 0x0 ~ | > out `y` $(z) #";
			const result = await run("set_comment", { addr: mainEa, text });
			expect(textOf(result)).not.toContain("INJECTED\n");
			expect((await rz.cmd(`CC. @ ${mainEa}`)).trim()).toBe(text);
		});

		test("multi-line text is rejected", async () => {
			expect((await captureError(run("set_comment", { addr: mainEa, text: "a\nb" }))).message).toBe(
				"omp-re: invalid text: contains forbidden character",
			);
		});

		test("/re undo steps back through comment history, then clears", async () => {
			await undoLastAnnotation(pi, ctx);
			expect((await rz.cmd(`CC. @ ${mainEa}`)).trim()).toBe("second");
			await undoLastAnnotation(pi, ctx);
			expect((await rz.cmd(`CC. @ ${mainEa}`)).trim()).toBe("first");
			await undoLastAnnotation(pi, ctx);
			expect((await rz.cmd(`CC. @ ${mainEa}`)).trim()).toBe("");
		});
	});

	describe("set_prototype", () => {
		test("lands (tolerating rizin's trailing ;), and /re undo restores the old signature", async () => {
			const before = (await rz.cmd(`afs @ ${mainEa}`)).trim();
			const sig = `int ${mainName}(int argc, char **argv)`;
			const result = await run("set_prototype", { addr: mainEa, sig });
			expect(textOf(result)).toContain(`-> ${JSON.stringify(sig)} @ ${mainEa}`);
			expect((await rz.cmd(`afs @ ${mainEa}`)).trim()).toBe(`${sig};`);

			await undoLastAnnotation(pi, ctx);
			expect((await rz.cmd(`afs @ ${mainEa}`)).trim()).toBe(before);
		});

		test("a forbidden character is rejected before touching rizin", async () => {
			expect((await captureError(run("set_prototype", { addr: mainEa, sig: "int f(void); !id" }))).message).toBe(
				'omp-re: invalid sig: forbidden character ";"',
			);
		});
	});

	describe("set_variable_type", () => {
		test("lands, independently verified, and /re undo restores the old type", async () => {
			const result = await run("set_variable_type", { addr: mainEa, var: firstVar.name, type: "char *" });
			expect(textOf(result)).toBe(`set_variable_type: ${firstVar.name}: ${JSON.stringify(firstVar.type)} -> "char *" @ ${mainEa}`);
			expect((await vars()).find((v) => v.name === firstVar.name)?.type).toBe("char *");

			await undoLastAnnotation(pi, ctx);
			expect((await vars()).find((v) => v.name === firstVar.name)?.type).toBe(firstVar.type);
		});
	});

	describe("annotation replay", () => {
		test("a rename survives the rizin process dying: the respawn replays it", async () => {
			await run("rename_function", { addr: mainEa, new: "omp_re_survivor" });
			rz.close();
			rz = await ensureRizin(ctx);
			expect(await fnName()).toBe("omp_re_survivor");

			await undoLastAnnotation(pi, ctx);
			expect(await fnName()).toBe(mainName);
		});

		test("nothing is left to undo once every annotation is reverted", async () => {
			expect((await captureError(undoLastAnnotation(pi, ctx))).message).toBe("omp-re: no annotation left to undo");
		});
	});
});
