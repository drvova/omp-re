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
		for (const name of ["rename_function", "rename_variable", "set_comment", "set_prototype", "set_variable_type", "define_function", "set_calling_convention", "set_flag", "set_arch_hint"]) {
			const approval = harness.tool(name).approval as (args: unknown) => { tier: string; reason?: string };
			expect(typeof approval).toBe("function");
			const decision = approval({ addr: "main", new: "x", old: "y", text: "t", sig: "int f(void)", var: "v", type: "int", cc: "ms", name: "lbl", arch: "arm", bits: 16 });
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

describe.skipIf(!canRunRizin)("analysis-edit mutate tools (chapter C): define_function, set_calling_convention, set_flag", () => {
	const harness = makeHarness("omp-re-tools-analysis-edit-test");
	const { pi, ctx, entries } = harness;
	const run = (name: string, params: Record<string, unknown>) => harness.tool(name).execute(`call-${name}`, params, undefined, undefined, ctx);
	let rz: RzSession;
	let binaryPath: string;
	let mainEa: string;
	let freeEa: string; // an address with no flag, for set_flag

	const fnStart = async (ea: string): Promise<string | undefined> => {
		const fn = (await rz.cmdj<{ offset: number }[]>(`afij @ ${ea}`))?.[0];
		return fn ? eaFromOffset(addrOf(fn as never)!) : undefined;
	};
	const flagName = async (ea: string): Promise<string> => (await rz.cmdj<{ name?: string }>(`fdj @ ${ea}`))?.name ?? "";
	const ccOf = async (ea: string): Promise<string> => (await rz.cmd(`afc @ ${ea}`)).trim();

	registerMutateTools(pi);

	beforeAll(async () => {
		binaryPath = await resolveBinaryPath(TEST_BINARY);
		entries.push({ type: "custom", id: "bin-0", customType: "re.binary", data: { path: binaryPath } });
		rz = await RzSession.spawn(rizinPath, binaryPath);
		const state = getState(ctx);
		state.binaryPath = binaryPath;
		state.rz = rz;
		mainEa = eaFromOffset(addrOf((await rz.cmdj<{ offset: number }[]>("afij @ main"))![0]! as never)!);
		// First address at or after main with no flag — set_flag's clean add/remove path.
		const base = Number.parseInt(mainEa, 16);
		freeEa = mainEa;
		for (let off = 1; off <= 512; off++) {
			const cand = eaFromOffset(base + off);
			if ((await flagName(cand)) === "") {
				freeEa = cand;
				break;
			}
		}
	});

	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	test("set_calling_convention lands, independently verified, and /re undo restores the old one", async () => {
		const before = await ccOf(mainEa);
		const target = before === "ms" ? "amd64" : "ms"; // any other listed cc
		const result = await run("set_calling_convention", { addr: "main", cc: target });
		expect(textOf(result)).toBe(`set_calling_convention: ${JSON.stringify(before)} -> ${JSON.stringify(target)} @ ${mainEa}`);
		expect(await ccOf(mainEa)).toBe(target);
		expect(liveAnnotations(entries as never, binaryPath).at(-1)?.data).toMatchObject({ kind: "set_calling_convention", ea: mainEa, oldValue: before, newValue: target });

		await undoLastAnnotation(pi, ctx);
		expect(await ccOf(mainEa)).toBe(before);
	});

	test("set_calling_convention rejects an unknown convention with rizin's own error", async () => {
		const err = await captureError(run("set_calling_convention", { addr: "main", cc: "nonexistent_cc" }));
		expect(err.message).toContain("set_calling_convention");
		// the function's convention is unchanged
		expect(await ccOf(mainEa)).not.toBe("nonexistent_cc");
	});

	test("set_flag adds a named label, independently verified, and /re undo removes it", async () => {
		const old = await flagName(freeEa);
		const result = await run("set_flag", { addr: freeEa, name: "omp_re_label" });
		expect(textOf(result)).toBe(`set_flag: ${JSON.stringify(old)} -> "omp_re_label" @ ${freeEa}`);
		expect(await flagName(freeEa)).toBe("omp_re_label");

		await undoLastAnnotation(pi, ctx);
		expect(await flagName(freeEa)).toBe(old);
	});

	test("set_arch_hint sets an arch/bits hint (Thumb), independently verified, and /re undo removes it", async () => {
		const hintAt = async (ea: string): Promise<{ arch?: string; bits?: number } | undefined> => (await rz.cmdj<{ arch?: string; bits?: number }[]>(`ahl.j @ ${ea}`))?.[0];
		expect(await hintAt(mainEa)).toBeUndefined();
		const result = await run("set_arch_hint", { addr: "main", arch: "arm", bits: 16 });
		expect(textOf(result)).toBe(`set_arch_hint: "" -> "arch=arm;bits=16" @ ${mainEa}`);
		expect(await hintAt(mainEa)).toMatchObject({ arch: "arm", bits: 16 });

		await undoLastAnnotation(pi, ctx);
		expect(await hintAt(mainEa)).toBeUndefined();
	});

	test("define_function creates a function where rizin missed one, and /re undo removes it", async () => {
		// Undefine main to create the gap, define it back through the tool, verify, undo, then restore main for anyone else.
		await rz.cmd(`af- @ ${mainEa}`);
		expect(await fnStart(mainEa)).not.toBe(mainEa);

		const result = await run("define_function", { addr: mainEa });
		expect(textOf(result)).toContain(`@ ${mainEa}`);
		expect(await fnStart(mainEa)).toBe(mainEa);
		expect(liveAnnotations(entries as never, binaryPath).at(-1)?.data).toMatchObject({ kind: "define_function", ea: mainEa, oldValue: "" });

		await undoLastAnnotation(pi, ctx);
		expect(await fnStart(mainEa)).not.toBe(mainEa);
	});

	test("define_function refuses when a function already begins at the address", async () => {
		await rz.cmd(`af @ ${mainEa}`); // ensure one exists
		const err = await captureError(run("define_function", { addr: mainEa }));
		expect(err.message).toContain("already begins at");
	});

	test("a defined function survives the rizin process dying: the respawn replays it", async () => {
		// Pick a second function, undefine it, define through the tool, then crash+respawn.
		const fns = (await rz.cmdj<{ offset: number }[]>("aflj"))!;
		const victim = eaFromOffset(fns.map((f) => f.offset).find((o) => eaFromOffset(o) !== mainEa)!);
		await rz.cmd(`af- @ ${victim}`);
		await run("define_function", { addr: victim });
		expect(await fnStart(victim)).toBe(victim);

		rz.close();
		rz = await ensureRizin(ctx);
		expect(await fnStart(victim)).toBe(victim);
		await undoLastAnnotation(pi, ctx);
	});
});
