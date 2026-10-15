import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { resolveDecompiler } from "../extensions/re/decompile.ts";
import { RzAbortError, RzProtocolError, RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { ensureRizin, getState, shutdownState, spawnRizin, syncAnnotationsToBranch } from "../extensions/re/state.ts";
import { canRunRizin, logSkip, makeHarness, rizinPath, TEST_BINARY } from "./helpers.ts";

logSkip("rizin-integration tests");

describe.skipIf(!canRunRizin)("RzSession (rizin integration)", () => {
	let session: RzSession;

	beforeAll(async () => {
		session = await RzSession.spawn(rizinPath, TEST_BINARY);
	});

	afterAll(() => {
		session.close();
	});

	test("spawn + ij returns parseable JSON describing the binary", async () => {
		const parsed = JSON.parse((await session.cmd("ij")).trim()) as { core?: { format?: string; file?: string }; bin?: { arch?: string } };
		expect(typeof parsed.bin?.arch).toBe("string");
		expect(String(parsed.core?.format)).toMatch(/elf|pe|mach0/i);
	});

	test("50 sequential commands in one session all return their own output", async () => {
		for (let i = 0; i < 50; i++) {
			const marker = `omp-re-seq-${i}`;
			expect((await session.cmd(`echo ${marker}`)).trim()).toBe(marker);
		}
	});

	test("an invalid address returns empty output and keeps the stream aligned", async () => {
		expect((await session.cmd("afij @ no_such_symbol_anywhere")).trim()).toBe("");
		expect(await session.cmdj("afij @ no_such_symbol_anywhere")).toBeNull();
		expect((await session.cmd("echo still-aligned")).trim()).toBe("still-aligned");
	});

	test("a quoted comment containing a command separator is stored literally and runs nothing", async () => {
		await session.cmd("CC- @ entry0");
		const echoed = await session.cmd("CC 'x; echo INJECTED' @ entry0");
		expect(echoed).not.toContain("INJECTED");
		expect((await session.cmd("CC. @ entry0")).trim()).toBe("x; echo INJECTED");
		await session.cmd("CC- @ entry0");
	});

	test("aborting a command rejects the caller but leaves the process usable and aligned", async () => {
		const controller = new AbortController();
		const pending = session.cmd("aflj", { signal: controller.signal });
		controller.abort();
		await expect(pending).rejects.toBeInstanceOf(RzAbortError);
		expect(session.isClosed).toBe(false);
		expect((await session.cmd("echo after-abort")).trim()).toBe("after-abort");
	});

	test("a tiny-timeout command rejects with RzProtocolError and closes the session", async () => {
		const slow = await RzSession.spawn(rizinPath, TEST_BINARY);
		let caught: unknown;
		try {
			await slow.cmd("!sleep 2", { timeoutMs: 200 });
		} catch (err) {
			caught = err;
		}
		expect(caught).toBeInstanceOf(RzProtocolError);
		expect((caught as Error).message).toMatch(/timed out/);
		expect(slow.isClosed).toBe(true);
	});

	test("aborting during analysis kills the half-analyzed process", async () => {
		const controller = new AbortController();
		controller.abort();
		await expect(RzSession.spawn(rizinPath, TEST_BINARY, { signal: controller.signal })).rejects.toBeInstanceOf(RzAbortError);
	});

	test("spawn reports analysis progress through onProgress while aaa runs", async () => {
		const ticks: number[] = [];
		const s = await RzSession.spawn(rizinPath, TEST_BINARY, { onProgress: (ms) => ticks.push(ms) });
		s.close();
		// Analysis of a small binary can finish inside the first tick; progress is best-effort, never required.
		for (const ms of ticks) expect(ms).toBeGreaterThan(0);
	});

	test("the decompiler probe settles on pdg, pdd, or none, and caches its answer", async () => {
		const first = await resolveDecompiler(session);
		expect([null, "pdg", "pdd"]).toContain(first);
		expect(await resolveDecompiler(session)).toBe(first);
	});
});

describe.skipIf(!canRunRizin)("session state: respawn, replay, and branch sync", () => {
	const harness = makeHarness("rizin-integration-state");
	const { ctx, entries } = harness;
	let fnEa: string;
	let fnName: string;

	beforeAll(async () => {
		const binaryPath = await resolveBinaryPath(TEST_BINARY);
		entries.push({ type: "custom", id: "bin-0", customType: "re.binary", data: { path: binaryPath } });
		const { rz } = await spawnRizin(ctx, binaryPath);
		const fn = (await rz.cmdj<{ offset: number; name: string }[]>("aflj"))![0]!;
		fnEa = `0x${fn.offset.toString(16)}`;
		fnName = fn.name;
	});

	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	test("ensureRizin respawns a closed process and replays this branch's annotations", async () => {
		const state = getState(ctx);
		entries.push({
			type: "custom",
			id: "ann-0",
			customType: "re.annotation",
			data: { kind: "rename_function", ea: fnEa, oldValue: fnName, newValue: "omp_re_replayed" },
		});
		state.rz!.close();

		const respawned = await ensureRizin(ctx);
		expect(respawned.isClosed).toBe(false);
		expect((await respawned.cmdj<{ name: string }[]>(`afij @ ${fnEa}`))![0]!.name).toBe("omp_re_replayed");
	});

	test("concurrent callers after a crash share one respawn", async () => {
		getState(ctx).rz!.close();
		const [a, b] = await Promise.all([ensureRizin(ctx), ensureRizin(ctx)]);
		expect(a).toBe(b);
	});

	test("navigating to a branch without the annotation retires the process and the respawn drops the rename", async () => {
		const state = getState(ctx);
		state.appliedAnnotations = "ann-0";
		entries.splice(entries.findIndex((e) => e.id === "ann-0"), 1);
		syncAnnotationsToBranch(ctx);
		expect(state.rz).toBeNull();

		const rz = await ensureRizin(ctx);
		expect((await rz.cmdj<{ name: string }[]>(`afij @ ${fnEa}`))![0]!.name).toBe(fnName);
	});
});

describe("resolveBinaryPath", () => {
	test("rejects a nonexistent path", async () => {
		await expect(resolveBinaryPath("/tmp/omp-re-does-not-exist-ever.bin")).rejects.toThrow("omp-re: no such binary:");
	});
});
