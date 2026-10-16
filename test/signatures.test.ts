/**
 * apply_signatures (FLIRT) against real rizin, plus the custom-file replay.
 *
 * A minimal FLIRT `.pat` is built from the fixture's own `main` bytes so the
 * application matches exactly one function and creates the observable
 * `flirt.*` flag rizin uses — letting the test assert the apply landed and
 * that it is re-applied after the rizin process dies (resume/crash).
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordedSignatures } from "../extensions/re/entries.ts";
import { addrOf, eaFromOffset, RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { registerSignatureTools } from "../extensions/re/tools-signatures.ts";
import { ensureRizin, getState, shutdownState } from "../extensions/re/state.ts";
import { canRunRizin, captureError, logSkip, makeHarness, rizinPath, TEST_BINARY, textOf } from "./helpers.ts";

logSkip("signatures tests");

describe.skipIf(!canRunRizin)("apply_signatures (chapter D)", () => {
	const harness = makeHarness("omp-re-signatures-test");
	const { pi, ctx, entries } = harness;
	const run = (params: Record<string, unknown>) => harness.tool("apply_signatures").execute("call-apply", params, undefined, undefined, ctx);
	let rz: RzSession;
	let binaryPath: string;
	let dir: string;
	let pat: string;
	let mainEa: string;

	const flirtFlagExists = async (): Promise<boolean> => (await rz.cmd("fl~omp_re_sig_main")).trim() !== "";

	registerSignatureTools(pi);

	beforeAll(async () => {
		binaryPath = await resolveBinaryPath(TEST_BINARY);
		entries.push({ type: "custom", id: "bin-0", customType: "re.binary", data: { path: binaryPath } });
		rz = await RzSession.spawn(rizinPath, binaryPath);
		getState(ctx).binaryPath = binaryPath;
		getState(ctx).rz = rz;
		mainEa = eaFromOffset(addrOf((await rz.cmdj<{ offset: number }[]>("afij @ main"))![0]! as never)!);

		// A minimal FLIRT .pat matching main's first 16 bytes: <32 nibbles> <crc-len> <crc16> <len> :<off> <name>.
		const bytes = (await rz.cmd(`p8 32 @ ${mainEa}`)).trim().toUpperCase();
		dir = mkdtempSync(join(tmpdir(), "omp-re-sig-"));
		pat = join(dir, "fixture.pat");
		writeFileSync(pat, `${bytes.slice(0, 32)} 00 0000 0020 :0000 omp_re_sig_main\n---\n`);
	});

	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
		rmSync(dir, { recursive: true, force: true });
	});

	test("source 'sigdb' re-applies the built-in database and reports the function count", async () => {
		const result = await run({ source: "sigdb" });
		expect(textOf(result)).toMatch(/Re-applied the built-in signature database\. Functions: \d+ before, \d+ after\./);
	});

	test("source 'file' applies a custom .pat, is recorded, and creates rizin's flirt flag", async () => {
		const result = await run({ source: "file", path: pat });
		expect(textOf(result)).toMatch(/Applied \d+ FLIRT signature\(s\)/);
		expect(await flirtFlagExists()).toBe(true);
		// Recorded for replay, scoped to this binary.
		expect(recordedSignatures(entries as never, binaryPath)).toContain(pat);
	});

	test("source 'file' without a path is rejected", async () => {
		expect((await captureError(run({ source: "file" }))).message).toContain("needs a path");
	});

	test("the applied custom signature survives the rizin process dying: the respawn re-applies it", async () => {
		// The flag exists now; kill the process and let ensureRizin respawn + replay from the branch.
		expect(await flirtFlagExists()).toBe(true);
		rz.close();
		rz = await ensureRizin(ctx);
		expect(await flirtFlagExists()).toBe(true);
	});
});
