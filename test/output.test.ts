import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { outputDir, prepareOutputPath, safeBasename } from "../extensions/re/output.ts";

describe("safeBasename", () => {
	test("accepts bare names of safe characters", () => {
		for (const name of ["dump.bin", "a_b-c.1", "payload", "x.0x4000.bin"]) {
			expect(safeBasename(name)).toBe(name);
		}
	});

	test("rejects separators, traversal, absolute paths, and empties", () => {
		for (const bad of ["../etc/passwd", "a/b", "a\\b", "/abs", "..", ".", "", "  ", "na me", "a;b", "`id`"]) {
			expect(() => safeBasename(bad)).toThrow(/invalid output filename/);
		}
	});
});

describe("prepareOutputPath", () => {
	let dir: string;
	beforeAll(() => {
		dir = mkdtempSync(join(tmpdir(), "omp-re-out-test-"));
		process.env.OMPRE_OUTPUT_DIR = dir;
	});
	afterAll(() => {
		delete process.env.OMPRE_OUTPUT_DIR;
		rmSync(dir, { recursive: true, force: true });
	});

	test("honors OMPRE_OUTPUT_DIR and returns a path inside it, creating the dir", async () => {
		expect(outputDir()).toBe(dir);
		const path = await prepareOutputPath("dump.bin");
		expect(path).toBe(join(dir, "dump.bin"));
		expect(existsSync(dir)).toBe(true);
	});

	test("refuses a name that escapes the directory before any write", async () => {
		await expect(prepareOutputPath("../escape.bin")).rejects.toThrow(/invalid output filename/);
		await expect(prepareOutputPath("sub/escape.bin")).rejects.toThrow(/invalid output filename/);
	});
});
