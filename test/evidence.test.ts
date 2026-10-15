import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { readBlob, rebuildEvidenceIndex, writeBlob } from "../extensions/re/evidence.ts";
import { getState } from "../extensions/re/state.ts";
import { makeHarness } from "./helpers.ts";

let tempDir: string;
let originalAgentDir: string;

beforeEach(async () => {
	originalAgentDir = getAgentDir();
	tempDir = await mkdtemp(join(tmpdir(), "omp-re-evidence-test-"));
	setAgentDir(tempDir);
});

afterEach(async () => {
	setAgentDir(originalAgentDir);
	await rm(tempDir, { recursive: true, force: true });
});

describe("writeBlob / readBlob", () => {
	test("round-trips content and returns a stable content-addressed hash", async () => {
		const content = "some evidence text";
		const hash = await writeBlob(content);
		expect(hash).toMatch(/^[0-9a-f]{64}$/);
		const read = await readBlob(hash);
		expect(read).toBe(content);
	});

	test("writing identical content twice is idempotent and yields the same hash", async () => {
		const content = "duplicate blob content";
		const hash1 = await writeBlob(content);
		const hash2 = await writeBlob(content);
		expect(hash1).toBe(hash2);
		expect(await readBlob(hash1)).toBe(content);
	});

	test("readBlob on an unknown hash returns null and does not throw", async () => {
		const unknownHash = "0".repeat(64);
		await expect(readBlob(unknownHash)).resolves.toBeNull();
	});
});

describe("rebuildEvidenceIndex", () => {
	test("indexes exactly the evidence on the current branch, latest id per address", () => {
		const { ctx, entries } = makeHarness("evidence-index-session");
		entries.push(
			{ type: "custom", id: "e1", customType: "re.evidence", data: { id: "ev-a", tool: "get_function", ea: "0x4DA0", summary: "" } },
			{ type: "custom", id: "e2", customType: "re.evidence", data: { id: "ev-b", tool: "decompile_function", ea: "0x4da0", summary: "" } },
			{ type: "custom", id: "e3", customType: "re.evidence", data: { id: "ev-c", tool: "list_imports", summary: "" } },
		);
		rebuildEvidenceIndex(ctx);
		const state = getState(ctx);
		expect(state.evidenceCount).toBe(3);
		expect(state.evidenceByAddr.get("0x4da0")).toBe("ev-b");

		// /tree navigation back to before the decompile: the index follows the branch.
		entries.splice(1);
		rebuildEvidenceIndex(ctx);
		expect(state.evidenceCount).toBe(1);
		expect(state.evidenceByAddr.get("0x4da0")).toBe("ev-a");
	});
});
