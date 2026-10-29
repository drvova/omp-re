/**
 * Compaction preservation (preserve.ts): the snapshot folded into a summary
 * so the post-compaction model stays grounded. Pure — no rizin needed.
 */
import { describe, expect, test } from "bun:test";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { preservedStateLines, registerPreservation } from "../extensions/re/preserve.ts";
import { getState, shutdownState, switchBinary } from "../extensions/re/state.ts";
import { makeHarness } from "./helpers.ts";

function withEvidence(h: ReturnType<typeof makeHarness>, items: { id: string; tool: string; ea?: string }[]): void {
	for (const it of items) h.pi.appendEntry("re.evidence", { ...it, summary: `${it.tool} output` });
}

describe("preservedStateLines", () => {
	test("is empty when no RE session is active", () => {
		const h = makeHarness("preserve-empty");
		expect(preservedStateLines(h.ctx)).toEqual([]);
		shutdownState("preserve-empty");
	});

	test("names the open binary, the counts, and the most recent evidence", () => {
		const h = makeHarness("preserve-active");
		switchBinary(h.ctx, "/usr/bin/ls");
		withEvidence(h, [
			{ id: "aaaaaaaa-1111", tool: "hash_binary" },
			{ id: "bbbbbbbb-2222", tool: "list_imports", ea: "0x1000" },
		]);
		const lines = preservedStateLines(h.ctx);
		const text = lines.join("\n");
		expect(text).toContain("omp-re reverse-engineering session");
		expect(text).toContain("Open binary: ls (/usr/bin/ls)");
		expect(text).toContain("2 evidence item(s)");
		expect(text).toContain("aaaaaaaa · hash_binary");
		expect(text).toContain("bbbbbbbb · list_imports @ 0x1000");
		expect(text).toContain("must still come from tool output");
		shutdownState("preserve-active");
	});

	test("restates live findings verbatim (not superseded or retracted ones) so the model doesn't re-derive them", () => {
		const h = makeHarness("preserve-findings");
		switchBinary(h.ctx, "/bin/ls");
		withEvidence(h, [{ id: "dddddddd-4444", tool: "rizin_command" }]);
		h.pi.appendEntry("re.finding", { id: "f1111111-x", claim: "checksum is djb2.", evidenceIds: ["dddddddd-4444"], addr: "sym.checksum", confidence: "confirmed" });
		h.pi.appendEntry("re.finding", { id: "f2222222-x", claim: "old claim", evidenceIds: ["dddddddd-4444"], confidence: "likely" });
		h.pi.appendEntry("re.finding.retract", { id: "f2222222-x", reason: "wrong" });
		h.pi.appendEntry("re.finding", { id: "f3333333-x", claim: "fib is iterative.", evidenceIds: ["dddddddd-4444"], confidence: "likely", inherited: { fromBinarySha256: null, fromFindingId: "z", carryStatus: "holds" } });
		const text = preservedStateLines(h.ctx).join("\n");
		expect(text).toContain("Recorded findings (2;");
		expect(text).toContain("f1111111 [confirmed] checksum is djb2. (at sym.checksum)");
		expect(text).toContain("f3333333 [likely, inherited] fib is iterative.");
		expect(text).not.toContain("old claim");
		shutdownState("preserve-findings");
	});

	test("caps the named evidence but still reports the full count", () => {
		const h = makeHarness("preserve-cap");
		switchBinary(h.ctx, "/bin/ls");
		withEvidence(
			h,
			Array.from({ length: 20 }, (_, i) => ({ id: `id${i.toString().padStart(6, "0")}-x`, tool: "list_functions" })),
		);
		const lines = preservedStateLines(h.ctx);
		expect(lines.join("\n")).toContain("20 evidence item(s)");
		// one header line + at most 8 named records
		const named = lines.filter((l) => l.trim().startsWith("·"));
		expect(named.length).toBe(8);
		expect(named.at(-1)).toContain("id000019");
		shutdownState("preserve-cap");
	});

	test("notes a session whose binary was closed but that recorded evidence", () => {
		const h = makeHarness("preserve-closed");
		withEvidence(h, [{ id: "cccccccc-3333", tool: "hash_binary" }]);
		const text = preservedStateLines(h.ctx).join("\n");
		expect(text).toContain("none currently open");
		shutdownState("preserve-closed");
	});
});

describe("registerPreservation", () => {
	test("registers a session.compacting handler that returns the snapshot only when active", async () => {
		let handler: ((event: unknown, ctx: ExtensionContext) => unknown) | undefined;
		const pi = {
			on: (event: string, h: (event: unknown, ctx: ExtensionContext) => unknown) => {
				if (event === "session.compacting") handler = h;
			},
		} as unknown as ExtensionAPI;
		registerPreservation(pi);
		expect(handler).toBeDefined();

		const active = makeHarness("preserve-handler-active");
		switchBinary(active.ctx, "/bin/ls");
		active.pi.appendEntry("re.evidence", { id: "dddddddd-4444", tool: "list_strings", summary: "s" });
		const result = (await handler!({ type: "session.compacting" }, active.ctx)) as { context?: string[] } | undefined;
		expect(result?.context?.join("\n")).toContain("Open binary: ls");
		shutdownState("preserve-handler-active");

		const idle = makeHarness("preserve-handler-idle");
		expect(await handler!({ type: "session.compacting" }, idle.ctx)).toBeUndefined();
		shutdownState("preserve-handler-idle");
	});
});
