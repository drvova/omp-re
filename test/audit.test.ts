import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import {
	RE_ALL_TOOL_NAMES,
	RE_MUTATE_TOOL_NAMES,
	RE_DEBUG_TOOL_NAMES,
	RE_ANALYZE_TOOL_NAMES,
	RE_EMULATE_TOOL_NAMES,
	RE_EVIDENCE_TOOL_NAMES,
	RE_FINDING_TOOL_NAMES,
	RE_SIGNATURE_TOOL_NAMES,
	RE_RIZIN_TOOL_NAMES,
	RE_RZCLI_TOOL_NAMES,
	RE_SESSION_TOOL_NAMES,
	RE_TRIAGE_TOOL_NAMES,
	registerAuditLog,
} from "../extensions/re/audit.ts";

describe("RE_ALL_TOOL_NAMES", () => {
	test("contains exactly 33 names and is the union of mutate (15), rizin (2), rizin CLI (1), triage (4), debug (1), emulate (1), signature (2), analyze (1), session (3), and finding (3)", () => {
		expect(Object.keys(RE_MUTATE_TOOL_NAMES)).toHaveLength(15);
		expect(Object.keys(RE_RIZIN_TOOL_NAMES)).toHaveLength(2);
		expect(Object.keys(RE_RZCLI_TOOL_NAMES)).toHaveLength(1);
		expect(Object.keys(RE_TRIAGE_TOOL_NAMES)).toHaveLength(4);
		expect(Object.keys(RE_DEBUG_TOOL_NAMES)).toHaveLength(1);
		expect(Object.keys(RE_EMULATE_TOOL_NAMES)).toHaveLength(1);
		expect(Object.keys(RE_SIGNATURE_TOOL_NAMES)).toHaveLength(2);
		expect(Object.keys(RE_ANALYZE_TOOL_NAMES)).toHaveLength(1);
		expect(Object.keys(RE_SESSION_TOOL_NAMES)).toHaveLength(3);
		expect(Object.keys(RE_FINDING_TOOL_NAMES)).toHaveLength(3);

		const allNames = Object.keys(RE_ALL_TOOL_NAMES);
		expect(allNames).toHaveLength(33);

		const expectedUnion = new Set([
			...Object.keys(RE_MUTATE_TOOL_NAMES),
			...Object.keys(RE_RIZIN_TOOL_NAMES),
			...Object.keys(RE_RZCLI_TOOL_NAMES),
			...Object.keys(RE_TRIAGE_TOOL_NAMES),
			...Object.keys(RE_DEBUG_TOOL_NAMES),
			...Object.keys(RE_EMULATE_TOOL_NAMES),
			...Object.keys(RE_SIGNATURE_TOOL_NAMES),
			...Object.keys(RE_ANALYZE_TOOL_NAMES),
			...Object.keys(RE_SESSION_TOOL_NAMES),
			...Object.keys(RE_FINDING_TOOL_NAMES),
		]);
		expect(new Set(allNames)).toEqual(expectedUnion);
	});

	test("rizin_command is the one observational tool that grounds evidence; the retired read tier is gone from every gate", () => {
		expect(RE_EVIDENCE_TOOL_NAMES.rizin_command).toBe(true);
		expect(Object.keys(RE_EVIDENCE_TOOL_NAMES)).toEqual(["rizin_command"]);
		for (const name of ["search_bytes", "list_types", "get_binary_info", "list_functions", "deobfuscate", "syscall_lookup"]) {
			expect(RE_EVIDENCE_TOOL_NAMES[name]).toBeUndefined();
			expect(RE_ALL_TOOL_NAMES[name]).toBeUndefined();
		}
	});

	test("the emulator, debugger, signature-apply, and analyze tools are audited and toggled by /re off, but never recorded as evidence", () => {
		for (const name of ["rizin_emulate", "rizin_debug", "apply_signatures", "analyze"]) {
			expect(RE_ALL_TOOL_NAMES[name]).toBe(true);
			expect(RE_EVIDENCE_TOOL_NAMES[name]).toBeUndefined();
		}
	});
});

type Handler = (event: Record<string, unknown>, ctx: ExtensionContext) => Promise<void>;

/** Captures the handlers registerAuditLog installs, plus whatever it logs through pi.logger, without a real ExtensionAPI. */
function captureHandlers(): { toolCall: Handler; approval: Handler; warnings: string[] } {
	const handlers = new Map<string, Handler>();
	const warnings: string[] = [];
	const fakePi = {
		on: (event: string, handler: Handler) => {
			handlers.set(event, handler);
		},
		logger: { warn: (msg: string) => warnings.push(msg), error: (msg: string) => warnings.push(msg) },
	} as unknown as ExtensionAPI;
	registerAuditLog(fakePi);
	const toolCall = handlers.get("tool_call");
	const approval = handlers.get("tool_approval_resolved");
	if (!toolCall || !approval) throw new Error("registerAuditLog did not register its handlers");
	return { toolCall, approval, warnings };
}

function makeCtx(sessionId: string, notifications: { message: string; type?: string }[]): ExtensionContext {
	return {
		hasUI: false,
		ui: {
			notify: (message: string, type?: string) => {
				notifications.push({ message, type });
			},
		},
		sessionManager: {
			getSessionId: () => sessionId,
		},
	} as unknown as ExtensionContext;
}

async function readAuditLines(sessionId: string): Promise<string[]> {
	const path = join(getAgentDir(), "re", "audit", `${sessionId}.log`);
	const raw = await readFile(path, "utf8");
	return raw
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l.length > 0);
}

describe("audit log", () => {
	let tempDir: string;
	let originalAgentDir: string;
	const originalHmacKey = process.env.OMPRE_AUDIT_HMAC_KEY;

	beforeEach(async () => {
		originalAgentDir = getAgentDir();
		tempDir = await mkdtemp(join(tmpdir(), "omp-re-audit-test-"));
		setAgentDir(tempDir);
	});

	afterEach(async () => {
		setAgentDir(originalAgentDir);
		await rm(tempDir, { recursive: true, force: true });
		if (originalHmacKey === undefined) delete process.env.OMPRE_AUDIT_HMAC_KEY;
		else process.env.OMPRE_AUDIT_HMAC_KEY = originalHmacKey;
	});

	test("with OMPRE_AUDIT_HMAC_KEY set, an appended line carries a non-empty hmac field that verifies", async () => {
		process.env.OMPRE_AUDIT_HMAC_KEY = "test-hmac-key";
		const sessionId = "audit-signed-session";
		const { toolCall: handler } = captureHandlers();
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx(sessionId, notifications);

		await handler({ type: "tool_call", toolCallId: "call-1", toolName: "rizin_command", input: { command: "aflj" } }, ctx);

		const lines = await readAuditLines(sessionId);
		expect(lines).toHaveLength(1);
		const parsed = JSON.parse(lines[0]!) as { hmac?: string; [key: string]: unknown };
		expect(typeof parsed.hmac).toBe("string");
		expect(parsed.hmac!.length).toBeGreaterThan(0);

		const { hmac, ...rest } = parsed;
		const expectedHmac = createHmac("sha256", "test-hmac-key").update(JSON.stringify(rest)).digest("base64");
		expect(hmac).toBe(expectedHmac);
	});

	test("with the key unset, lines are still written and the warning fires exactly once per session", async () => {
		delete process.env.OMPRE_AUDIT_HMAC_KEY;
		const sessionId = "audit-unsigned-session";
		const { toolCall: handler, warnings } = captureHandlers();
		const notifications: { message: string; type?: string }[] = [];
		const ctx = makeCtx(sessionId, notifications);

		await handler({ type: "tool_call", toolCallId: "call-1", toolName: "rizin_command", input: {} }, ctx);
		await handler({ type: "tool_call", toolCallId: "call-2", toolName: "rename_function", input: {} }, ctx);
		await handler({ type: "tool_call", toolCallId: "call-3", toolName: "set_comment", input: {} }, ctx);

		const lines = await readAuditLines(sessionId);
		expect(lines).toHaveLength(3);
		for (const line of lines) {
			const parsed = JSON.parse(line) as { hmac?: string };
			expect(parsed.hmac).toBeUndefined();
		}

		// Headless: the one-time warning goes to omp's log, not stdout/stderr.
		expect(warnings.filter((msg) => msg.includes("OMPRE_AUDIT_HMAC_KEY not configured"))).toHaveLength(1);
	});

	test("non-RE tool calls are not audited", async () => {
		const sessionId = "audit-non-re-session";
		const { toolCall: handler } = captureHandlers();
		const ctx = makeCtx(sessionId, []);
		await handler({ type: "tool_call", toolCallId: "call-1", toolName: "bash", input: { command: "ls" } }, ctx);
		await handler({ type: "tool_call", toolCallId: "call-2", toolName: "rizin_command", input: {} }, ctx);
		expect((await readAuditLines(sessionId)).map((l) => (JSON.parse(l) as { tool: string }).tool)).toEqual(["rizin_command"]);
	});

	test("an approval decision for an RE tool is recorded next to its call", async () => {
		const sessionId = "audit-approval-session";
		const { approval } = captureHandlers();
		const ctx = makeCtx(sessionId, []);
		await approval(
			{ type: "tool_approval_resolved", sessionId, toolCallId: "call-9", toolName: "rename_function", approved: false, reason: "user denied" },
			ctx,
		);
		await approval({ type: "tool_approval_resolved", sessionId, toolCallId: "call-10", toolName: "bash", approved: true }, ctx);
		const lines = (await readAuditLines(sessionId)).map((l) => JSON.parse(l) as Record<string, unknown>);
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({ toolCallId: "call-9", tool: "rename_function", approved: false, reason: "user denied" });
	});
});
