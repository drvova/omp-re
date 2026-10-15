/**
 * Audit trail for RE tool calls.
 *
 * Allow/deny/prompt is entirely omp's: every tool declares an `approval` tier
 * (with a per-call reason for the mutate and triage tools), and
 * `tools.approvalMode` / `tools.approval.<tool>` in the user's omp config
 * decide what happens. This module only observes: a `tool_call` handler that
 * always lets the call through and appends one (optionally HMAC-signed) JSON
 * line per RE tool call to a per-session log, plus one line per approval
 * decision omp reports for an RE tool, so operators keep a record of what the
 * RE suite did and who allowed it.
 */
import { createHmac } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import { getState } from "./state.ts";

/** The 12 read-tier RE tools (tools-read.ts). */
export const RE_READ_TOOL_NAMES: Record<string, true> = {
	list_functions: true,
	search_functions: true,
	get_function: true,
	decompile_function: true,
	disassemble_function: true,
	get_xrefs_to: true,
	get_xrefs_from: true,
	list_imports: true,
	list_exports: true,
	list_strings: true,
	list_segments: true,
	hash_binary: true,
};

/** The 5 write-tier annotation tools (tools-mutate.ts). */
export const RE_MUTATE_TOOL_NAMES: Record<string, true> = {
	rename_function: true,
	rename_variable: true,
	set_comment: true,
	set_prototype: true,
	set_variable_type: true,
};

/** The 4 exec-tier triage tools (tools-triage.ts). */
export const RE_TRIAGE_TOOL_NAMES: Record<string, true> = {
	triage_capa: true,
	triage_floss: true,
	triage_die: true,
	triage_yara: true,
};

/** The 2 rizin CLI bridge tools (tools-rizin.ts): `rizin_help` reads rizin's own documentation; `rizin_command` runs read-only rizin commands. */
export const RE_RIZIN_TOOL_NAMES: Record<string, true> = {
	rizin_help: true,
	rizin_command: true,
};

/** Tools whose successful output is an observation of the binary and becomes a `re.evidence` record (evidence.ts). `rizin_help` is not: help text says nothing about the binary. */
export const RE_EVIDENCE_TOOL_NAMES: Record<string, true> = {
	...RE_READ_TOOL_NAMES,
	rizin_command: true,
};

/** Session-setup tools that are neither analysis (no evidence to record — opening a binary asserts nothing about its contents) nor mutation, but still worth an audit-trail line. */
export const RE_SESSION_TOOL_NAMES: Record<string, true> = {
	open_binary: true,
};

/** All 24 RE-suite tool names (read + mutate + triage + rizin CLI + session-setup) — the audit log's gate. */
export const RE_ALL_TOOL_NAMES: Record<string, true> = {
	...RE_READ_TOOL_NAMES,
	...RE_MUTATE_TOOL_NAMES,
	...RE_TRIAGE_TOOL_NAMES,
	...RE_RIZIN_TOOL_NAMES,
	...RE_SESSION_TOOL_NAMES,
};

interface AuditLine {
	ts: string;
	sessionId: string;
	toolCallId: string;
	tool: string;
	/** Present on call lines. */
	args?: unknown;
	/** Present on approval lines: what omp's approval gate decided for this call. */
	approved?: boolean;
	reason?: string;
	/** Base64 HMAC-SHA256 over the JSON encoding of every other field, present only when OMPRE_AUDIT_HMAC_KEY is configured. */
	hmac?: string;
}

/**
 * Append one line to the current session's audit log. Never throws: a
 * serialization failure (unlikely — args come from schema-validated tool
 * params, but not impossible) or a filesystem error is reported via
 * `ctx.ui.notify` (or omp's log file when headless) and otherwise swallowed, because the audit
 * log is a mirror for operator review, not the source of truth — it must
 * never abort the tool call being audited.
 */
async function appendAuditLine(
	ctx: ExtensionContext,
	line: Omit<AuditLine, "ts" | "sessionId" | "hmac">,
	logger?: ExtensionAPI["logger"],
): Promise<void> {
	try {
		const state = getState(ctx);
		const dir = join(getAgentDir(), "re", "audit");
		const path = join(dir, `${state.sessionId}.log`);
		const base: Omit<AuditLine, "hmac"> = { ts: new Date().toISOString(), sessionId: state.sessionId, ...line };
		const canonicalJson = JSON.stringify(base);

		const hmacKey = process.env.OMPRE_AUDIT_HMAC_KEY;
		let text: string;
		if (hmacKey) {
			const hmac = createHmac("sha256", hmacKey).update(canonicalJson).digest("base64");
			text = `${JSON.stringify({ ...base, hmac })}\n`;
		} else {
			text = `${canonicalJson}\n`;
			if (!state.auditHmacWarned) {
				state.auditHmacWarned = true;
				const msg = "omp-re: OMPRE_AUDIT_HMAC_KEY not configured — audit log entries will not be signed.";
				if (ctx.hasUI) ctx.ui.notify(msg, "warning");
				else logger?.warn(msg);
			}
		}

		await mkdir(dir, { recursive: true, mode: 0o700 });
		const fh = await open(path, "a", 0o600);
		try {
			await fh.appendFile(text);
			// fsync the exact fd we just appended through, so the trail survives a crash immediately after this call.
			await fh.sync();
		} finally {
			await fh.close();
		}
	} catch (err) {
		const msg = `omp-re: audit log write failed: ${err instanceof Error ? err.message : String(err)}`;
		if (ctx.hasUI) ctx.ui.notify(msg, "error");
		else logger?.error(msg);
	}
}

/**
 * Register the RE audit trail: records every RE tool call (read + mutate +
 * triage + session setup) and every approval decision for one to a
 * per-session log. Never blocks — the handlers always return `undefined`.
 */
export function registerAuditLog(pi: ExtensionAPI): void {
	pi.on("tool_call", async (event, ctx) => {
		if (RE_ALL_TOOL_NAMES[event.toolName] !== true) return undefined;
		await appendAuditLine(ctx, { toolCallId: event.toolCallId, tool: event.toolName, args: event.input }, pi.logger);
		return undefined;
	});

	pi.on("tool_approval_resolved", async (event, ctx) => {
		if (RE_ALL_TOOL_NAMES[event.toolName] !== true) return;
		await appendAuditLine(
			ctx,
			{ toolCallId: event.toolCallId, tool: event.toolName, approved: event.approved, ...(event.reason ? { reason: event.reason } : {}) },
			pi.logger,
		);
	});
}
