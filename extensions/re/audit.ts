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

/**
 * Every read-tier RE tool — the ones registered with `approval: "read"`,
 * across tools-read.ts, tools-search.ts, tools-types.ts, tools-syscalls.ts,
 * and tools-info.ts. This list IS the read tier: it gates evidence recording
 * (RE_EVIDENCE_TOOL_NAMES), audit logging, and `/re off`/`/re on`, so a read
 * tool missing from it silently records no evidence, is never audited, and
 * isn't disabled by `/re off`. Keep it in sync as read tools are added.
 */
export const RE_READ_TOOL_NAMES: Record<string, true> = {
	// tools-read.ts
	list_functions: true,
	search_functions: true,
	get_function: true,
	decompile_function: true,
	disassemble_function: true,
	get_xrefs_to: true,
	get_xrefs_from: true,
	list_imports: true,
	list_exports: true,
	list_symbols: true,
	list_strings: true,
	list_segments: true,
	hash_binary: true,
	// tools-search.ts
	search_bytes: true,
	search_string: true,
	search_regex_bytes: true,
	search_asm: true,
	search_value: true,
	search_gadgets: true,
	// tools-types.ts
	list_types: true,
	define_types: true,
	cast_memory: true,
	// tools-syscalls.ts
	list_syscalls: true,
	syscall_lookup: true,
	// tools-info.ts
	get_binary_info: true,
	list_entrypoints: true,
	list_relocations: true,
	list_flags: true,
	list_classes: true,
	// tools-deobfuscate.ts
	deobfuscate: true,
};

/** The 15 write-tier annotation tools (tools-mutate.ts). */
export const RE_MUTATE_TOOL_NAMES: Record<string, true> = {
	rename_function: true,
	rename_variable: true,
	set_comment: true,
	set_prototype: true,
	set_variable_type: true,
	define_variable: true,
	define_global: true,
	define_function: true,
	set_calling_convention: true,
	set_flag: true,
	set_arch_hint: true,
	set_hint: true,
	set_data: true,
	set_string: true,
	set_format: true,
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

/** The rizin CLI-suite bridge (tools-rzcli.ts): one tool fronting rz-bin, rz-diff, rz-hash, rz-find, rz-asm, rz-ax. */
export const RE_RZCLI_TOOL_NAMES: Record<string, true> = {
	rizin_cli: true,
};

/** The dynamic-analysis debugger (tools-debug.ts): one tool, registered only when OMPRE_ENABLE_DEBUGGER is set. In the audit gate regardless, so its executions are always logged when it is on. */
export const RE_DEBUG_TOOL_NAMES: Record<string, true> = {
	rizin_debug: true,
};

/** The RzIL emulator (tools-emulate.ts): one exec-tier tool that interprets the target's code inside rizin. In the audit gate so its runs are always logged; not evidence (it is an action, like the debugger). */
export const RE_EMULATE_TOOL_NAMES: Record<string, true> = {
	rizin_emulate: true,
};

/** FLIRT signatures (tools-signatures.ts): `apply_signatures` renames matched library functions (changes analysis); `create_signature` writes a FLIRT file from the analyzed functions (changes nothing, emits an artifact). Both exec-tier, audited and toggled, but not evidence. */
export const RE_SIGNATURE_TOOL_NAMES: Record<string, true> = {
	apply_signatures: true,
	create_signature: true,
};

/** Analysis passes (tools-analyze.ts): one exec-tier tool that re-runs an `aa*` pass to recover more functions/xrefs/types. Audited and toggled, but not evidence (it changes analysis rather than observing it). */
export const RE_ANALYZE_TOOL_NAMES: Record<string, true> = {
	analyze: true,
};

/** Tools whose successful output is an observation of the binary and becomes a `re.evidence` record (evidence.ts). `rizin_help` is not (help text says nothing about the binary); `rizin_cli` is not (it also does arithmetic and standalone assembly — cite binary facts through the dedicated tools or rizin_command). */
export const RE_EVIDENCE_TOOL_NAMES: Record<string, true> = {
	...RE_READ_TOOL_NAMES,
	rizin_command: true,
};

/** Session-management tools that are neither analysis (no evidence to record — opening a binary or exporting the session asserts nothing about its contents) nor mutation, but still worth an audit-trail line. */
export const RE_SESSION_TOOL_NAMES: Record<string, true> = {
	open_binary: true,
	export_project: true,
};

/** Every RE-suite tool name (read + mutate + triage + rizin REPL + rizin CLI + debugger + emulator + session-setup) — the gate for the audit log, the status band, and `/re off`/`/re on`. `debug` is counted here even though it registers only when enabled, so turning it on never bypasses the log. */
export const RE_ALL_TOOL_NAMES: Record<string, true> = {
	...RE_READ_TOOL_NAMES,
	...RE_MUTATE_TOOL_NAMES,
	...RE_TRIAGE_TOOL_NAMES,
	...RE_RIZIN_TOOL_NAMES,
	...RE_RZCLI_TOOL_NAMES,
	...RE_DEBUG_TOOL_NAMES,
	...RE_EMULATE_TOOL_NAMES,
	...RE_SIGNATURE_TOOL_NAMES,
	...RE_ANALYZE_TOOL_NAMES,
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
