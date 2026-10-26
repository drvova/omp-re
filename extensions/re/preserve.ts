/**
 * Preserve the reverse-engineering session across context compaction.
 *
 * omp-re's evidence, annotations, and the open binary are stored as custom
 * session entries, so the *data* survives compaction. What does not survive is
 * the model's working memory: when the conversation is summarized, the model
 * can forget which binary is open and what it already found, even though the
 * entries are still on the branch. The `session.compacting` hook lets an
 * extension add lines to the summary, so this folds a compact snapshot of the
 * RE state into it — the post-compaction model stays grounded and knows it can
 * recall the detail with `/re evidence` / `/re cite`.
 *
 * It only contributes lines when a session is actually active (a binary is
 * open or evidence exists), so a conversation that never touched omp-re pays
 * nothing.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { basename } from "node:path";
import { liveAnnotations } from "./annotations.ts";
import { branchEntries } from "./entries.ts";
import { getState } from "./state.ts";
import { evidenceRecords } from "./ui.ts";
import { liveFindings } from "./findings.ts";

/** How many recent evidence records to name in the preserved snapshot (the rest stay recallable via `/re evidence`). */
const PRESERVED_EVIDENCE = 8;
/** How many live findings to restate verbatim; they are the session's conclusions, so the cap is generous. */
const PRESERVED_FINDINGS = 24;

/** The lines folded into a compaction summary, or `[]` when no RE session is active. */
export function preservedStateLines(ctx: ExtensionContext): string[] {
	const state = getState(ctx);
	const evidence = evidenceRecords(ctx);
	const annotations = state.binaryPath ? liveAnnotations(branchEntries(ctx), state.binaryPath).length : 0;
	if (!state.binaryPath && evidence.length === 0) return [];

	const lines = ["omp-re reverse-engineering session (preserve — the model must not lose this):"];
	lines.push(`- Open binary: ${state.binaryPath ? `${basename(state.binaryPath)} (${state.binaryPath})` : "none currently open — reopen with open_binary before using other RE tools"}`);
	lines.push(`- Recorded: ${evidence.length} evidence item(s), ${annotations} annotation(s) in effect. They persist on the session branch; list them with \`/re evidence\` and recall one with \`/re cite <id>\`.`);
	if (evidence.length > 0) {
		lines.push(`- Most recent evidence (id · tool · where):`);
		for (const rec of evidence.slice(-PRESERVED_EVIDENCE)) {
			lines.push(`  · ${rec.id.slice(0, 8)} · ${rec.tool}${rec.ea ? ` @ ${rec.ea}` : ""}`);
		}
	}
	// Findings are the session's conclusions: restating them is what stops the post-compaction model
	// re-deriving (or contradicting) what it already established and recorded.
	const findings = liveFindings(ctx);
	if (findings.length > 0) {
		lines.push(`- Recorded findings (${findings.length}; already in the report — revise with record_finding supersedes, withdraw with retract_finding, don't re-record):`);
		for (const f of findings.slice(-PRESERVED_FINDINGS)) {
			lines.push(`  · ${f.id.slice(0, 8)} [${f.confidence}${f.inherited ? ", inherited" : ""}] ${f.claim}${f.addr ? ` (at ${f.addr})` : ""}`);
		}
	}
	lines.push("- Every address stated after this must still come from tool output on this branch; do not invent one from the summary.");
	return lines;
}

/**
 * The compaction-preservation subsystem. Registered like every other
 * subsystem (see app.ts); the `session.compacting` handler returns extra
 * context lines for the summary.
 */
export function registerPreservation(pi: ExtensionAPI): void {
	pi.on("session.compacting", (_event, ctx) => {
		const context = preservedStateLines(ctx);
		return context.length > 0 ? { context } : undefined;
	});
}
