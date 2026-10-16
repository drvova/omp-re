/**
 * Re-running rizin's analysis passes (book: analysis/code_analysis).
 *
 * `open_binary` runs `aaa`, which already does call/xref analysis and applies
 * signatures. The deeper and format-specific passes it skips — prelude scans
 * that recover functions in stripped binaries, Go and Objective-C recovery,
 * pointer/value analysis, recursive type matching — are run on demand through
 * the `analyze` tool. Because `aaa` runs again on every respawn but these
 * extra passes do not, a pass the analyst ran is recorded and re-run on
 * resume/respawn (entries.ts + runtime.ts), so the recovered functions are
 * there again — exactly like replayed signatures and annotations. This module
 * is the single pass-name → command map shared by the tool and the replay.
 */
import type { RzSession } from "./rizin.ts";

/** Analysis passes exposed by the `analyze` tool, each a rizin `aa*` command. All are additive (they find functions/xrefs/names or match types); none deletes analysis. */
export const ANALYSIS_PASSES = {
	calls: "aac", // analyze function calls
	xrefs: "aar", // analyze cross-references
	pointers: "aav", // analyze values that reference a section/map (pointers)
	preludes: "aap", // find functions by prologue byte patterns (recovers stripped code)
	autoname: "aan", // name functions from the strings/calls they use
	types: "aaft", // recursive type matching across all functions
	golang: "aalg", // recover Go functions and strings
	objc: "aalor", // recover Objective-C references from selector usage
	emulate_functions: "aaef", // analyze references by emulating every function (slow)
} as const;

export type AnalysisPass = keyof typeof ANALYSIS_PASSES;

export function isAnalysisPass(name: string): name is AnalysisPass {
	return Object.hasOwn(ANALYSIS_PASSES, name);
}

/**
 * Re-run recorded analysis passes on a freshly analyzed process, in order. An
 * unknown or failing pass is reported rather than aborting the rest, matching
 * replayAnnotations / replaySignatures.
 */
export async function replayAnalysisPasses(rz: RzSession, passes: readonly string[], timeoutMs?: number): Promise<string[]> {
	const failures: string[] = [];
	for (const pass of passes) {
		if (!isAnalysisPass(pass)) {
			failures.push(`analysis pass ${pass}: unknown`);
			continue;
		}
		try {
			await rz.cmd(ANALYSIS_PASSES[pass], timeoutMs !== undefined ? { timeoutMs } : {});
		} catch (err) {
			failures.push(`analysis pass ${pass}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}
	return failures;
}
