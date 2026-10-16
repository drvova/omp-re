/**
 * Applying custom FLIRT signature files (book: analysis/signatures).
 *
 * The built-in signature database is applied by rizin's own `aaa` on open
 * (`analysis.apply.signature`), so it needs no replay. A *custom* `.sig`/`.pat`
 * file the analyst applies with `Fs` does need replay: the function names it
 * produces live in rizin's process memory, so a respawn (resume, crash
 * recovery, tree navigation) must re-apply the same files, exactly as
 * annotations are replayed. This module is the single builder for that `Fs`
 * command, shared by the apply_signatures tool and the respawn path.
 */
import { rzQuote, type RzSession } from "./rizin.ts";

/** Reject paths that would break the NUL-framed pipe; everything else is made literal by rzQuote (so a path with spaces or rizin metacharacters is one argument). */
export function validateSignaturePath(path: string): string {
	if (path.includes("\n") || path.includes("\r") || path.includes("\0")) {
		throw new Error("omp-re: apply_signatures: path must not contain a line break or NUL");
	}
	if (path.trim() === "") throw new Error("omp-re: apply_signatures: empty path");
	return path;
}

/** The rizin command that applies one FLIRT file. */
export function signatureApplyCommand(path: string): string {
	return `Fs ${rzQuote(validateSignaturePath(path))}`;
}

/** rizin's `Fs` prints `Found <n> FLIRT signatures via <path>`; pull out the count for a verifiable result. */
export function parseAppliedCount(output: string): number | undefined {
	const m = /Found\s+(\d+)\s+FLIRT signatures?/i.exec(output);
	return m ? Number(m[1]) : undefined;
}

/**
 * Re-apply custom FLIRT files to a freshly analyzed process, in order. A file
 * that no longer applies (moved, unreadable) is reported rather than aborting
 * the rest — matching replayAnnotations.
 */
export async function replaySignatures(rz: RzSession, paths: readonly string[]): Promise<string[]> {
	const failures: string[] = [];
	for (const path of paths) {
		try {
			await rz.cmd(signatureApplyCommand(path));
		} catch (err) {
			failures.push(`signature ${path}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}
	return failures;
}
