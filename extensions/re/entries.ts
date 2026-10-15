/**
 * Session-entry access shared by every module that reads omp-re's `re.*`
 * custom entries (`re.binary`, `re.evidence`, `re.annotation`, `re.undo`).
 *
 * Everything reads the current *branch* (`getBranch()`, root to active leaf),
 * never `getEntries()`: after `/tree` navigation or a branch, evidence and
 * annotations from an abandoned branch must not ground a claim or be
 * re-applied to rizin.
 */
import type { CustomEntry, ExtensionContext, SessionEntry } from "@oh-my-pi/pi-coding-agent";

export function branchEntries(ctx: ExtensionContext): SessionEntry[] {
	return ctx.sessionManager.getBranch();
}

/** Custom entries of one `customType`, in branch order. */
export function customEntries(entries: readonly SessionEntry[], customType: string): CustomEntry[] {
	return entries.filter((entry): entry is CustomEntry => entry.type === "custom" && entry.customType === customType);
}

/** The binary path the latest `re.binary` entry on this branch opened, if any. */
export function lastRecordedBinaryPath(entries: readonly SessionEntry[]): string | undefined {
	let last: string | undefined;
	for (const entry of customEntries(entries, "re.binary")) {
		const path = (entry.data as { path?: unknown } | undefined)?.path;
		if (typeof path === "string") last = path;
	}
	return last;
}
