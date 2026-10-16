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
import type { LoadOptions } from "./rizin.ts";

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

/**
 * The load options (`-a/-b/-B/-F`) recorded with the latest `re.binary` entry,
 * so a resume reopens a raw/headerless target the same way it was first
 * opened. Undefined when the last open used plain header autodetection.
 */
export function lastRecordedLoadOptions(entries: readonly SessionEntry[]): LoadOptions | undefined {
	let last: LoadOptions | undefined;
	for (const entry of customEntries(entries, "re.binary")) {
		const load = (entry.data as { load?: unknown } | undefined)?.load;
		last = load && typeof load === "object" && !Array.isArray(load) ? (load as LoadOptions) : undefined;
	}
	return last;
}

/**
 * The custom FLIRT signature files applied to `binaryPath` on this branch, in
 * order, so a resume re-applies the same files. Scoped to the binary the same
 * way annotations are: an `re.signature` entry belongs to whichever `re.binary`
 * opened most recently before it.
 */
export function recordedSignatures(entries: readonly SessionEntry[], binaryPath: string): string[] {
	const paths: string[] = [];
	let current: string | undefined;
	for (const entry of entries) {
		if (entry.type !== "custom") continue;
		if (entry.customType === "re.binary") {
			const path = (entry.data as { path?: unknown } | undefined)?.path;
			current = typeof path === "string" ? path : undefined;
			continue;
		}
		if (entry.customType === "re.signature" && current === binaryPath) {
			const path = (entry.data as { path?: unknown } | undefined)?.path;
			if (typeof path === "string") paths.push(path);
		}
	}
	return paths;
}
