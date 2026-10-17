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

/**
 * One recorded `re.evidence` entry, read back from the branch. The reproducibility
 * fields (`commands`/`reproHash`/`canonicalExcerpt`/`binarySha256`) are present only
 * on records written since verifiable reports shipped; older records omit them and
 * are treated as "unverifiable (legacy)" by `/re verify` and the report manifest.
 */
export interface EvidenceRecord {
	id: string;
	tool: string;
	/** The tool's JSON params (for `rizin_command`: `{ command, addr }`), used to reconstruct the exact line at verify time. */
	args?: unknown;
	ea?: string;
	/** SHA-256 of the model-facing text (header + any truncation footer): resolves the blob, but NOT reproducible. */
	outputHash?: string;
	artifactId?: string;
	summary: string;
	/** `rizin_command` only: the exact rizin line(s) that produced this output. */
	commands?: string[];
	/** `rizin_command` only: SHA-256 of the canonicalized raw output — the verification key. */
	reproHash?: string;
	/** `rizin_command` only: a short canonical excerpt for human diffing. */
	canonicalExcerpt?: string;
	/** SHA-256 of the binary this evidence was taken against, stamped at record time. */
	binarySha256?: string;
}

/**
 * Every `re.evidence` record on the branch. Skips malformed rows (missing
 * id/tool/summary); the provenance fields are copied through when present and
 * left undefined on legacy records, so old sessions load without crashing.
 */
export function collectEvidence(entries: readonly { type: string; customType?: string; data?: unknown }[]): EvidenceRecord[] {
	const out: EvidenceRecord[] = [];
	for (const entry of entries) {
		if (entry.type !== "custom" || entry.customType !== "re.evidence") continue;
		const data = entry.data as Partial<EvidenceRecord> | undefined;
		if (!data || typeof data.id !== "string" || typeof data.tool !== "string" || typeof data.summary !== "string") continue;
		out.push({
			id: data.id,
			tool: data.tool,
			args: data.args,
			ea: typeof data.ea === "string" ? data.ea : undefined,
			outputHash: typeof data.outputHash === "string" ? data.outputHash : undefined,
			artifactId: typeof data.artifactId === "string" ? data.artifactId : undefined,
			summary: data.summary,
			commands: Array.isArray(data.commands) && data.commands.every((c) => typeof c === "string") ? data.commands : undefined,
			reproHash: typeof data.reproHash === "string" ? data.reproHash : undefined,
			canonicalExcerpt: typeof data.canonicalExcerpt === "string" ? data.canonicalExcerpt : undefined,
			binarySha256: typeof data.binarySha256 === "string" ? data.binarySha256 : undefined,
		});
	}
	return out;
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

/** The SHA-256 of the binary the latest `re.binary` entry on this branch opened, if one was recorded (absent on entries written before verifiable reports). */
export function lastRecordedBinarySha256(entries: readonly SessionEntry[]): string | undefined {
	let last: string | undefined;
	for (const entry of customEntries(entries, "re.binary")) {
		const sha = (entry.data as { sha256?: unknown } | undefined)?.sha256;
		if (typeof sha === "string") last = sha;
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

/**
 * The analysis passes (`analyze` tool) run against `binaryPath` on this
 * branch, de-duplicated and in first-run order, so a resume re-runs the same
 * passes (`aaa` runs on every spawn, but these extra passes don't). Scoped to
 * the binary like signatures and annotations.
 */
export function recordedAnalysisPasses(entries: readonly SessionEntry[], binaryPath: string): string[] {
	const passes: string[] = [];
	let current: string | undefined;
	for (const entry of entries) {
		if (entry.type !== "custom") continue;
		if (entry.customType === "re.binary") {
			const path = (entry.data as { path?: unknown } | undefined)?.path;
			current = typeof path === "string" ? path : undefined;
			continue;
		}
		if (entry.customType === "re.analysis" && current === binaryPath) {
			const pass = (entry.data as { pass?: unknown } | undefined)?.pass;
			if (typeof pass === "string" && !passes.includes(pass)) passes.push(pass);
		}
	}
	return passes;
}

/**
 * The files mapped into the session (`map_file`) against `binaryPath` on this
 * branch, de-duplicated by path+address and in first-map order, so a resume
 * re-maps them. Scoped to the binary like signatures and annotations.
 */
export function recordedMapFiles(entries: readonly SessionEntry[], binaryPath: string): { path: string; addr: string; perm?: string }[] {
	const maps: { path: string; addr: string; perm?: string }[] = [];
	let current: string | undefined;
	for (const entry of entries) {
		if (entry.type !== "custom") continue;
		if (entry.customType === "re.binary") {
			const path = (entry.data as { path?: unknown } | undefined)?.path;
			current = typeof path === "string" ? path : undefined;
			continue;
		}
		if (entry.customType === "re.mapfile" && current === binaryPath) {
			const data = entry.data as { path?: unknown; addr?: unknown; perm?: unknown } | undefined;
			if (typeof data?.path === "string" && typeof data.addr === "string" && !maps.some((m) => m.path === data.path && m.addr === data.addr)) {
				maps.push({ path: data.path, addr: data.addr, ...(typeof data.perm === "string" ? { perm: data.perm } : {}) });
			}
		}
	}
	return maps;
}
