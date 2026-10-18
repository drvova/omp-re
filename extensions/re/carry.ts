/**
 * `/re carry <manifest.json>`: replay a finished report's findings against a
 * DIFFERENT binary — the next sample of a malware family, a firmware update, a
 * patched build — and say which claims still hold.
 *
 * A report's verification manifest (`<report>.manifest.json`, report.ts) is
 * already a test suite: claim → exact read-only rizin command → canonical output
 * hash. `/re verify` runs it against the SAME binary to prove reproducibility;
 * carry runs it against whatever binary is open now and classifies each piece of
 * evidence, then each claim:
 *
 * - **holds**: the re-run's canonical output hash is identical, or identical
 *   once positional addresses are masked (`shiftHash`, format.ts) — the code
 *   didn't change, the build just moved it.
 * - **relocated**: the anchor vanished (a renamed symbol) or a numeric anchor
 *   now points elsewhere, but the function it named was found again by its
 *   fingerprint (anchor.ts) and the command re-run there says the same thing.
 * - **drifted**: the command still runs (at the original or relocated anchor)
 *   but its output changed. The recorded canonical excerpt is line-diffed
 *   against the new one, matching lines with addresses masked so the diff keeps
 *   to what really changed — a patch-diff starting point.
 * - **broken**: the anchor is gone — the symbol/flag the command was pinned to no
 *   longer resolves and nothing matches its fingerprint, or the command now
 *   produces nothing (or only an error).
 * - **unchecked**: the evidence was provenance-only or legacy (no reproducible
 *   hash), or the manifest's command is no longer runnable in this rizin.
 *
 * A claim takes the worst status among its checked evidence (broken > drifted >
 * relocated > holds); a claim with no checkable evidence is unchecked.
 *
 * Deterministic and read-only, like `/re verify`: the manifest is untrusted
 * input, so every command goes back through `checkRizinCommand` (the same
 * read-only gate `rizin_command` uses) and every address through
 * `validateAddr`; commands run via `rz.cmdWithStderr`, never omp tool dispatch,
 * so carrying records no new evidence. Headless, a broken claim sets
 * `process.exitCode = 1` (`--strict` also fails on relocated, drifted, or unchecked), so a
 * report doubles as a CI regression test for the next build.
 */
import { readFile, writeFile } from "node:fs/promises";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { type AnchorFingerprint, relocateAnchor } from "./anchor.ts";
import { checkRizinCommand, loadCatalog, type RzCatalog } from "./catalog.ts";
import { canonicalExcerpt, canonicalHash, maskAddresses, shiftHash } from "./format.ts";
import { normalizeAddr, resolveNumericAddr, type RzSession, validateAddr } from "./rizin.ts";
import { ensureRizin, getState } from "./state.ts";
import { cleanStderr } from "./tools-rizin.ts";
import { sha256File } from "./verify.ts";

const CARRY_COMMAND_TIMEOUT_MS = 120_000;
/** Cap on diff lines shown per drifted record — the excerpt is ≤20 lines a side, so this only bites on a total rewrite. */
const MAX_DIFF_LINES = 40;
/** {@link canonicalExcerpt}'s default byte cap: an excerpt this long was cut mid-line. */
const EXCERPT_MAX_BYTES = 1024;

/** One entry of a `<report>.manifest.json`, as read back. Every field is optional on read: manifests are untrusted and may predate a field. */
export interface ManifestEntry {
	evidenceId: string;
	tool: string;
	args?: { command: string; addr?: string } | null;
	command?: string | null;
	commands?: string[] | null;
	reproHash?: string | null;
	canonicalExcerpt?: string | null;
	shiftHash?: string | null;
	anchor?: AnchorFingerprint | null;
	binarySha256?: string | null;
	claims: string[];
}

export interface CarryManifest {
	binarySha256: string | null;
	entries: ManifestEntry[];
}

export type CarryStatus = "holds" | "relocated" | "drifted" | "broken" | "unchecked";

export interface CarryEvidenceRow {
	evidenceId: string;
	tool: string;
	/** The exact line re-run (or that would have been), for display. */
	command?: string;
	status: CarryStatus;
	detail: string;
	/** drifted only: unified-style line diff of recorded excerpt (`-`) vs. new excerpt (`+`). */
	diff?: string[];
	/** Set when the anchor was found again elsewhere by fingerprint (relocated, or drifted after relocating). */
	relocation?: { from: string; to: string; addr: string; similarity: number };
}

export interface CarryClaimRow {
	text: string;
	status: CarryStatus;
	evidenceIds: string[];
}

export interface CarryResult {
	/** SHA-256 the report's evidence was taken against. */
	fromSha256: string | null;
	/** SHA-256 of the binary carried onto (the one open now). */
	toSha256: string | null;
	toPath: string | null;
	evidence: CarryEvidenceRow[];
	claims: CarryClaimRow[];
}

/** Parse and shape-check a manifest's JSON text. Throws a clear error on anything that isn't a manifest; tolerates missing optional fields per entry. */
export function parseManifest(text: string): CarryManifest {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch (err) {
		throw new Error(`omp-re: carry: manifest is not valid JSON (${err instanceof Error ? err.message : String(err)})`);
	}
	const obj = raw as { binarySha256?: unknown; entries?: unknown } | null;
	if (!obj || typeof obj !== "object" || !Array.isArray(obj.entries)) {
		throw new Error("omp-re: carry: not a verification manifest (no `entries` array) — pass the <report>.manifest.json written by /re report <path>");
	}
	const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
	const entries: ManifestEntry[] = [];
	for (const e of obj.entries as unknown[]) {
		const row = e as Record<string, unknown> | null;
		if (!row || typeof row !== "object" || typeof row.evidenceId !== "string") continue;
		const args = row.args as { command?: unknown; addr?: unknown } | null | undefined;
		entries.push({
			evidenceId: row.evidenceId,
			tool: str(row.tool) ?? "unknown",
			args:
				args && typeof args.command === "string"
					? typeof args.addr === "string" && args.addr
						? { command: args.command, addr: args.addr }
						: { command: args.command }
					: null,
			command: str(row.command),
			commands: Array.isArray(row.commands) ? row.commands.filter((c): c is string => typeof c === "string") : null,
			reproHash: str(row.reproHash),
			canonicalExcerpt: str(row.canonicalExcerpt),
			shiftHash: str(row.shiftHash),
			anchor: parseAnchor(row.anchor),
			binarySha256: str(row.binarySha256),
			claims: Array.isArray(row.claims) ? row.claims.filter((c): c is string => typeof c === "string") : [],
		});
	}
	return { binarySha256: str(obj.binarySha256), entries };
}

/**
 * Shape-check a manifest entry's anchor fingerprint. Untrusted input: the name and
 * offset are only displayed, the delta becomes part of an address (so it must be a
 * small non-negative integer), and the mnemonics only feed the similarity score.
 * Anything malformed drops the fingerprint (the entry just can't be relocated).
 */
function parseAnchor(raw: unknown): AnchorFingerprint | null {
	const a = raw as Partial<Record<keyof AnchorFingerprint, unknown>> | null | undefined;
	if (!a || typeof a !== "object") return null;
	const okNum = (v: unknown, max: number) => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max;
	if (typeof a.anchor !== "string" || typeof a.function !== "string" || typeof a.offset !== "string") return null;
	if (!okNum(a.delta, 1 << 24) || !okNum(a.size, 1 << 30) || !okNum(a.nbbs, 1 << 24)) return null;
	if (!Array.isArray(a.mnemonics) || a.mnemonics.length === 0 || !a.mnemonics.every((m) => typeof m === "string")) return null;
	return { anchor: a.anchor, function: a.function, offset: a.offset, delta: a.delta as number, size: a.size as number, nbbs: a.nbbs as number, mnemonics: a.mnemonics as string[] };
}

/**
 * The `{ command, addr }` to re-run for a manifest entry. Prefers the structured
 * `args` (manifests since carry shipped); falls back to splitting the recorded
 * line on its trailing ` @ <addr>` (what `checkRizinCommand` appends), leaving
 * `@!<blocksize>` alone since that is part of the command, not a seek.
 */
export function entryRequest(entry: ManifestEntry): { command: string; addr?: string } | undefined {
	if (entry.args) return entry.args;
	const line = entry.commands?.length === 1 ? entry.commands[0] : (entry.command ?? undefined);
	if (!line) return undefined;
	const match = /^(.*\S)\s+@\s+([^!\s]\S*)$/.exec(line.trim());
	if (match) return { command: match[1]!, addr: match[2]! };
	return { command: line.trim() };
}

/**
 * Line diff (LCS) of two short texts: unchanged lines prefixed `  `, removed `- `,
 * added `+ `. Lines are matched on `key(line)` (default: the line itself) but
 * printed as written, so with an address mask a line that only moved shows as
 * unchanged (new form) and the diff keeps to what really changed. Inputs are
 * canonical excerpts (≤20 lines), so the O(n·m) table is trivial.
 */
export function lineDiff(before: string, after: string, key: (line: string) => string = (line) => line): string[] {
	const a = before === "" ? [] : before.split("\n");
	const b = after === "" ? [] : after.split("\n");
	const ka = a.map(key);
	const kb = b.map(key);
	const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
	for (let i = a.length - 1; i >= 0; i--) {
		for (let j = b.length - 1; j >= 0; j--) {
			lcs[i]![j] = ka[i] === kb[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
		}
	}
	const out: string[] = [];
	let i = 0;
	let j = 0;
	while (i < a.length && j < b.length) {
		if (ka[i] === kb[j]) {
			out.push(`  ${b[j]}`);
			i++;
			j++;
		} else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
			out.push(`- ${a[i++]}`);
		} else {
			out.push(`+ ${b[j++]}`);
		}
	}
	while (i < a.length) out.push(`- ${a[i++]}`);
	while (j < b.length) out.push(`+ ${b[j++]}`);
	return out;
}

const RANK: Record<CarryStatus, number> = { unchecked: 0, holds: 1, relocated: 2, drifted: 3, broken: 4 };

/** Roll evidence statuses up to claims: worst checked status wins; all-unchecked stays unchecked. Claim order follows first appearance in the manifest. */
export function rollUpClaims(manifest: CarryManifest, evidence: readonly CarryEvidenceRow[]): CarryClaimRow[] {
	const statusById = new Map(evidence.map((row) => [row.evidenceId, row.status]));
	const claims = new Map<string, string[]>();
	for (const entry of manifest.entries) {
		for (const text of entry.claims) {
			const ids = claims.get(text) ?? [];
			if (!ids.includes(entry.evidenceId)) ids.push(entry.evidenceId);
			claims.set(text, ids);
		}
	}
	return [...claims.entries()].map(([text, evidenceIds]) => {
		let status: CarryStatus = "unchecked";
		for (const id of evidenceIds) {
			const s = statusById.get(id) ?? "unchecked";
			if (RANK[s] > RANK[status]) status = s;
		}
		return { text, status, evidenceIds };
	});
}

/**
 * Whether a re-run's output still says what the recorded one did: the exact
 * canonical hash, or — when the manifest carries one — the address-masked
 * `shiftHash`, which forgives a rebuild that only moved code. Returns the holds
 * detail, or undefined when the output really changed.
 */
function compareOutput(entry: ManifestEntry, output: string, binaryPath: string): string | undefined {
	if (canonicalHash(output, binaryPath) === entry.reproHash) return "output identical";
	if (entry.shiftHash && shiftHash(output, binaryPath) === entry.shiftHash) return "output identical apart from shifted addresses";
	return undefined;
}

/** Line diff of the recorded canonical excerpt against the new output's, capped; undefined when the excerpts are equal (the change lies further down). */
function excerptDiff(recordedExcerpt: string, output: string, binaryPath: string): string[] | undefined {
	const newExcerpt = canonicalExcerpt(output, binaryPath);
	if (recordedExcerpt === newExcerpt) return undefined;
	// An excerpt that hit its byte cap ends mid-line, at a different column on each side; drop that partial line so it never shows as a change.
	const whole = (excerpt: string) => (excerpt.length >= EXCERPT_MAX_BYTES ? excerpt.slice(0, Math.max(0, excerpt.lastIndexOf("\n"))) : excerpt);
	const diff = lineDiff(whole(recordedExcerpt), whole(newExcerpt), maskAddresses);
	if (!diff.some((line) => !line.startsWith("  "))) return undefined;
	return diff.length > MAX_DIFF_LINES ? [...diff.slice(0, MAX_DIFF_LINES), `  … ${diff.length - MAX_DIFF_LINES} more diff line(s)`] : diff;
}

/**
 * Find the anchor's function in this build by fingerprint and re-run the command
 * there. The new function's name is folded back to the recorded one before
 * comparing, so a pure rename compares equal. Returns the row fields — relocated
 * when the output then matches (exactly or apart from addresses), drifted with the
 * relocation noted and a diff when it doesn't — or undefined when nothing matches
 * the fingerprint or the relocated line can't run.
 */
async function tryRelocated(
	rz: RzSession,
	catalog: RzCatalog,
	entry: ManifestEntry,
	request: { command: string; addr?: string },
	fp: AnchorFingerprint,
	binaryPath: string,
): Promise<Omit<CarryEvidenceRow, "evidenceId" | "tool"> | undefined> {
	const found = await relocateAnchor(rz, fp);
	if (!found) return undefined;
	const check = checkRizinCommand(catalog, request.command, found.addr);
	if (!check.ok) return undefined;
	const { output } = await rz.cmdWithStderr(check.line, { timeoutMs: CARRY_COMMAND_TIMEOUT_MS });
	const folded = found.function !== fp.function ? output.split(found.function).join(fp.function) : output;
	const relocation = { from: `${fp.function} @ ${fp.offset}`, to: `${found.function} @ ${found.offset}`, addr: found.addr, similarity: found.similarity };
	const renamed = found.function !== fp.function;
	const moved = normalizeAddr(found.offset) !== normalizeAddr(fp.offset);
	const how = renamed && moved ? `moved to ${found.function} @ ${found.offset}` : renamed ? `renamed to ${found.function}` : moved ? `moved from ${fp.offset} to ${found.offset}` : `found at ${found.offset}`;
	const where = `${fp.function} ${how} (code similarity ${found.similarity})`;
	const same = compareOutput(entry, folded, binaryPath);
	if (same) return { command: check.line, status: "relocated", detail: `${where}; ${same}`, relocation };
	const diff = excerptDiff(entry.canonicalExcerpt ?? "", folded, binaryPath);
	return { command: check.line, status: "drifted", detail: `${where}; output changed${diff ? "" : " beyond the recorded 20-line excerpt"}`, relocation, ...(diff ? { diff } : {}) };
}

/**
 * Re-run every reproducible manifest entry against the currently-open binary and
 * classify it. Never throws for a single entry — any per-entry failure degrades
 * that entry to "unchecked" (an infra problem) or "broken" (the anchor is gone).
 */
export async function buildCarry(ctx: ExtensionContext, manifest: CarryManifest): Promise<CarryResult> {
	const state = getState(ctx);
	const binaryPath = state.binaryPath ?? undefined;
	if (!binaryPath) throw new Error("omp-re: carry: no binary open — /re open <the new build> first, or pass --against <path>");
	const toSha256 = state.binarySha256 ?? (await sha256File(binaryPath).catch(() => undefined)) ?? null;

	let catalog: Awaited<ReturnType<typeof loadCatalog>> | undefined;
	const evidence: CarryEvidenceRow[] = [];
	const seen = new Set<string>();

	for (const entry of manifest.entries) {
		if (seen.has(entry.evidenceId)) continue;
		seen.add(entry.evidenceId);
		const request = entry.tool === "rizin_command" ? entryRequest(entry) : undefined;
		const base = { evidenceId: entry.evidenceId, tool: entry.tool };

		if (!request || !entry.reproHash) {
			const detail = entry.commands?.length ? "provenance-only: no reproducible hash to compare (re-run by hand)" : "legacy: no reproducible hash recorded";
			evidence.push({ ...base, command: entry.command ?? undefined, status: "unchecked", detail });
			continue;
		}

		let line: string;
		try {
			if (!catalog) catalog = await loadCatalog();
			const check = checkRizinCommand(catalog, request.command, request.addr !== undefined ? validateAddr(request.addr) : undefined);
			if (!check.ok) {
				evidence.push({ ...base, command: request.command, status: "unchecked", detail: `not runnable here: ${check.reason}` });
				continue;
			}
			line = check.line;
		} catch (err) {
			evidence.push({ ...base, command: request.command, status: "unchecked", detail: `not runnable here: ${err instanceof Error ? err.message : String(err)}` });
			continue;
		}

		try {
			const rz = await ensureRizin(ctx);
			const fp = entry.anchor ?? undefined;
			// A symbolic anchor (sym.decrypt_config, a flag) that no longer resolves means the thing the
			// claim is about is gone under that name; with a fingerprint it may just have been renamed,
			// so look for it before calling it broken. A numeric anchor always "resolves", so it is
			// judged by its output (and relocated by fingerprint below when that output changed).
			const numericAnchor = request.addr !== undefined && /^(0x[0-9a-f]+|\d+)$/i.test(request.addr);
			if (request.addr !== undefined && !numericAnchor) {
				const resolves = await resolveNumericAddr(rz, request.addr).then(
					() => true,
					() => false,
				);
				if (!resolves) {
					const moved = fp ? await tryRelocated(rz, catalog!, entry, request, fp, binaryPath) : undefined;
					evidence.push(moved ? { ...base, ...moved } : { ...base, command: line, status: "broken", detail: `anchor \`${request.addr}\` no longer resolves in this binary${fp ? " and no function matching its fingerprint was found" : ""}` });
					continue;
				}
			}
			const { output, stderr } = await rz.cmdWithStderr(line, { timeoutMs: CARRY_COMMAND_TIMEOUT_MS });
			const recordedExcerpt = entry.canonicalExcerpt ?? "";
			if (output.trim() === "") {
				const errors = cleanStderr(stderr);
				if (errors || recordedExcerpt.trim() !== "") {
					const moved = numericAnchor && fp ? await tryRelocated(rz, catalog!, entry, request, fp, binaryPath) : undefined;
					const said = errors ? `: ${errors.split("\n").slice(-1)[0]}` : "";
					evidence.push(moved ? { ...base, ...moved } : { ...base, command: line, status: "broken", detail: `command now produces no output${said}` });
					continue;
				}
			}
			const same = compareOutput(entry, output, binaryPath);
			if (same) {
				evidence.push({ ...base, command: line, status: "holds", detail: same });
				continue;
			}
			// Drifted at a numeric anchor: the code it named may simply have moved. Relocate by
			// fingerprint and re-run there; keep the drift only if the code isn't found elsewhere.
			if (numericAnchor && fp) {
				const moved = await tryRelocated(rz, catalog!, entry, request, fp, binaryPath);
				if (moved && moved.relocation?.addr !== normalizeAddr(request.addr!)) {
					evidence.push({ ...base, ...moved });
					continue;
				}
			}
			const parts = [];
			const diff = excerptDiff(recordedExcerpt, output, binaryPath);
			parts.push(diff ? "output changed" : "output changed beyond the recorded 20-line excerpt (re-run to see it)");
			if (numericAnchor) parts.push(`pinned to numeric address ${request.addr}${fp ? "; no function matching its fingerprint was found elsewhere" : " — the code it named may have moved in this build"}`);
			evidence.push({ ...base, command: line, status: "drifted", detail: parts.join("; "), ...(diff ? { diff } : {}) });
		} catch (err) {
			evidence.push({ ...base, command: line, status: "unchecked", detail: `re-run failed: ${err instanceof Error ? err.message : String(err)}` });
		}
	}

	return { fromSha256: manifest.binarySha256, toSha256, toPath: binaryPath, evidence, claims: rollUpClaims(manifest, evidence) };
}

function counts(rows: readonly { status: CarryStatus }[]): Record<CarryStatus, number> {
	const c: Record<CarryStatus, number> = { holds: 0, relocated: 0, drifted: 0, broken: 0, unchecked: 0 };
	for (const row of rows) c[row.status]++;
	return c;
}

const short = (sha: string | null) => (sha ? `${sha.slice(0, 12)}…` : "unknown");

/** The one-line summary plus per-claim lines (non-holding first), for notify/console. */
export function formatCarrySummary(result: CarryResult): string {
	const c = counts(result.claims);
	const lines = [
		`omp-re: carry ${short(result.fromSha256)} → ${short(result.toSha256)} — ${c.holds} hold, ${c.relocated} relocated, ${c.drifted} drifted, ${c.broken} BROKEN, ${c.unchecked} unchecked (of ${result.claims.length} claim(s))`,
	];
	if (result.fromSha256 && result.fromSha256 === result.toSha256) lines.push("  (same binary the report was written against — this is /re verify; open the new build to carry onto it)");
	const order: CarryStatus[] = ["broken", "drifted", "unchecked", "relocated", "holds"];
	for (const status of order) {
		for (const claim of result.claims.filter((cl) => cl.status === status)) lines.push(`  ${status.toUpperCase().padEnd(9)} ${claim.text}`);
	}
	return lines.join("\n");
}

/** The full carry report as Markdown: claim matrix, then per-evidence detail with diffs for drifted records. */
export function formatCarryMarkdown(result: CarryResult, manifestPath: string): string {
	const c = counts(result.claims);
	const evidenceById = new Map(result.evidence.map((row) => [row.evidenceId, row]));
	const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
	const out = [
		"# Carry Report",
		"",
		`- **Manifest:** \`${manifestPath}\``,
		`- **From binary:** \`${result.fromSha256 ?? "unknown"}\``,
		`- **To binary:** \`${result.toSha256 ?? "unknown"}\`${result.toPath ? ` (${result.toPath})` : ""}`,
		`- **Claims:** ${c.holds} hold · ${c.relocated} relocated · ${c.drifted} drifted · ${c.broken} broken · ${c.unchecked} unchecked`,
		"",
		"## Claims",
		"",
		"| Status | Claim | Evidence |",
		"| --- | --- | --- |",
		...result.claims.map((cl) => `| ${cl.status} | ${cell(cl.text)} | ${cl.evidenceIds.map((id) => `\`${id.slice(0, 8)}\` ${evidenceById.get(id)?.status ?? "unchecked"}`).join(", ")} |`),
		"",
		"## Evidence",
		"",
	];
	for (const row of result.evidence) {
		out.push(`### \`${row.evidenceId.slice(0, 8)}\` — ${row.status}`, "", `- **Tool:** ${row.tool}`);
		if (row.command) out.push(`- **Command:** \`${row.command}\``);
		if (row.relocation) out.push(`- **Relocated:** ${row.relocation.from} → ${row.relocation.to} (similarity ${row.relocation.similarity})`);
		out.push(`- **Detail:** ${row.detail}`, "");
		if (row.diff && row.diff.length > 0) out.push("```diff", ...row.diff, "```", "");
	}
	return out.join("\n");
}

/**
 * `/re carry <manifest> [--strict] [--out <path>]`: load the manifest, carry it
 * onto the open binary, and report. Interactive → notify the summary; headless →
 * console, with `process.exitCode = 1` on any broken claim (and, under
 * `--strict`, any drifted or unchecked one). `--out` also writes the Markdown
 * carry report and a `<out>.json` sidecar of the full result.
 */
export async function carryManifest(ctx: ExtensionContext, manifestPath: string, opts: { strict?: boolean; out?: string } = {}): Promise<CarryResult> {
	let text: string;
	try {
		text = await readFile(manifestPath, "utf8");
	} catch (err) {
		throw new Error(`omp-re: carry: could not read manifest ${manifestPath}: ${err instanceof Error ? err.message : String(err)}`);
	}
	const result = await buildCarry(ctx, parseManifest(text));
	const c = counts(result.claims);
	const failed = c.broken > 0 || (opts.strict === true && (c.relocated > 0 || c.drifted > 0 || c.unchecked > 0));

	let summary = formatCarrySummary(result);
	if (opts.out) {
		try {
			await writeFile(opts.out, formatCarryMarkdown(result, manifestPath), "utf8");
			await writeFile(`${opts.out}.json`, `${JSON.stringify(result, null, 2)}\n`, "utf8");
			summary += `\ncarry report written to ${opts.out} (+ ${opts.out}.json)`;
		} catch (err) {
			summary += `\ncarry report not written: ${err instanceof Error ? err.message : String(err)}`;
		}
	}

	if (ctx.hasUI) {
		ctx.ui.notify(summary, failed ? "error" : c.drifted > 0 ? "warning" : "info");
	} else if (failed) {
		console.error(summary);
		// Same deliberate headless signal as /re verify and the report gate: a finding that no
		// longer holds on the new build must fail the pipeline. process.exitCode, never process.exit.
		process.exitCode = 1;
	} else {
		console.log(summary);
	}
	return result;
}
