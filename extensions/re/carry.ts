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
 * - **holds**: the re-run's canonical output hash is identical — the finding
 *   carries over unchanged.
 * - **drifted**: the command still runs but its output changed. The recorded
 *   canonical excerpt is line-diffed against the new one, so the claim lands
 *   with the exact change under it — a patch-diff starting point.
 * - **broken**: the anchor is gone — the symbol/flag the command was pinned to no
 *   longer resolves, or the command now produces nothing (or only an error).
 * - **unchecked**: the evidence was provenance-only or legacy (no reproducible
 *   hash), or the manifest's command is no longer runnable in this rizin.
 *
 * A claim takes the worst status among its checked evidence (broken > drifted >
 * holds); a claim with no checkable evidence is unchecked.
 *
 * Deterministic and read-only, like `/re verify`: the manifest is untrusted
 * input, so every command goes back through `checkRizinCommand` (the same
 * read-only gate `rizin_command` uses) and every address through
 * `validateAddr`; commands run via `rz.cmdWithStderr`, never omp tool dispatch,
 * so carrying records no new evidence. Headless, a broken claim sets
 * `process.exitCode = 1` (`--strict` also fails on drifted or unchecked), so a
 * report doubles as a CI regression test for the next build.
 */
import { readFile, writeFile } from "node:fs/promises";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { checkRizinCommand, loadCatalog } from "./catalog.ts";
import { canonicalExcerpt, canonicalHash } from "./format.ts";
import { resolveNumericAddr, validateAddr } from "./rizin.ts";
import { ensureRizin, getState } from "./state.ts";
import { cleanStderr } from "./tools-rizin.ts";
import { sha256File } from "./verify.ts";

const CARRY_COMMAND_TIMEOUT_MS = 120_000;
/** Cap on diff lines shown per drifted record — the excerpt is ≤20 lines a side, so this only bites on a total rewrite. */
const MAX_DIFF_LINES = 40;

/** One entry of a `<report>.manifest.json`, as read back. Every field is optional on read: manifests are untrusted and may predate a field. */
export interface ManifestEntry {
	evidenceId: string;
	tool: string;
	args?: { command: string; addr?: string } | null;
	command?: string | null;
	commands?: string[] | null;
	reproHash?: string | null;
	canonicalExcerpt?: string | null;
	binarySha256?: string | null;
	claims: string[];
}

export interface CarryManifest {
	binarySha256: string | null;
	entries: ManifestEntry[];
}

export type CarryStatus = "holds" | "drifted" | "broken" | "unchecked";

export interface CarryEvidenceRow {
	evidenceId: string;
	tool: string;
	/** The exact line re-run (or that would have been), for display. */
	command?: string;
	status: CarryStatus;
	detail: string;
	/** drifted only: unified-style line diff of recorded excerpt (`-`) vs. new excerpt (`+`). */
	diff?: string[];
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
			binarySha256: str(row.binarySha256),
			claims: Array.isArray(row.claims) ? row.claims.filter((c): c is string => typeof c === "string") : [],
		});
	}
	return { binarySha256: str(obj.binarySha256), entries };
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

/** Line diff (LCS) of two short texts: unchanged lines prefixed `  `, removed `- `, added `+ `. Inputs are canonical excerpts (≤20 lines), so the O(n·m) table is trivial. */
export function lineDiff(before: string, after: string): string[] {
	const a = before === "" ? [] : before.split("\n");
	const b = after === "" ? [] : after.split("\n");
	const lcs: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
	for (let i = a.length - 1; i >= 0; i--) {
		for (let j = b.length - 1; j >= 0; j--) {
			lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
		}
	}
	const out: string[] = [];
	let i = 0;
	let j = 0;
	while (i < a.length && j < b.length) {
		if (a[i] === b[j]) {
			out.push(`  ${a[i]}`);
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

const RANK: Record<CarryStatus, number> = { unchecked: 0, holds: 1, drifted: 2, broken: 3 };

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
			// A symbolic anchor (sym.decrypt_config, a flag) that no longer resolves is the clearest
			// "broken": the thing the claim is about is gone from this build. A numeric anchor can't be
			// checked this way — it always "resolves" — so it is judged by its output and flagged below.
			const numericAnchor = request.addr !== undefined && /^(0x[0-9a-f]+|\d+)$/i.test(request.addr);
			if (request.addr !== undefined && !numericAnchor) {
				try {
					await resolveNumericAddr(rz, request.addr);
				} catch {
					evidence.push({ ...base, command: line, status: "broken", detail: `anchor \`${request.addr}\` no longer resolves in this binary` });
					continue;
				}
			}
			const { output, stderr } = await rz.cmdWithStderr(line, { timeoutMs: CARRY_COMMAND_TIMEOUT_MS });
			const recordedExcerpt = entry.canonicalExcerpt ?? "";
			if (output.trim() === "") {
				const errors = cleanStderr(stderr);
				if (errors || recordedExcerpt.trim() !== "") {
					const said = errors ? `: ${errors.split("\n").slice(-1)[0]}` : "";
					evidence.push({ ...base, command: line, status: "broken", detail: `command now produces no output${said}` });
					continue;
				}
			}
			const rehash = canonicalHash(output, binaryPath);
			if (rehash === entry.reproHash) {
				evidence.push({ ...base, command: line, status: "holds", detail: "output identical" });
				continue;
			}
			const newExcerpt = canonicalExcerpt(output, binaryPath);
			const diff = recordedExcerpt === newExcerpt ? [] : lineDiff(recordedExcerpt, newExcerpt);
			const parts = [diff.length > 0 ? "output changed" : "output changed beyond the recorded 20-line excerpt (re-run to see it)"];
			if (numericAnchor) parts.push(`pinned to numeric address ${request.addr} — the code it named may have moved in this build`);
			evidence.push({
				...base,
				command: line,
				status: "drifted",
				detail: parts.join("; "),
				...(diff.length > 0 ? { diff: diff.length > MAX_DIFF_LINES ? [...diff.slice(0, MAX_DIFF_LINES), `  … ${diff.length - MAX_DIFF_LINES} more diff line(s)`] : diff } : {}),
			});
		} catch (err) {
			evidence.push({ ...base, command: line, status: "unchecked", detail: `re-run failed: ${err instanceof Error ? err.message : String(err)}` });
		}
	}

	return { fromSha256: manifest.binarySha256, toSha256, toPath: binaryPath, evidence, claims: rollUpClaims(manifest, evidence) };
}

function counts(rows: readonly { status: CarryStatus }[]): Record<CarryStatus, number> {
	const c: Record<CarryStatus, number> = { holds: 0, drifted: 0, broken: 0, unchecked: 0 };
	for (const row of rows) c[row.status]++;
	return c;
}

const short = (sha: string | null) => (sha ? `${sha.slice(0, 12)}…` : "unknown");

/** The one-line summary plus per-claim lines (non-holding first), for notify/console. */
export function formatCarrySummary(result: CarryResult): string {
	const c = counts(result.claims);
	const lines = [
		`omp-re: carry ${short(result.fromSha256)} → ${short(result.toSha256)} — ${c.holds} hold, ${c.drifted} drifted, ${c.broken} BROKEN, ${c.unchecked} unchecked (of ${result.claims.length} claim(s))`,
	];
	if (result.fromSha256 && result.fromSha256 === result.toSha256) lines.push("  (same binary the report was written against — this is /re verify; open the new build to carry onto it)");
	const order: CarryStatus[] = ["broken", "drifted", "unchecked", "holds"];
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
		`- **Claims:** ${c.holds} hold · ${c.drifted} drifted · ${c.broken} broken · ${c.unchecked} unchecked`,
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
	const failed = c.broken > 0 || (opts.strict === true && (c.drifted > 0 || c.unchecked > 0));

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
