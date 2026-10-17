/**
 * `/re verify`: re-derive each piece of evidence from the open binary and prove
 * it reproducible. The report gate (report.ts) already withholds any report whose
 * claims lack an evidence id; this adds the next guarantee — a claim's evidence is
 * not merely cited but RE-RUNNABLE: its exact rizin command, run read-only against
 * the same binary (matched by SHA-256), still produces the same canonical output
 * hash. Unreproducible evidence is flagged; tampered or drifted evidence FAILS with
 * a non-zero headless exit, the same loud signal the report gate uses for
 * ungrounded claims.
 *
 * Cut 1 machine-verifies `rizin_command` evidence, whose recorded args fully re-run
 * the line and whose body is the raw rizin output. Dedicated read tools (which run
 * several internal commands and post-process in TS) carry their command(s) for the
 * manifest but are "provenance-only" here until each opts into a reproHash over its
 * own raw output.
 *
 * Read-only and side-effect-free: commands go through the same `checkRizinCommand`
 * gate and the live rizin session, never a writable reopen, and re-running calls
 * `rz.cmdWithStderr` directly rather than omp tool dispatch, so the `tool_result`
 * evidence hook never fires and verification records no new evidence.
 */
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { checkRizinCommand, loadCatalog } from "./catalog.ts";
import { branchEntries, collectEvidence, type EvidenceRecord } from "./entries.ts";
import { canonicalHash } from "./format.ts";
import { ensureRizin, getState } from "./state.ts";

const VERIFY_COMMAND_TIMEOUT_MS = 120_000;

/** SHA-256 hex of a file, streamed (no rizin spawn). Used at open time (index.ts) and to re-hash the currently-open binary at verify time. */
export async function sha256File(path: string): Promise<string> {
	const hash = createHash("sha256");
	await new Promise<void>((resolve, reject) => {
		const stream = createReadStream(path);
		stream.on("data", (chunk) => hash.update(chunk));
		stream.on("end", () => resolve());
		stream.on("error", reject);
	});
	return hash.digest("hex");
}

/** Static status of a recorded evidence row, from its recorded fields alone (no re-run) — what the report manifest shows. */
export type RecordedStatus = "reproducible" | "provenance-only" | "unverifiable (legacy)";

/** Classify an evidence record from what it recorded, without re-running anything. */
export function recordedStatus(ev: EvidenceRecord): RecordedStatus {
	if (ev.reproHash && ev.binarySha256) return "reproducible";
	if (ev.commands && ev.commands.length > 0) return "provenance-only";
	return "unverifiable (legacy)";
}

/** The exact line(s) recorded for a record, for display; falls back to rendering the recorded args. */
export function recordedCommand(ev: EvidenceRecord): string | undefined {
	if (ev.commands && ev.commands.length > 0) return ev.commands.join(" ; ");
	const args = ev.args as { command?: unknown; addr?: unknown } | undefined;
	if (args && typeof args.command === "string") {
		const addr = typeof args.addr === "string" && args.addr ? ` @ ${args.addr}` : "";
		return `${args.command}${addr}`;
	}
	return undefined;
}

/** Live status of a record after an actual re-run (`/re verify`). */
export type VerifyStatus = "reproducible" | "tampered" | "unverifiable";

export interface VerifyRow {
	id: string;
	tool: string;
	command?: string;
	status: VerifyStatus;
	detail: string;
}

/**
 * Re-run every re-runnable evidence record against the currently-open binary and
 * classify it. The non-re-running classifications (provenance-only, legacy,
 * unbound, different-binary) are decided from recorded fields alone and never
 * touch rizin; the catalog and rizin session are loaded lazily only when a record
 * is genuinely re-runnable. Never throws — any error degrades that record to
 * "unverifiable".
 */
export async function buildVerification(ctx: ExtensionContext): Promise<VerifyRow[]> {
	const state = getState(ctx);
	const binaryPath = state.binaryPath ?? undefined;
	const currentSha = state.binarySha256 ?? (binaryPath ? await sha256File(binaryPath).catch(() => undefined) : undefined);

	const records = collectEvidence(branchEntries(ctx));
	const rows: VerifyRow[] = [];
	let catalog: Awaited<ReturnType<typeof loadCatalog>> | undefined;

	for (const ev of records) {
		const command = recordedCommand(ev);
		const base = { id: ev.id, tool: ev.tool, command };

		if (ev.tool !== "rizin_command" || !ev.reproHash) {
			const detail = ev.commands?.length
				? "provenance-only: tool ran multiple internal commands; re-run manually"
				: "legacy: no reproducible hash recorded";
			rows.push({ ...base, status: "unverifiable", detail });
			continue;
		}
		if (!ev.binarySha256) {
			rows.push({ ...base, status: "unverifiable", detail: "legacy: evidence not bound to a binary hash" });
			continue;
		}
		if (!currentSha) {
			rows.push({ ...base, status: "unverifiable", detail: "no binary open to verify against" });
			continue;
		}
		if (ev.binarySha256 !== currentSha) {
			rows.push({ ...base, status: "unverifiable", detail: `evidence was taken against a different binary — open sha ${ev.binarySha256.slice(0, 12)}… to verify` });
			continue;
		}

		const args = ev.args as { command?: unknown; addr?: unknown } | undefined;
		const cmd = typeof args?.command === "string" ? args.command : undefined;
		const addr = typeof args?.addr === "string" ? args.addr : undefined;
		if (!cmd) {
			rows.push({ ...base, status: "unverifiable", detail: "recorded args carry no command to re-run" });
			continue;
		}

		try {
			if (!catalog) catalog = await loadCatalog();
			const check = checkRizinCommand(catalog, cmd, addr);
			if (!check.ok) {
				rows.push({ ...base, status: "unverifiable", detail: `command no longer runnable in this rizin build: ${check.reason}` });
				continue;
			}
			const rz = await ensureRizin(ctx);
			const { output } = await rz.cmdWithStderr(check.line, { timeoutMs: VERIFY_COMMAND_TIMEOUT_MS });
			const rehash = canonicalHash(output, binaryPath);
			if (rehash === ev.reproHash) {
				rows.push({ ...base, status: "reproducible", detail: "re-run output hash matches" });
			} else {
				rows.push({ ...base, status: "tampered", detail: `output hash changed: recorded ${ev.reproHash.slice(0, 12)}… but re-run produced ${rehash.slice(0, 12)}…` });
			}
		} catch (err) {
			rows.push({ ...base, status: "unverifiable", detail: `re-run failed: ${err instanceof Error ? err.message : String(err)}` });
		}
	}
	return rows;
}

/**
 * `/re verify [--strict]`: run {@link buildVerification} and report. Interactive →
 * `ctx.ui.notify` a summary; headless → a console summary and `process.exitCode = 1`
 * on any FAIL (tampered/drifted), mirroring the report write-gate's exit signal.
 * UNVERIFIABLE (legacy / provenance-only / different-binary) does not fail the run
 * by default — only with `--strict`, so resuming an old session never spuriously
 * breaks CI.
 */
export async function verifyEvidence(ctx: ExtensionContext, opts: { strict?: boolean } = {}): Promise<VerifyRow[]> {
	const rows = await buildVerification(ctx);
	const reproducible = rows.filter((r) => r.status === "reproducible").length;
	const tampered = rows.filter((r) => r.status === "tampered");
	const unverifiable = rows.filter((r) => r.status === "unverifiable");

	const lines = [
		`omp-re: verify — ${reproducible} reproducible, ${tampered.length} FAILED, ${unverifiable.length} unverifiable (of ${rows.length} evidence record(s))`,
		...tampered.map((r) => `  FAIL ${r.id.slice(0, 8)} ${r.tool} \`${r.command ?? "?"}\`: ${r.detail}`),
	];
	if (opts.strict) lines.push(...unverifiable.map((r) => `  UNVERIFIABLE ${r.id.slice(0, 8)} ${r.tool}: ${r.detail}`));
	const text = lines.join("\n");
	const failed = tampered.length > 0 || (opts.strict === true && unverifiable.length > 0);

	if (ctx.hasUI) {
		ctx.ui.notify(text, failed ? "error" : "info");
	} else if (failed) {
		console.error(text);
		// Same deliberate headless signal the report gate uses (report.ts): a tampered or
		// unreproducible claim must fail a pipeline, not pass silently. process.exitCode, never process.exit.
		process.exitCode = 1;
	} else {
		console.log(text);
	}
	return rows;
}
