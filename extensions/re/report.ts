/**
 * Report generation with two hard properties: IOCs are defanged, and the
 * write gate refuses to emit a report containing any claim with zero backing
 * evidence. Every rendered claim anchors to the evidence entry it actually
 * came from (`[tool:id]`), tracked per claim.
 *
 * Evidence and annotations are read from the current session branch. Tool
 * output is read from the session artifact when the tool spilled one (the
 * untruncated output), else from the content-addressed blob store under
 * `getAgentDir()/re/blobs`. `writeReport` folds in the interactive-vs-
 * headless split, so the `/re report` handler needs only ctx and a path.
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import { branchEntries } from "./entries.ts";

/**
 * The full text a piece of evidence recorded: the session artifact when the
 * tool spilled one (untruncated), else the content-addressed blob
 * (`getAgentDir()/re/blobs/<hash[0:2]>/<hash[2:4]>/<hash>`, the same layout
 * evidence.ts writes). Never throws — a missing or unreadable source degrades
 * a capa/floss claim to "no extra evidence" rather than crashing the report.
 */
async function readEvidenceOutput(ctx: ExtensionContext, ev: EvidenceRecord): Promise<string | null> {
	if (ev.artifactId) {
		try {
			const path = await ctx.sessionManager.getArtifactPath(ev.artifactId);
			if (path) return await readFile(path, "utf8");
		} catch {
			// fall through to the blob
		}
	}
	if (!ev.outputHash) return null;
	const target = join(getAgentDir(), "re", "blobs", ev.outputHash.slice(0, 2), ev.outputHash.slice(2, 4), ev.outputHash);
	try {
		return await readFile(target, "utf8");
	} catch {
		return null;
	}
}

interface Claim {
	text: string;
	/** Evidence/annotation ids backing this claim. Empty means ungrounded — the write gate blocks on this. */
	evidenceIds: string[];
}

interface ReportSection {
	title: string;
	/** Free-form prose that precedes the claims list (e.g. a section intro sentence). Never itself gated — only `claims` are checked for grounding. */
	intro?: string;
	claims: Claim[];
}

interface EvidenceRecord {
	id: string;
	tool: string;
	ea?: string;
	outputHash?: string;
	artifactId?: string;
	summary: string;
}

interface AnnotationRecord {
	kind: string;
	ea: string;
	oldValue: string;
	newValue: string;
	evidenceId: string;
}

function collectEvidence(entries: readonly { type: string; customType?: string; data?: unknown }[]): EvidenceRecord[] {
	const out: EvidenceRecord[] = [];
	for (const entry of entries) {
		if (entry.type !== "custom" || entry.customType !== "re.evidence") continue;
		const data = entry.data as Partial<EvidenceRecord> | undefined;
		if (!data || typeof data.id !== "string" || typeof data.tool !== "string" || typeof data.summary !== "string") continue;
		out.push({ id: data.id, tool: data.tool, ea: data.ea, outputHash: data.outputHash, artifactId: data.artifactId, summary: data.summary });
	}
	return out;
}

/** Annotations on this branch that `/re undo` has not reversed. */
function collectAnnotations(entries: readonly { id?: string; type: string; customType?: string; data?: unknown }[]): AnnotationRecord[] {
	const undone = new Set<string>();
	for (const entry of entries) {
		if (entry.type !== "custom" || entry.customType !== "re.undo") continue;
		const target = (entry.data as { undidEntryId?: unknown } | undefined)?.undidEntryId;
		if (typeof target === "string") undone.add(target);
	}
	const out: AnnotationRecord[] = [];
	for (const entry of entries) {
		if (entry.type !== "custom" || entry.customType !== "re.annotation") continue;
		if (entry.id !== undefined && undone.has(entry.id)) continue;
		const data = entry.data as Partial<AnnotationRecord> | undefined;
		if (!data || typeof data.kind !== "string" || typeof data.ea !== "string") continue;
		out.push({
			kind: data.kind,
			ea: data.ea,
			oldValue: data.oldValue ?? "",
			newValue: data.newValue ?? "",
			evidenceId: data.evidenceId ?? "",
		});
	}
	return out;
}

// --- IOC extraction, ported from ioc.go ---

const PATH_PATTERN = /(?:\/[^/\s]+){3,}|(?:[A-Za-z]:\\[^\\\s]+){3,}/g;
const URL_PATTERN = /(?:https?|hxxps?):\/\/[\w\-._~:/?#[\]@!$&'()*+,;=%]+/gi;
const IPV4_PATTERN = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const REGKEY_PATTERN = /(?:HKLM|HKCU)\\[^\\\s]+/g;

// Non-global copies for defangIOC's shape checks: `.test()` on a `/g` regex
// is stateful (advances lastIndex across calls), which silently alternates
// between defanging and not defanging consecutive IOCs from the same list.
const URL_SHAPE = /^(?:https?|hxxps?):\/\//i;
const IPV4_SHAPE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/** Evidence text scanned here includes raw JSON (`ev.summary`), whose escaping/delimiters (trailing `",`, `),`, etc.) can hang off an otherwise-real match — trim them so an IOC never ends mid-punctuation. */
function trimTrailingPunctuation(match: string): string {
	return match.replace(/["'),;.]+$/, "");
}

function extractIOCsFromString(text: string): string[] {
	const iocs: string[] = [];
	for (const pattern of [PATH_PATTERN, URL_PATTERN, IPV4_PATTERN, REGKEY_PATTERN]) {
		for (const match of text.matchAll(pattern)) iocs.push(trimTrailingPunctuation(match[0]));
	}
	return iocs;
}

/**
 * Defang an IOC so it can't be accidentally clicked/resolved when pasted from
 * a report: http(s) -> hxxp(s), '.' -> '[.]' in hostnames/IPv4 literals, '@'
 * -> '[@]' in emails. Applied unconditionally per transformation — each only
 * matches the IOC shapes it's relevant to, so applying all three is safe
 * for paths and registry keys too (no-ops for those).
 */
export function defangIOC(ioc: string): string {
	let out = ioc.replace(/^https?/i, (scheme) => scheme.toLowerCase().replace("tt", "xx"));
	// The replace above only rewrites the scheme; still defang dots for URLs/IPv4 specifically to avoid mangling path/registry-key separators.
	if (URL_SHAPE.test(ioc) || IPV4_SHAPE.test(ioc)) {
		out = out.replace(/\./g, "[.]");
	}
	out = out.replace(/@/g, "[@]");
	return out;
}

function extractStringsFromJson(value: unknown): string[] {
	if (typeof value === "string") return [value];
	if (Array.isArray(value)) return value.flatMap(extractStringsFromJson);
	if (value && typeof value === "object") return Object.values(value).flatMap(extractStringsFromJson);
	return [];
}

/**
 * `tools-triage.ts`'s `capaFindings()` turns capa's real `{rules: {name: {meta}}}` map into a flat
 * array of `{name, meta}` records before it ever reaches an evidence blob — that array, not raw
 * capa JSON, is what's stored here. `meta.attack` entries are themselves objects (`{id, tactic,
 * technique, ...}`), not bare ATT&CK id strings.
 */
interface CapaFinding {
	name?: string;
	meta?: { name?: string; attack?: Array<string | { id?: string; technique?: string; subtechnique?: string }> };
}

/**
 * Evidence blobs are `${header line}\n${JSON body}` for every jsonResult-backed tool (see
 * format.ts) — never pure JSON. Try a direct parse first so a blob that genuinely is pure JSON
 * still works, then fall back to stripping the leading header line before parsing.
 */
function parseEvidenceJson(raw: string): unknown {
	try {
		return JSON.parse(raw);
	} catch {
		const nl = raw.indexOf("\n");
		if (nl === -1) throw new Error("not JSON");
		return JSON.parse(raw.slice(nl + 1));
	}
}

async function extractCapabilities(
	ctx: ExtensionContext,
	capaEvidence: EvidenceRecord[],
): Promise<{
	capabilities: string[];
	attackIds: string[];
	sourceByCapability: Map<string, string>;
	sourceByAttack: Map<string, string>;
	labelByAttack: Map<string, string>;
}> {
	const capSet = new Map<string, string>(); // capability name -> evidence id
	const attackSet = new Map<string, string>(); // attack id -> evidence id
	const labelSet = new Map<string, string>(); // attack id -> capa's own technique/subtechnique label

	for (const ev of capaEvidence) {
		const raw = await readEvidenceOutput(ctx, ev);
		if (!raw) continue;
		let findings: CapaFinding[];
		try {
			const parsed: unknown = parseEvidenceJson(raw);
			findings = Array.isArray(parsed) ? (parsed as CapaFinding[]) : [];
		} catch {
			continue; // truncated or malformed blob (e.g. output-size cap) — degrade to no capabilities, never crash
		}
		for (const rule of findings) {
			const name = rule.meta?.name?.trim() || rule.name?.trim();
			if (name) capSet.set(name, ev.id);
			for (const entry of rule.meta?.attack ?? []) {
				if (typeof entry === "string") {
					const id = entry.trim();
					if (id) attackSet.set(id, ev.id);
					continue;
				}
				const id = entry.id?.trim();
				if (!id) continue;
				attackSet.set(id, ev.id);
				const label = [entry.technique, entry.subtechnique].filter((s) => s?.trim()).join(": ");
				if (label) labelSet.set(id, label);
			}
		}
	}

	return {
		capabilities: [...capSet.keys()].sort(),
		attackIds: [...attackSet.keys()].sort(),
		sourceByCapability: capSet,
		sourceByAttack: attackSet,
		labelByAttack: labelSet,
	};
}

/** 22-entry MITRE ATT&CK lookup, ported verbatim from internal/report/attack.go. */
const MITRE_ATTACK: Record<string, string> = {
	T1059: "Command and Scripting Interpreter",
	"T1059.004": "Unix Shell",
	"T1059.003": "Windows Command Shell",
	"T1059.007": "JavaScript",
	T1204: "User Execution",
	T1086: "PowerShell",
	T1053: "Scheduled Task/Job",
	T1547: "Boot or Logon Autostart Execution",
	T1027: "Obfuscated Files or Information",
	T1082: "System Information Discovery",
	T1036: "Masquerading",
	T1543: "Create or Modify System Process",
	T1078: "Valid Accounts",
	T1112: "Modify Registry",
	T1006: "Direct Volume Access",
	T1003: "OS Credential Dumping",
	T1548: "Abuse Elevation Control Mechanism",
	T1070: "Indicator Removal on Host",
	T1021: "Remote Services",
	T1090: "Proxy",
	T1568: "Dynamic Resolution",
	T1480: "Execution Guardrails",
};

async function buildIOCClaims(
	ctx: ExtensionContext,
	evidence: EvidenceRecord[],
	annotations: AnnotationRecord[],
): Promise<Claim[]> {
	const claims: Claim[] = [];

	for (const ev of evidence) {
		const lowerTool = ev.tool.toLowerCase();
		const texts: string[] = [ev.summary];
		if (lowerTool === "floss" || lowerTool === "strings" || lowerTool === "triage_floss" || lowerTool === "list_strings") {
			const raw = await readEvidenceOutput(ctx, ev);
			if (raw) {
				try {
					texts.push(...extractStringsFromJson(parseEvidenceJson(raw)));
				} catch {
					texts.push(raw);
				}
			}
		}
		for (const text of texts) {
			for (const ioc of extractIOCsFromString(text)) {
				claims.push({ text: defangIOC(ioc), evidenceIds: [ev.id] });
			}
		}
	}

	for (const annotation of annotations) {
		for (const text of [annotation.oldValue, annotation.newValue]) {
			for (const ioc of extractIOCsFromString(text)) {
				claims.push({ text: defangIOC(ioc), evidenceIds: annotation.evidenceId ? [annotation.evidenceId] : [] });
			}
		}
	}

	const seen = new Map<string, Claim>();
	for (const claim of claims) {
		const existing = seen.get(claim.text);
		if (existing) existing.evidenceIds = [...new Set([...existing.evidenceIds, ...claim.evidenceIds])];
		else seen.set(claim.text, { text: claim.text, evidenceIds: [...claim.evidenceIds] });
	}
	return [...seen.values()].sort((a, b) => a.text.localeCompare(b.text));
}

interface BuiltReport {
	title: string;
	sections: ReportSection[];
	/** tool name per evidence/annotation id, for anchor rendering. */
	toolById: Map<string, string>;
}

async function buildReport(ctx: ExtensionContext): Promise<BuiltReport> {
	const sessionId = ctx.sessionManager.getSessionId();
	const entries = branchEntries(ctx);
	const evidence = collectEvidence(entries);
	const annotations = collectAnnotations(entries);

	const toolById = new Map<string, string>();
	for (const ev of evidence) toolById.set(ev.id, ev.tool);
	for (const annotation of annotations) if (annotation.evidenceId) toolById.set(annotation.evidenceId, toolById.get(annotation.evidenceId) ?? "annotation");

	const capaEvidence = evidence.filter((ev) => ev.tool.toLowerCase() === "capa" || ev.tool.toLowerCase() === "triage_capa");
	const sections: ReportSection[] = [];

	if (capaEvidence.length > 0) {
		const { capabilities, attackIds, sourceByCapability, sourceByAttack, labelByAttack } = await extractCapabilities(ctx, capaEvidence);
		const capClaims: Claim[] = capabilities.map((c) => ({ text: c, evidenceIds: [sourceByCapability.get(c)!] }));
		const attackClaims: Claim[] = attackIds.map((id) => ({
			text: `${id} — ${labelByAttack.get(id) ?? MITRE_ATTACK[id] ?? "(unmapped technique)"}`,
			evidenceIds: [sourceByAttack.get(id)!],
		}));
		const attackNote = attackIds.length > 0 ? ` mapping to ${attackIds.length} ATT&CK technique(s)` : "";
		sections.push({
			title: "Summary",
			intro: `Analysis performed using **capa** on the provided sample: ${capabilities.length} capability rule(s) matched${attackNote}. See Capabilities & MITRE ATT&CK Mapping below for the full, evidence-anchored list.`,
			claims: [],
		});
		if (capClaims.length + attackClaims.length > 0) {
			sections.push({ title: "Capabilities & MITRE ATT&CK Mapping", claims: [...capClaims, ...attackClaims] });
		}
	}

	const iocClaims = await buildIOCClaims(ctx, evidence, annotations);
	if (iocClaims.length > 0) {
		sections.push({ title: "Indicators of Compromise", claims: iocClaims });
	}

	sections.push({
		title: "Conclusion",
		intro: "This report was generated from an automated analysis session.",
		claims: [],
	});

	return {
		title: `Analysis Report — Session ${sessionId.length > 8 ? sessionId.slice(-8) : sessionId}`,
		sections,
		toolById,
	};
}

function formatMarkdown(report: BuiltReport): string {
	const lines: string[] = [`# ${report.title}`, ""];
	for (const section of report.sections) {
		lines.push(`## ${section.title}`, "");
		if (section.intro) lines.push(section.intro, "");
		if (section.claims.length > 0) {
			for (const claim of section.claims) {
				lines.push(`- ${claim.text}`);
				const anchors = claim.evidenceIds.map((id) => `[${report.toolById.get(id) ?? "unknown"}:${id}]`).join(" ");
				if (anchors) lines.push(`  **Evidence:** ${anchors}`);
			}
			lines.push("");
		}
	}
	return `${lines.join("\n").trimEnd()}\n`;
}

/** Every claim across the whole report must resolve to at least one evidence/annotation id. A partial or annotated report is not an acceptable substitute — the point of the gate is that an ungrounded report never reaches a ticket. */
function findUngroundedClaims(report: BuiltReport): Claim[] {
	const ungrounded: Claim[] = [];
	for (const section of report.sections) {
		for (const claim of section.claims) {
			if (claim.evidenceIds.length === 0) ungrounded.push(claim);
		}
	}
	return ungrounded;
}

/**
 * Build the analysis report for the current session and either write it to
 * `outputPath` or hand the rendered Markdown back through the UI/console —
 * this is the sole entry point a `/re report [path]` command handler needs,
 * folding in what index.ts's handler used to do with the returned result.
 *
 * The write gate is hard: if any claim in the report has zero evidence ids,
 * the whole report is withheld (never partially written) and the caller is
 * told exactly which claims are ungrounded. Headless failure is loud and
 * visible — console.error plus a non-zero exit code — never a silently
 * dropped report.
 */
export async function writeReport(ctx: ExtensionContext, outputPath?: string): Promise<void> {
	const report = await buildReport(ctx);
	const ungrounded = findUngroundedClaims(report);
	if (ungrounded.length > 0) {
		const message = [
			`omp-re: report withheld — ${ungrounded.length} claim(s) without evidence:`,
			...ungrounded.map((c) => `  - ${c.text}`),
		].join("\n");
		if (ctx.hasUI) ctx.ui.notify(message, "error");
		else {
			console.error(message);
			// Headless (e.g. `omp --print "/re report …"`): the withheld-report gate must fail the
			// run, not pass silently into a pipeline. omp exposes no exit-code API, so this is the
			// one deliberate place the extension signals the host — `process.exitCode`, never
			// `process.exit`, so omp's own shutdown still completes. Interactive callers get the
			// `ctx.ui.notify` above instead, where a non-zero exit would be meaningless.
			process.exitCode = 1;
		}
		return;
	}

	const markdown = formatMarkdown(report);
	let successMessage: string;
	if (outputPath) {
		try {
			await writeFile(outputPath, markdown, "utf8");
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			throw new Error(`omp-re: could not write report to ${outputPath}: ${reason}`);
		}
		successMessage = `omp-re: report written to ${outputPath}`;
	} else {
		successMessage = markdown;
	}
	if (ctx.hasUI) ctx.ui.notify(successMessage, "info");
	else console.log(successMessage);
}
