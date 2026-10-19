import { readFile, writeFile } from "node:fs/promises";
import nodePath from "node:path";

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
import { getAgentDir } from "@oh-my-pi/pi-utils";

import { fingerprintAnchor } from "./anchor.ts";
import type { AnchorFingerprint } from "./anchor.ts";
import {
  auditClaims,
  ephemeralJudge,
  flaggedVerdicts,
} from "./audit-claims.ts";
import type {
  AuditClaimInput,
  AuditMode,
  AuditOutcome,
  ClaimJudge,
} from "./audit-claims.ts";
import {
  branchEntries,
  collectEvidence,
  lastRecordedBinarySha256,
} from "./entries.ts";
import type { EvidenceRecord } from "./entries.ts";
import { collectFindings, findingNote } from "./findings.ts";
import type { FindingRecord } from "./findings.ts";
import { inSequence } from "./sequence.ts";
import { ensureRizin, getState } from "./state.ts";
import { recordedCommand, recordedStatus } from "./verify.ts";

/**
 * The full text a piece of evidence recorded: the session artifact when the
 * tool spilled one (untruncated), else the content-addressed blob
 * (`getAgentDir()/re/blobs/<hash[0:2]>/<hash[2:4]>/<hash>`, the same layout
 * evidence.ts writes). Never throws — a missing or unreadable source degrades
 * a capa/floss claim to "no extra evidence" rather than crashing the report.
 */
const readEvidenceOutput = async (
  ctx: ExtensionContext,
  ev: EvidenceRecord
): Promise<string | null> => {
  if (ev.artifactId) {
    try {
      const path = await ctx.sessionManager.getArtifactPath(ev.artifactId);
      if (path) {
        return await readFile(path, "utf-8");
      }
    } catch {
      // fall through to the blob
    }
  }
  if (!ev.outputHash) {
    return null;
  }
  const target = nodePath.join(
    getAgentDir(),
    "re",
    "blobs",
    ev.outputHash.slice(0, 2),
    ev.outputHash.slice(2, 4),
    ev.outputHash
  );
  try {
    return await readFile(target, "utf-8");
  } catch {
    return null;
  }
};

interface Claim {
  text: string;
  /** Evidence/annotation ids backing this claim. Empty means ungrounded — the write gate blocks on this. */
  evidenceIds: string[];
  /** Provenance line rendered under the claim (findings: confidence, inheritance, audit override). Display only — never part of the claim text, which is what carry matches on. */
  note?: string;
}

interface ReportSection {
  title: string;
  /** Free-form prose that precedes the claims list (e.g. a section intro sentence). Never itself gated — only `claims` are checked for grounding. */
  intro?: string;
  claims: Claim[];
}

interface AnnotationRecord {
  kind: string;
  ea: string;
  oldValue: string;
  newValue: string;
  evidenceId: string;
}

/** Annotations on this branch that `/re undo` has not reversed. */
const collectAnnotations = (
  entries: readonly {
    id?: string;
    type: string;
    customType?: string;
    data?: unknown;
  }[]
): AnnotationRecord[] => {
  const undone = new Set<string>();
  for (const entry of entries) {
    if (entry.type !== "custom" || entry.customType !== "re.undo") {
      continue;
    }
    const target = (entry.data as { undidEntryId?: unknown } | undefined)
      ?.undidEntryId;
    if (typeof target === "string") {
      undone.add(target);
    }
  }
  const out: AnnotationRecord[] = [];
  for (const entry of entries) {
    if (entry.type !== "custom" || entry.customType !== "re.annotation") {
      continue;
    }
    if (entry.id !== undefined && undone.has(entry.id)) {
      continue;
    }
    const data = entry.data as Partial<AnnotationRecord> | undefined;
    if (!data || typeof data.kind !== "string" || typeof data.ea !== "string") {
      continue;
    }
    out.push({
      ea: data.ea,
      evidenceId: data.evidenceId ?? "",
      kind: data.kind,
      newValue: data.newValue ?? "",
      oldValue: data.oldValue ?? "",
    });
  }
  return out;
};

// --- IOC extraction, ported from ioc.go ---

const PATH_PATTERN = /(?:\/[^/\s]+){3,}|(?:[A-Za-z]:\\[^\\\s]+){3,}/gu;
const URL_PATTERN = /(?:https?|hxxps?):\/\/[\w\-._~:/?#[\]@!$&'()*+,;=%]+/giu;
const IPV4_PATTERN = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/gu;
const REGKEY_PATTERN = /(?:HKLM|HKCU)\\[^\\\s]+/gu;

// Non-global copies for defangIOC's shape checks: `.test()` on a `/g` regex
// is stateful (advances lastIndex across calls), which silently alternates
// between defanging and not defanging consecutive IOCs from the same list.
const URL_SHAPE = /^(?:https?|hxxps?):\/\//iu;
const IPV4_SHAPE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/u;

/** Evidence text scanned here includes raw JSON (`ev.summary`), whose escaping/delimiters (trailing `",`, `),`, etc.) can hang off an otherwise-real match — trim them so an IOC never ends mid-punctuation. */
const trimTrailingPunctuation = (match: string): string =>
  match.replace(/["'),;.]+$/u, "");

const extractIOCsFromString = (text: string): string[] => {
  const iocs: string[] = [];
  for (const pattern of [
    PATH_PATTERN,
    URL_PATTERN,
    IPV4_PATTERN,
    REGKEY_PATTERN,
  ]) {
    for (const match of text.matchAll(pattern)) {
      iocs.push(trimTrailingPunctuation(match[0]));
    }
  }
  return iocs;
};

/**
 * Defang an IOC so it can't be accidentally clicked/resolved when pasted from
 * a report: http(s) -> hxxp(s), '.' -> '[.]' in hostnames/IPv4 literals, '@'
 * -> '[@]' in emails. Applied unconditionally per transformation — each only
 * matches the IOC shapes it's relevant to, so applying all three is safe
 * for paths and registry keys too (no-ops for those).
 */
export const defangIOC = (ioc: string): string => {
  let out = ioc.replace(/^https?/iu, (scheme) =>
    scheme.toLowerCase().replace("tt", "xx")
  );
  // The replace above only rewrites the scheme; still defang dots for URLs/IPv4 specifically to avoid mangling path/registry-key separators.
  if (URL_SHAPE.test(ioc) || IPV4_SHAPE.test(ioc)) {
    out = out.replaceAll(".", "[.]");
  }
  out = out.replaceAll("@", "[@]");
  return out;
};

const extractStringsFromJson = (value: unknown): string[] => {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap(extractStringsFromJson);
  }
  if (value && typeof value === "object") {
    return Object.values(value).flatMap(extractStringsFromJson);
  }
  return [];
};

/**
 * `tools-triage.ts`'s `capaFindings()` turns capa's real `{rules: {name: {meta}}}` map into a flat
 * array of `{name, meta}` records before it ever reaches an evidence blob — that array, not raw
 * capa JSON, is what's stored here. `meta.attack` entries are themselves objects (`{id, tactic,
 * technique, ...}`), not bare ATT&CK id strings.
 */
interface CapaFinding {
  name?: string;
  meta?: {
    name?: string;
    attack?: (
      | string
      | { id?: string; technique?: string; subtechnique?: string }
    )[];
  };
}

/**
 * Evidence blobs are `${header line}\n${JSON body}` for every jsonResult-backed tool (see
 * format.ts) — never pure JSON. Try a direct parse first so a blob that genuinely is pure JSON
 * still works, then fall back to stripping the leading header line before parsing.
 */
const parseEvidenceJson = (raw: string): unknown => {
  try {
    return JSON.parse(raw);
  } catch {
    const nl = raw.indexOf("\n");
    if (nl === -1) {
      throw new Error("not JSON");
    }
    return JSON.parse(raw.slice(nl + 1));
  }
};

const extractCapabilities = async (
  ctx: ExtensionContext,
  capaEvidence: EvidenceRecord[]
): Promise<{
  capabilities: string[];
  attackIds: string[];
  sourceByCapability: Map<string, string>;
  sourceByAttack: Map<string, string>;
  labelByAttack: Map<string, string>;
}> => {
  // capability name -> evidence id
  const capSet = new Map<string, string>();
  // attack id -> evidence id
  const attackSet = new Map<string, string>();
  // attack id -> capa's own technique/subtechnique label
  const labelSet = new Map<string, string>();

  await inSequence(capaEvidence, async (ev) => {
    const raw = await readEvidenceOutput(ctx, ev);
    if (!raw) {
      return;
    }
    let findings: CapaFinding[];
    try {
      const parsed: unknown = parseEvidenceJson(raw);
      findings = Array.isArray(parsed) ? (parsed as CapaFinding[]) : [];
    } catch {
      // truncated or malformed blob (e.g. output-size cap) — degrade to no capabilities, never crash
      return;
    }
    for (const rule of findings) {
      const name = rule.meta?.name?.trim() || rule.name?.trim();
      if (name) {
        capSet.set(name, ev.id);
      }
      for (const entry of rule.meta?.attack ?? []) {
        if (typeof entry === "string") {
          const id = entry.trim();
          if (id) {
            attackSet.set(id, ev.id);
          }
          continue;
        }
        const id = entry.id?.trim();
        if (!id) {
          continue;
        }
        attackSet.set(id, ev.id);
        const label = [entry.technique, entry.subtechnique]
          .filter((s) => s?.trim())
          .join(": ");
        if (label) {
          labelSet.set(id, label);
        }
      }
    }
  });

  return {
    attackIds: [...attackSet.keys()].toSorted(),
    capabilities: [...capSet.keys()].toSorted(),
    labelByAttack: labelSet,
    sourceByAttack: attackSet,
    sourceByCapability: capSet,
  };
};

/** 22-entry MITRE ATT&CK lookup, ported verbatim from internal/report/attack.go. */
const MITRE_ATTACK: Record<string, string> = {
  T1003: "OS Credential Dumping",
  T1006: "Direct Volume Access",
  T1021: "Remote Services",
  T1027: "Obfuscated Files or Information",
  T1036: "Masquerading",
  T1053: "Scheduled Task/Job",
  T1059: "Command and Scripting Interpreter",
  "T1059.003": "Windows Command Shell",
  "T1059.004": "Unix Shell",
  "T1059.007": "JavaScript",
  T1070: "Indicator Removal on Host",
  T1078: "Valid Accounts",
  T1082: "System Information Discovery",
  T1086: "PowerShell",
  T1090: "Proxy",
  T1112: "Modify Registry",
  T1204: "User Execution",
  T1480: "Execution Guardrails",
  T1543: "Create or Modify System Process",
  T1547: "Boot or Logon Autostart Execution",
  T1548: "Abuse Elevation Control Mechanism",
  T1568: "Dynamic Resolution",
};

const buildIOCClaims = async (
  ctx: ExtensionContext,
  evidence: EvidenceRecord[],
  annotations: AnnotationRecord[]
): Promise<Claim[]> => {
  const claims: Claim[] = [];

  await inSequence(evidence, async (ev) => {
    const lowerTool = ev.tool.toLowerCase();
    const texts: string[] = [ev.summary];
    if (
      lowerTool === "floss" ||
      lowerTool === "strings" ||
      lowerTool === "triage_floss" ||
      lowerTool === "list_strings"
    ) {
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
        claims.push({ evidenceIds: [ev.id], text: defangIOC(ioc) });
      }
    }
  });

  for (const annotation of annotations) {
    for (const text of [annotation.oldValue, annotation.newValue]) {
      for (const ioc of extractIOCsFromString(text)) {
        claims.push({
          evidenceIds: annotation.evidenceId ? [annotation.evidenceId] : [],
          text: defangIOC(ioc),
        });
      }
    }
  }

  const seen = new Map<string, Claim>();
  for (const claim of claims) {
    const existing = seen.get(claim.text);
    if (existing) {
      existing.evidenceIds = [
        ...new Set([...existing.evidenceIds, ...claim.evidenceIds]),
      ];
    } else {
      seen.set(claim.text, {
        evidenceIds: [...claim.evidenceIds],
        text: claim.text,
      });
    }
  }
  return [...seen.values()].toSorted((a, b) => a.text.localeCompare(b.text));
};

interface BuiltReport {
  title: string;
  sections: ReportSection[];
  /** tool name per evidence/annotation id, for anchor rendering. */
  toolById: Map<string, string>;
  /** full evidence record per id, for the verification manifest. */
  evidenceById: Map<string, EvidenceRecord>;
  /** SHA-256 of the binary this branch last opened, bound into the manifest. */
  binarySha256?: string;
  /** Live findings, for the manifest's `findings` block (what `/re carry --inherit` re-proves). */
  findings: FindingRecord[];
}

const buildReport = async (ctx: ExtensionContext): Promise<BuiltReport> => {
  const sessionId = ctx.sessionManager.getSessionId();
  const entries = branchEntries(ctx);
  const evidence = collectEvidence(entries);
  const annotations = collectAnnotations(entries);

  const toolById = new Map<string, string>();
  for (const ev of evidence) {
    toolById.set(ev.id, ev.tool);
  }
  for (const annotation of annotations) {
    if (annotation.evidenceId) {
      toolById.set(
        annotation.evidenceId,
        toolById.get(annotation.evidenceId) ?? "annotation"
      );
    }
  }

  const capaEvidence = evidence.filter(
    (ev) =>
      ev.tool.toLowerCase() === "capa" ||
      ev.tool.toLowerCase() === "triage_capa"
  );
  const sections: ReportSection[] = [];

  if (capaEvidence.length > 0) {
    const {
      capabilities,
      attackIds,
      sourceByCapability,
      sourceByAttack,
      labelByAttack,
    } = await extractCapabilities(ctx, capaEvidence);
    const capClaims: Claim[] = capabilities.map((c) => ({
      evidenceIds: [sourceByCapability.get(c)].filter((id) => id !== undefined),
      text: c,
    }));
    const attackClaims: Claim[] = attackIds.map((id) => ({
      evidenceIds: [sourceByAttack.get(id)].filter(
        (source) => source !== undefined
      ),
      text: `${id} — ${labelByAttack.get(id) ?? MITRE_ATTACK[id] ?? "(unmapped technique)"}`,
    }));
    const attackNote =
      attackIds.length > 0
        ? ` mapping to ${attackIds.length} ATT&CK technique(s)`
        : "";
    sections.push({
      claims: [],
      intro: `Analysis performed using **capa** on the provided sample: ${capabilities.length} capability rule(s) matched${attackNote}. See Capabilities & MITRE ATT&CK Mapping below for the full, evidence-anchored list.`,
      title: "Summary",
    });
    if (capClaims.length + attackClaims.length > 0) {
      sections.push({
        claims: [...capClaims, ...attackClaims],
        title: "Capabilities & MITRE ATT&CK Mapping",
      });
    }
  }

  // The model's own conclusions, recorded with record_finding: already gated at record time, and
  // gated again here like every other claim (existence, support audit, manifest).
  const findings = collectFindings(entries);
  if (findings.length > 0) {
    sections.push({
      claims: findings.map((f) => ({
        evidenceIds: [...f.evidenceIds],
        note: findingNote(f),
        text: f.claim,
      })),
      title: "Findings",
    });
  }

  const iocClaims = await buildIOCClaims(ctx, evidence, annotations);
  if (iocClaims.length > 0) {
    sections.push({ claims: iocClaims, title: "Indicators of Compromise" });
  }

  sections.push({
    claims: [],
    intro: "This report was generated from an automated analysis session.",
    title: "Conclusion",
  });

  return {
    binarySha256: lastRecordedBinarySha256(entries),
    evidenceById: new Map(evidence.map((ev) => [ev.id, ev])),
    findings,
    sections,
    title: `Analysis Report — Session ${sessionId.length > 8 ? sessionId.slice(-8) : sessionId}`,
    toolById,
  };
};

/**
 * Append the claim↔evidence support-audit summary note (prose, never a gated
 * claim, so {@link findUngroundedClaims} is unaffected). Silent when nothing was
 * audited (no evidence-backed claims); otherwise a one-line summary, or the
 * degrade note when the side turn was unavailable. Per-claim flags render inline
 * above, next to each claim.
 */
const appendClaimAudit = (lines: string[], outcome: AuditOutcome): void => {
  if (outcome.itemCount === 0) {
    return;
  }
  if (!outcome.audited) {
    lines.push(
      `> _Claim–evidence support unaudited — ${outcome.unauditedReason ?? "side turn unavailable"}._`,
      ""
    );
    return;
  }
  const vals = [...outcome.byIndex.values()];
  const supported = vals.filter((v) => v.verdict === "supported").length;
  const flagged = vals.filter(
    (v) => v.verdict === "unsupported" || v.verdict === "overreach"
  ).length;
  const unaudited = vals.filter((v) => v.verdict === "unaudited").length;
  lines.push(
    `> _Claim–evidence support audit: ${supported} supported, ${flagged} flagged, ${unaudited} unaudited._`,
    ""
  );
};

/** The manifest table's Command cell: the recorded rizin line(s) in inline code, or an em dash. */
const manifestCommandCell = (ev: EvidenceRecord): string => {
  const command = recordedCommand(ev);
  return command ? `\`${command}\`` : "—";
};

/**
 * Append the Verification Manifest: one row per distinct cited evidence id — the
 * table its `[tool:id]` anchors resolve into (command, reproducible-output hash,
 * binary hash, status) — so anyone with the binary can re-derive each claim
 * (`/re verify`, or re-running the command read-only). Prose/table only, never a
 * gated `claims` entry, so {@link findUngroundedClaims} is unaffected.
 */
const appendVerificationManifest = (
  lines: string[],
  report: BuiltReport
): void => {
  const citedIds: string[] = [];
  const seen = new Set<string>();
  for (const section of report.sections) {
    for (const claim of section.claims) {
      for (const id of claim.evidenceIds) {
        if (seen.has(id)) {
          continue;
        }
        seen.add(id);
        citedIds.push(id);
      }
    }
  }
  if (citedIds.length === 0) {
    return;
  }

  lines.push(
    "## Verification Manifest",
    "",
    `Binary SHA-256: \`${report.binarySha256 ?? "unbound (legacy)"}\``,
    "",
    "Each `reproducible` row can be re-derived from the binary: re-run its command read-only and compare the output hash (`/re verify`).",
    "",
    "| Evidence | Tool | Command | Output hash (repro) | Status |",
    "| --- | --- | --- | --- | --- |"
  );
  for (const id of citedIds) {
    const ev = report.evidenceById.get(id);
    const tool = report.toolById.get(id) ?? ev?.tool ?? "unknown";
    const command = ev ? manifestCommandCell(ev) : "—";
    const repro = ev?.reproHash ? `\`${ev.reproHash.slice(0, 12)}…\`` : "—";
    const status = ev ? recordedStatus(ev) : "unverifiable (legacy)";
    lines.push(
      `| \`${id.slice(0, 8)}\` | ${tool} | ${command} | ${repro} | ${status} |`
    );
  }
  lines.push("");
};

const formatMarkdown = (
  report: BuiltReport,
  outcome?: AuditOutcome
): string => {
  const lines: string[] = [`# ${report.title}`, ""];
  let claimIndex = 0;
  for (const section of report.sections) {
    lines.push(`## ${section.title}`, "");
    if (section.intro) {
      lines.push(section.intro, "");
    }
    if (section.claims.length > 0) {
      for (const claim of section.claims) {
        lines.push(`- ${claim.text}`);
        if (claim.note) {
          lines.push(`  _${claim.note}_`);
        }
        const anchors = claim.evidenceIds
          .map((id) => `[${report.toolById.get(id) ?? "unknown"}:${id}]`)
          .join(" ");
        if (anchors) {
          lines.push(`  **Evidence:** ${anchors}`);
        }
        const audit = outcome?.byIndex.get(claimIndex);
        if (
          audit &&
          (audit.verdict === "unsupported" || audit.verdict === "overreach")
        ) {
          lines.push(`  _⚠ Support audit: ${audit.verdict} — ${audit.reason}_`);
        }
        claimIndex += 1;
      }
      lines.push("");
    }
  }
  if (outcome) {
    appendClaimAudit(lines, outcome);
  }
  appendVerificationManifest(lines, report);
  return `${lines.join("\n").trimEnd()}\n`;
};

/** Every claim across the whole report must resolve to at least one evidence/annotation id. A partial or annotated report is not an acceptable substitute — the point of the gate is that an ungrounded report never reaches a ticket. */
const findUngroundedClaims = (report: BuiltReport): Claim[] => {
  const ungrounded: Claim[] = [];
  for (const section of report.sections) {
    for (const claim of section.claims) {
      if (claim.evidenceIds.length === 0) {
        ungrounded.push(claim);
      }
    }
  }
  return ungrounded;
};

/**
 * Assemble the audit input for the grounded claims: one entry per claim with at
 * least one resolvable evidence RECORD (annotation-only grounding carries no tool
 * output to audit), each carrying its cited records' summary + canonicalExcerpt
 * and — only when a judge will actually run — a short slice of the full output.
 * `index` is the claim's flat position across the report, which the verdicts map
 * back on and `formatMarkdown` renders flags by.
 */
const buildAuditInputs = async (
  ctx: ExtensionContext,
  report: BuiltReport,
  withFullText: boolean
): Promise<AuditClaimInput[]> => {
  const items: AuditClaimInput[] = [];
  const textCache = new Map<string, string | undefined>();
  let index = 0;
  await inSequence(report.sections, async (section) => {
    await inSequence(section.claims, async (claim) => {
      const evidence: AuditClaimInput["evidence"] = [];
      await inSequence(claim.evidenceIds, async (id) => {
        const ev = report.evidenceById.get(id);
        if (!ev) {
          return;
        }
        let fullText: string | undefined;
        if (withFullText) {
          if (!textCache.has(id)) {
            const raw = await readEvidenceOutput(ctx, ev);
            textCache.set(id, raw && raw.length <= 1200 ? raw : undefined);
          }
          fullText = textCache.get(id);
        }
        evidence.push({
          canonicalExcerpt: ev.canonicalExcerpt,
          fullText,
          id: ev.id,
          summary: ev.summary,
          tool: ev.tool,
        });
      });
      if (evidence.length > 0) {
        items.push({ claimText: claim.text, evidence, index });
      }
      index += 1;
    });
  });
  return items;
};

/** A `rizin_command` record's `{ command, addr }` params, or null for any other tool or a malformed record. */
const rizinCommandArgs = (
  ev: EvidenceRecord
): { command: string; addr?: string } | null => {
  if (ev.tool !== "rizin_command") {
    return null;
  }
  const args = ev.args as { command?: unknown; addr?: unknown } | undefined;
  if (!args || typeof args.command !== "string") {
    return null;
  }
  return typeof args.addr === "string" && args.addr
    ? { addr: args.addr, command: args.command }
    : { command: args.command };
};

/**
 * The machine-readable verification manifest written beside the report
 * (`<report>.manifest.json`): the binary hash plus one entry per distinct cited
 * evidence id — its command(s), reproducible-output hash, canonical excerpt, bound
 * binary hash, recorded status, and the claims it backs. The artifact "anyone with
 * the binary can re-derive it" from: re-run each command read-only, canonicalize,
 * hash, compare.
 */
const buildManifestJson = (
  report: BuiltReport,
  anchors: ReadonlyMap<string, AnchorFingerprint> = new Map()
): {
  binarySha256: string | null;
  /** The report's findings — what `/re carry --inherit` re-proves on another build. */
  findings: {
    id: string;
    claim: string;
    evidenceIds: string[];
    addr: string | null;
    confidence: string;
  }[];
  entries: {
    evidenceId: string;
    tool: string;
    /** `rizin_command` only: the structured `{ command, addr }` params, so `/re carry` re-runs the exact request against another binary. */
    args: { command: string; addr?: string } | null;
    command: string | null;
    commands: string[] | null;
    reproHash: string | null;
    canonicalExcerpt: string | null;
    shiftHash: string | null;
    /** Fingerprint of the function containing the command's anchor, so `/re carry` can find it again in another build. */
    anchor: AnchorFingerprint | null;
    binarySha256: string | null;
    status: string;
    claims: string[];
  }[];
} => {
  const claimsById = new Map<string, string[]>();
  for (const section of report.sections) {
    for (const claim of section.claims) {
      for (const id of claim.evidenceIds) {
        const list = claimsById.get(id) ?? [];
        list.push(claim.text);
        claimsById.set(id, list);
      }
    }
  }
  return {
    binarySha256: report.binarySha256 ?? null,
    entries: [...claimsById.keys()].map((id) => {
      const ev = report.evidenceById.get(id);
      return {
        anchor: anchors.get(id) ?? null,
        args: ev ? rizinCommandArgs(ev) : null,
        binarySha256: ev?.binarySha256 ?? null,
        canonicalExcerpt: ev?.canonicalExcerpt ?? null,
        claims: claimsById.get(id) ?? [],
        command: ev ? (recordedCommand(ev) ?? null) : null,
        commands: ev?.commands ?? null,
        evidenceId: id,
        reproHash: ev?.reproHash ?? null,
        shiftHash: ev?.shiftHash ?? null,
        status: ev ? recordedStatus(ev) : "unverifiable (legacy)",
        tool: report.toolById.get(id) ?? ev?.tool ?? "unknown",
      };
    }),
    findings: report.findings.map((f) => ({
      addr: f.addr ?? null,
      claim: f.claim,
      confidence: f.confidence,
      evidenceIds: f.evidenceIds,
      id: f.id,
    })),
  };
};

/**
 * Fingerprint the anchor of every cited, address-pinned `rizin_command` record —
 * but only while the binary that evidence was taken against is the one open, since
 * a fingerprint of any other build would point `/re carry` at the wrong code.
 * Best-effort: no open binary, a different binary, or any rizin failure just
 * leaves the entry without an anchor (carry then can't relocate it).
 */
const collectAnchors = async (
  ctx: ExtensionContext,
  report: BuiltReport
): Promise<Map<string, AnchorFingerprint>> => {
  const anchors = new Map<string, AnchorFingerprint>();
  const state = getState(ctx);
  if (!state.binaryPath || !state.binarySha256) {
    return anchors;
  }
  const cited = new Set(
    report.sections.flatMap((s) => s.claims.flatMap((c) => c.evidenceIds))
  );
  try {
    await inSequence(cited, async (id) => {
      const ev = report.evidenceById.get(id);
      if (!ev || ev.binarySha256 !== state.binarySha256) {
        return;
      }
      const addr = rizinCommandArgs(ev)?.addr;
      if (!addr) {
        return;
      }
      const fp = await fingerprintAnchor(await ensureRizin(ctx), addr);
      if (fp) {
        anchors.set(id, fp);
      }
    });
  } catch {
    // rizin unavailable: the manifest is still complete, just without relocation fingerprints.
  }
  return anchors;
};

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
export const writeReport = async (
  ctx: ExtensionContext,
  outputPath?: string,
  opts?: { audit?: AuditMode; judge?: ClaimJudge }
): Promise<void> => {
  const report = await buildReport(ctx);
  const ungrounded = findUngroundedClaims(report);
  if (ungrounded.length > 0) {
    const message = [
      `omp-re: report withheld — ${ungrounded.length} claim(s) without evidence:`,
      ...ungrounded.map((c) => `  - ${c.text}`),
    ].join("\n");
    if (ctx.hasUI) {
      ctx.ui.notify(message, "error");
    } else {
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

  // Third gate (semantic): does each grounded claim's cited evidence actually SUPPORT it? Runs only
  // after the two deterministic gates pass. Advisory by default (flags claims, never blocks); strict
  // withholds the whole report on an explicit unsupported/overreach — but fails OPEN on any infra or
  // parse failure (the audit degrades to "unaudited"), so a strict report stays emittable when the
  // side turn or model is unavailable. The two deterministic gates stay blocking in every mode.
  const mode = opts?.audit ?? "advisory";
  const judge = mode === "off" ? null : (opts?.judge ?? ephemeralJudge(ctx));
  const items =
    mode === "off" ? [] : await buildAuditInputs(ctx, report, judge !== null);
  const outcome = await auditClaims(items, judge, mode);
  if (mode === "strict") {
    const flagged = flaggedVerdicts(outcome);
    if (flagged.length > 0) {
      const flat = report.sections.flatMap((s) => s.claims);
      const message = [
        `omp-re: report withheld — ${flagged.length} claim(s) not supported by their cited evidence:`,
        ...flagged.map(
          (v) => `  - [${v.verdict}] ${flat[v.index]?.text ?? ""} — ${v.reason}`
        ),
      ].join("\n");
      if (ctx.hasUI) {
        ctx.ui.notify(message, "error");
      } else {
        console.error(message);
        process.exitCode = 1;
      }
      return;
    }
  }

  const markdown = formatMarkdown(report, outcome);
  let successMessage: string;
  if (outputPath) {
    try {
      await writeFile(outputPath, markdown, "utf-8");
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(
        `omp-re: could not write report to ${outputPath}: ${reason}`,
        { cause: error }
      );
    }
    const manifestPath = `${outputPath}.manifest.json`;
    let manifestNote = ` (+ ${manifestPath})`;
    try {
      await writeFile(
        manifestPath,
        `${JSON.stringify(buildManifestJson(report, await collectAnchors(ctx, report)), null, 2)}\n`,
        "utf-8"
      );
    } catch (error) {
      // The report itself is already on disk; a sidecar failure (disk full, EACCES) must not undo that — note it and carry on.
      manifestNote = ` (manifest sidecar not written: ${error instanceof Error ? error.message : String(error)})`;
    }
    successMessage = `omp-re: report written to ${outputPath}${manifestNote}`;
  } else {
    successMessage = markdown;
  }
  if (ctx.hasUI) {
    ctx.ui.notify(successMessage, "info");
  } else {
    console.log(successMessage);
  }
};
