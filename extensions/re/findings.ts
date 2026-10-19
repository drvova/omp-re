/**
 * First-class findings: the model's own conclusions as gated, carried claims.
 *
 * Until now a report's claims came only from machinery — capa capability lines
 * and IOC strings mined from evidence summaries. The conclusions that matter in
 * reverse engineering ("checksum is djb2", "the config is RC4-decrypted with a
 * key from the volume serial") lived only in chat, outside every gate. A finding
 * puts one into the record:
 *
 * - `record_finding` takes a claim, the evidence ids it rests on, and optionally
 *   an address and a confidence. It is gated AT RECORD TIME, while the model can
 *   still act on the answer: every id must resolve on this branch (existence),
 *   be taken against the open binary (binding), and the claim goes to the same
 *   side-turn support audit `/re report` uses — an unsupported or overreaching
 *   claim is refused with the auditor's reason unless the model overrides it with
 *   a written justification, which is kept and shown. Reproducibility is reported
 *   (only `rizin_command` evidence is machine-verifiable, and only that carries).
 * - `retract_finding` withdraws one, with a reason; `supersedes` revises one.
 * - Live findings become the report's **Findings** section, so they pass the
 *   report's own gates, land in the verification manifest with their anchor
 *   fingerprints, and `/re carry` tracks them onto the next build; `--inherit`
 *   re-proves the ones that hold there (carry.ts).
 *
 * Findings are `re.finding` / `re.finding.retract` custom entries, read from the
 * current branch like all other omp-re state, so `/tree` and branching behave.
 */
import { randomUUID } from "node:crypto";

import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import { auditClaims, ephemeralJudge } from "./audit-claims.ts";
import type { AuditClaimInput, ClaimJudge } from "./audit-claims.ts";
import { branchEntries, collectEvidence } from "./entries.ts";
import type { EvidenceRecord } from "./entries.ts";
import { recordEvidence } from "./evidence.ts";
import { plainResult } from "./format.ts";
import type { ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { inSequence } from "./sequence.ts";
import { getState } from "./state.ts";
import { runRizinCommand } from "./tools-rizin.ts";
import { recordedStatus } from "./verify.ts";

export type FindingConfidence = "confirmed" | "likely" | "speculative";

/** Where an inherited finding came from: the report's binary, the finding there, and how it carried. */
export interface FindingInheritance {
  fromBinarySha256: string | null;
  fromFindingId: string;
  carryStatus: "holds" | "relocated";
  relocation?: { from: string; to: string; similarity: number };
}

export interface FindingRecord {
  id: string;
  claim: string;
  evidenceIds: string[];
  addr?: string;
  confidence: FindingConfidence;
  /** The finding this one revises; the superseded one leaves the report. */
  supersedes?: string;
  audit?: { verdict: string; reason: string; override?: string };
  binarySha256?: string;
  inherited?: FindingInheritance;
  /** adopt_finding: who made the claim before it was re-proven here (e.g. "re-analyst"). */
  adoptedFrom?: string;
}

const CONFIDENCES: ReadonlySet<FindingConfidence> = new Set([
  "confirmed",
  "likely",
  "speculative",
]);
/** Shortest evidence/finding id prefix accepted — the panels show 8 characters. */
const MIN_ID_PREFIX = 6;

/**
 * The live findings on a branch, in order: every `re.finding` minus those later
 * superseded by another finding or withdrawn by a `re.finding.retract`.
 */
export const collectFindings = (
  entries: readonly { type: string; customType?: string; data?: unknown }[]
): FindingRecord[] => {
  const live = new Map<string, FindingRecord>();
  for (const entry of entries) {
    if (entry.type !== "custom") {
      continue;
    }
    if (entry.customType === "re.finding.retract") {
      const id = (entry.data as { id?: unknown } | undefined)?.id;
      if (typeof id === "string") {
        live.delete(id);
      }
      continue;
    }
    if (entry.customType !== "re.finding") {
      continue;
    }
    const d = entry.data as Partial<FindingRecord> | undefined;
    if (
      !d ||
      typeof d.id !== "string" ||
      typeof d.claim !== "string" ||
      !Array.isArray(d.evidenceIds)
    ) {
      continue;
    }
    if (typeof d.supersedes === "string") {
      live.delete(d.supersedes);
    }
    live.set(d.id, {
      claim: d.claim,
      evidenceIds: d.evidenceIds.filter(
        (x): x is string => typeof x === "string"
      ),
      id: d.id,
      ...(typeof d.addr === "string" ? { addr: d.addr } : {}),
      confidence: CONFIDENCES.has(d.confidence as FindingConfidence)
        ? (d.confidence as FindingConfidence)
        : "likely",
      ...(typeof d.supersedes === "string" ? { supersedes: d.supersedes } : {}),
      ...(d.audit && typeof d.audit === "object" ? { audit: d.audit } : {}),
      ...(typeof d.binarySha256 === "string"
        ? { binarySha256: d.binarySha256 }
        : {}),
      ...(d.inherited && typeof d.inherited === "object"
        ? { inherited: d.inherited }
        : {}),
      ...(typeof d.adoptedFrom === "string"
        ? { adoptedFrom: d.adoptedFrom }
        : {}),
    });
  }
  return [...live.values()];
};

/** Resolve one id by exact match or unique prefix (≥ {@link MIN_ID_PREFIX} chars). */
const resolveId = <T extends { id: string }>(
  items: readonly T[],
  id: string
): { ok: true; item: T } | { ok: false; reason: string } => {
  const exact = items.find((i) => i.id === id);
  if (exact) {
    return { item: exact, ok: true };
  }
  if (id.length < MIN_ID_PREFIX) {
    return {
      ok: false,
      reason: `${JSON.stringify(id)} is too short (use at least ${MIN_ID_PREFIX} characters of the id)`,
    };
  }
  const matches = items.filter((i) => i.id.startsWith(id));
  if (matches.length === 1) {
    return { item: matches[0], ok: true };
  }
  return {
    ok: false,
    reason:
      matches.length === 0
        ? `no id starting ${JSON.stringify(id)} on this branch`
        : `${JSON.stringify(id)} is ambiguous (${matches.length} matches)`,
  };
};

/** One-line rendering of a finding's provenance for the report and tool results: confidence, inheritance, and any audit override. */
export const findingNote = (f: FindingRecord): string => {
  const parts = [`confidence: ${f.confidence}`];
  if (f.addr) {
    parts.push(`at \`${f.addr}\``);
  }
  if (f.inherited) {
    const from = f.inherited.fromBinarySha256
      ? `\`${f.inherited.fromBinarySha256.slice(0, 12)}…\``
      : "an earlier build";
    parts.push(
      `inherited from ${from}, re-verified on this build (${f.inherited.carryStatus}${f.inherited.relocation ? `: ${f.inherited.relocation.from} → ${f.inherited.relocation.to}` : ""})`
    );
  }
  if (f.adoptedFrom) {
    parts.push(`adopted from ${f.adoptedFrom}, re-proven in this session`);
  }
  if (f.audit?.override) {
    parts.push(
      `recorded over a support-audit "${f.audit.verdict}" verdict — justification: ${f.audit.override}`
    );
  }
  return parts.join(" · ");
};

interface FindingInput {
  claim: string;
  addr?: string;
  confidence?: FindingConfidence;
  supersedes?: string;
  override_audit?: string;
  /** adopt_finding only: who made the claim originally (e.g. "re-analyst"). */
  adoptedFrom?: string;
}

/**
 * The gate every recorded finding passes after its evidence is resolved: the
 * side-turn support audit (refused on unsupported/overreach unless overridden
 * with a justification; fails open to "unaudited"), then the `re.finding` entry
 * and a result that says whether the finding can carry. Shared by
 * `record_finding` and `adopt_finding`, so the two can never gate differently.
 */
const gateAndRecord = async (
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  options: FindingToolOptions,
  tool: string,
  input: FindingInput,
  resolved: readonly EvidenceRecord[]
): Promise<ReToolResult> => {
  const item: AuditClaimInput = {
    claimText: input.claim,
    evidence: resolved.map((ev) => ({
      canonicalExcerpt: ev.canonicalExcerpt,
      id: ev.id,
      summary: ev.summary,
      tool: ev.tool,
    })),
    index: 0,
  };
  const judge = (options.judge ?? ephemeralJudge)(ctx);
  const outcome = await auditClaims([item], judge, "advisory");
  const verdict = outcome.byIndex.get(0);
  const refused =
    verdict &&
    (verdict.verdict === "unsupported" || verdict.verdict === "overreach");
  const evidenceList = resolved.map((ev) => ev.id.slice(0, 8)).join(", ");
  if (refused && !input.override_audit) {
    return {
      ...plainResult(
        `${tool}: NOT recorded — the support auditor judged this claim ${verdict.verdict}: ${verdict.reason}\nNarrow the claim to what the evidence shows, cite evidence that establishes it, or (only if the auditor is wrong) pass override_audit with a one-line justification.${tool === "adopt_finding" ? `\nThe re-run evidence was recorded (${evidenceList}); cite it in record_finding to record a narrower claim.` : ""}`
      ),
      isError: true,
    };
  }

  const id = randomUUID();
  const openSha = getState(ctx).binarySha256 ?? undefined;
  const audit = verdict
    ? {
        reason: verdict.reason,
        verdict: verdict.verdict,
        ...(refused && input.override_audit
          ? { override: input.override_audit }
          : {}),
      }
    : {
        reason: outcome.unauditedReason ?? "side turn unavailable",
        verdict: "unaudited",
      };
  const record: FindingRecord = {
    claim: input.claim,
    evidenceIds: resolved.map((ev) => ev.id),
    id,
    ...(input.addr ? { addr: input.addr } : {}),
    confidence: input.confidence ?? "likely",
    ...(input.supersedes ? { supersedes: input.supersedes } : {}),
    audit,
    ...(openSha ? { binarySha256: openSha } : {}),
    ...(input.adoptedFrom ? { adoptedFrom: input.adoptedFrom } : {}),
  };
  pi.appendEntry("re.finding", record);

  const reproducible = resolved.filter(
    (ev) => recordedStatus(ev) === "reproducible"
  ).length;
  const lines = [
    `${tool}: recorded ${id.slice(0, 8)}${input.supersedes ? ` (supersedes ${input.supersedes.slice(0, 8)})` : ""}`,
    `claim: ${input.claim}`,
    ...(input.adoptedFrom
      ? [
          `adopted from ${input.adoptedFrom}: re-proven in this session on evidence ${evidenceList}`,
        ]
      : []),
    `support audit: ${audit.verdict}${audit.reason ? ` — ${audit.reason}` : ""}${refused ? " (overridden)" : ""}`,
    reproducible > 0
      ? `evidence: ${reproducible} of ${resolved.length} machine-reproducible — this finding will carry to the next build (/re carry)`
      : `evidence: none machine-reproducible — the finding is in the report but cannot carry; cite rizin_command evidence to make it carryable`,
  ];
  return plainResult(lines.join("\n"), input.addr);
};

export interface FindingToolOptions {
  /** The support auditor; defaults to the session's ephemeral side turn. A test seam, like writeReport's `judge`. */
  judge?: (ctx: ExtensionContext) => ClaimJudge | null;
}

export const registerFindingTools = (
  pi: ExtensionAPI,
  options: FindingToolOptions = {}
): void => {
  const z = pi.zod;
  const recordFindingParams = z.object({
    addr: z
      .string()
      .optional()
      .describe(
        "The address or function the finding is about, when it is about one."
      ),
    claim: z
      .string()
      .min(1)
      .max(600)
      .describe(
        "The conclusion, stated as narrowly as the evidence supports — one finding per claim."
      ),
    confidence: z
      .enum(["confirmed", "likely", "speculative"])
      .optional()
      .describe("How sure the claim is (default likely)."),
    evidence: z
      .array(z.string())
      .min(1)
      .max(16)
      .describe(
        "Evidence ids the claim rests on: the 8-character id in the `[evidence xxxxxxxx]` tag at the end of each RE tool result."
      ),
    override_audit: z
      .string()
      .optional()
      .describe(
        "Only if the support auditor refused this claim and you are confident it is wrong: a one-line justification, recorded and shown beside the finding."
      ),
    supersedes: z
      .string()
      .optional()
      .describe(
        "Id of an earlier finding this one revises; the old one leaves the report."
      ),
  });
  const adoptFindingParams = z.object({
    addr: z
      .string()
      .optional()
      .describe("The address or function the finding is about."),
    claim: z
      .string()
      .min(1)
      .max(600)
      .describe("The finding's claim, as narrowly as its evidence supports."),
    commands: z
      .array(
        z.object({
          addr: z
            .string()
            .optional()
            .describe("Where to run it (address or name)."),
          command: z
            .string()
            .describe("A read-only rizin command, e.g. `pdf` or `px 64`."),
        })
      )
      .min(1)
      .max(8)
      .describe(
        "The rizin command(s) that reproduce the finding's evidence — re-run here and recorded as this session's evidence."
      ),
    confidence: z
      .enum(["confirmed", "likely", "speculative", "possible"])
      .optional()
      .describe(
        "How sure the claim is (default likely); the re-analyst's `possible` is taken as speculative."
      ),
    expect_sha256: z
      .string()
      .optional()
      .describe(
        "SHA-256 of the binary the finding was made on (the subagent's sha256); refused if a different binary is open."
      ),
    override_audit: z
      .string()
      .optional()
      .describe(
        "Only if the support auditor refused the claim and you are confident it is wrong: a one-line justification."
      ),
    source: z
      .string()
      .max(80)
      .optional()
      .describe('Who made the finding originally, e.g. "re-analyst".'),
  });
  const retractFindingParams = z.object({
    id: z
      .string()
      .describe("Id (or ≥6-char prefix) of the finding to withdraw."),
    reason: z.string().min(1).max(300).describe("Why it no longer stands."),
  });

  pi.registerTool({
    approval: "read",
    description:
      "Record an analytical conclusion as a finding in the report, backed by the evidence ids that establish it — each RE tool result ends with an `[evidence xxxxxxxx]` tag; cite those ids. Refused when an id doesn't resolve or was taken against a different binary; the claim is then checked by a support auditor and refused, with the reason, if the evidence doesn't establish it or it claims more than the evidence shows — narrow the claim or cite better evidence. Cite rizin_command evidence where you can: only that is machine-reproducible, so only those findings carry to the next build (/re carry). Use supersedes to revise a finding; retract_finding to withdraw one.",
    label: "Record Finding",
    loadMode: "essential",
    name: "record_finding",
    parameters: recordFindingParams,
    ...reRenderers({ body: "text", subject: "claim", title: "record_finding" }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const entries = branchEntries(ctx);
      const evidence = collectEvidence(entries);
      const resolved: EvidenceRecord[] = [];
      const problems: string[] = [];
      for (const raw of params.evidence) {
        const r = resolveId(evidence, raw.trim());
        if (!r.ok) {
          problems.push(r.reason);
        } else if (!resolved.includes(r.item)) {
          resolved.push(r.item);
        }
      }
      if (problems.length > 0) {
        throw new Error(
          `omp-re: record_finding: evidence not found — ${problems.join("; ")}. Cite ids from RE tool results on this branch (/re evidence lists them).`
        );
      }

      // Binding: a finding is about the open binary, so its evidence must be too.
      const openSha = getState(ctx).binarySha256 ?? undefined;
      const foreign = openSha
        ? resolved.filter(
            (ev) => ev.binarySha256 && ev.binarySha256 !== openSha
          )
        : [];
      if (foreign.length > 0) {
        throw new Error(
          `omp-re: record_finding: evidence ${foreign.map((ev) => ev.id.slice(0, 8)).join(", ")} was taken against a different binary than the one open — re-gather it on this binary.`
        );
      }

      let supersedes: string | undefined;
      if (params.supersedes) {
        const r = resolveId(collectFindings(entries), params.supersedes.trim());
        if (!r.ok) {
          throw new Error(
            `omp-re: record_finding: cannot supersede — ${r.reason}`
          );
        }
        supersedes = r.item.id;
      }

      return gateAndRecord(
        pi,
        ctx,
        options,
        "record_finding",
        { ...params, supersedes },
        resolved
      );
    },
  });

  pi.registerTool({
    approval: "read",
    description:
      "Adopt a finding made elsewhere — typically one returned by the re-analyst subagent, whose evidence lives in its own session — by re-proving it here: each given rizin command is re-run read-only on the open binary and recorded as evidence in THIS session, then the claim passes the same gates as record_finding (support audit included). Refused if expect_sha256 doesn't match the open binary or a command fails. Use the subagent's `reproduce` lines as the commands.",
    label: "Adopt Finding",
    loadMode: "essential",
    name: "adopt_finding",
    parameters: adoptFindingParams,
    ...reRenderers({ body: "text", subject: "claim", title: "adopt_finding" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const openSha = getState(ctx).binarySha256 ?? undefined;
      if (
        params.expect_sha256 &&
        openSha &&
        params.expect_sha256.toLowerCase() !== openSha
      ) {
        throw new Error(
          `omp-re: adopt_finding: the finding was made on binary ${params.expect_sha256.slice(0, 12)}… but ${openSha.slice(0, 12)}… is open — open the same binary first.`
        );
      }
      // Re-prove: every command runs through rizin_command's own read-only gate and is recorded
      // exactly as a live rizin_command result, bound to the open binary. A claim is adopted only
      // on evidence this session observed itself.
      const resolved: EvidenceRecord[] = [];
      await inSequence(params.commands, async ({ command, addr }) => {
        const res = await runRizinCommand(ctx, command, addr, signal);
        if (res.isError) {
          const said = res.content
            .map((c) => ("text" in c ? c.text : ""))
            .join(" ")
            .slice(0, 300);
          throw new Error(
            `omp-re: adopt_finding: \`${command}${addr ? ` @ ${addr}` : ""}\` failed here: ${said}`
          );
        }
        const evidenceId = await recordEvidence(
          pi,
          ctx,
          "rizin_command",
          addr ? { addr, command } : { command },
          res.content,
          res.details
        );
        const record = collectEvidence(branchEntries(ctx)).find(
          (ev) => ev.id === evidenceId
        );
        if (record) {
          resolved.push(record);
        }
      });
      return gateAndRecord(
        pi,
        ctx,
        options,
        "adopt_finding",
        {
          ...params,
          adoptedFrom: params.source ?? "an external analysis",
          confidence:
            params.confidence === "possible"
              ? "speculative"
              : params.confidence,
        },
        resolved
      );
    },
  });

  pi.registerTool({
    approval: "read",
    description:
      "Withdraw a finding recorded earlier with record_finding (it leaves the report). Give the reason; to revise rather than withdraw, call record_finding with supersedes instead.",
    label: "Retract Finding",
    loadMode: "essential",
    name: "retract_finding",
    parameters: retractFindingParams,
    ...reRenderers({ body: "text", subject: "id", title: "retract_finding" }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const r = resolveId(
        collectFindings(branchEntries(ctx)),
        params.id.trim()
      );
      if (!r.ok) {
        throw new Error(`omp-re: retract_finding: ${r.reason}`);
      }
      pi.appendEntry("re.finding.retract", {
        id: r.item.id,
        reason: params.reason,
      });
      return plainResult(
        `retract_finding: withdrew ${r.item.id.slice(0, 8)} — ${r.item.claim}\nreason: ${params.reason}`
      );
    },
  });
};

/** Live findings on the current branch. */
export const liveFindings = (ctx: ExtensionContext): FindingRecord[] =>
  collectFindings(branchEntries(ctx));
