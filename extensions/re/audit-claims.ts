/**
 * The claim↔evidence SUPPORT audit — the third grounding gate for `/re report`,
 * layered strictly AFTER the two deterministic gates (existence: a claim with no
 * evidence id withholds the report; reproducibility: reproHash + `/re verify`).
 * Those gates prove a claim is *cited* and *reproducible*; this one asks the
 * remaining question they cannot: does the cited evidence actually *support* what
 * the claim says, or is it a misattribution / overreach?
 *
 * The judge is omp's `ctx.runEphemeralTurn` — a `/btw`-style side turn that runs
 * on the session's model without appending to history or executing tools. omp has
 * no structured-output path for it, so the prompt asks for JSON in prose and the
 * reply is parsed defensively (fenced block, then a balanced scan), exactly as
 * omp's own `omfg` does. Everything here is model-agnostic given an injected
 * {@link ClaimJudge}, so the report path stays unit-testable without a live model.
 *
 * Fail-open by design: whenever the side turn is unavailable (no host method, no
 * model, a throw, or an unparseable reply) the audit degrades to "unaudited" and
 * NEVER blocks or weakens the two deterministic gates. In strict mode only an
 * explicit `unsupported`/`overreach` verdict withholds — an infrastructure or
 * parse failure never fails closed, so a strict report stays emittable.
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";

export type ClaimVerdict =
  | "supported"
  | "unsupported"
  | "overreach"
  | "unaudited";

export interface AuditEvidence {
  id: string;
  tool: string;
  summary: string;
  canonicalExcerpt?: string;
  fullText?: string;
}

export interface AuditClaimInput {
  /** Flat position of the claim across the whole report (sections in order, claims in order); the key verdicts are matched back on. */
  index: number;
  claimText: string;
  evidence: AuditEvidence[];
}

export interface ClaimAudit {
  index: number;
  verdict: ClaimVerdict;
  reason: string;
}

export type AuditMode = "off" | "advisory" | "strict";

/** Judges a batch of claims against their evidence; returns one verdict per claim, or null to degrade the whole audit to "unaudited". */
export type ClaimJudge = (
  items: readonly AuditClaimInput[]
) => Promise<ClaimAudit[] | null>;

export interface AuditOutcome {
  audited: boolean;
  unauditedReason?: string;
  byIndex: Map<number, ClaimAudit>;
  /** How many evidence-backed claims were put to the audit (0 => nothing to audit; no note rendered). */
  itemCount: number;
}

const AUDIT_TIMEOUT_MS = 30_000;
const EXCERPT_MAX = 800;
const REAL_VERDICTS = new Set<ClaimVerdict>([
  "supported",
  "unsupported",
  "overreach",
]);

const truncate = (text: string, max: number): string =>
  text.length <= max ? text : `${text.slice(0, max)}…`;

/** The adversarial per-claim prompt. One batched call over all evidence-backed claims; JSON is requested in prose because the side turn has no structured-output path. */
export const buildAuditPrompt = (items: readonly AuditClaimInput[]): string => {
  const lines: string[] = [
    "You are a strict reverse-engineering report auditor. For EACH numbered claim below, judge ONLY whether the quoted evidence actually supports what the claim asserts. Judge solely against the quoted evidence — do not use outside knowledge, and do not run or imagine any tools.",
    'Verdicts: "supported" = the evidence directly establishes the claim; "overreach" = the evidence is related but the claim asserts more than the evidence shows (stronger, broader, or attributive); "unsupported" = the evidence does not establish the claim (misattribution or wrong evidence).',
    "Reply with ONLY a JSON array, one object per claim, and no prose outside it:",
    '[{"index": <int>, "verdict": "supported|unsupported|overreach", "reason": "<=1 line"}]',
    "",
  ];
  for (const item of items) {
    lines.push(`CLAIM ${item.index}: ${item.claimText}`);
    if (item.evidence.length === 0) {
      lines.push("  (no evidence quoted)");
    }
    for (const ev of item.evidence) {
      lines.push(
        `  evidence [${ev.tool}:${ev.id.slice(0, 8)}] summary: ${ev.summary}`
      );
      const excerpt = ev.canonicalExcerpt ?? ev.fullText;
      if (excerpt) {
        lines.push(`    output: ${truncate(excerpt, EXCERPT_MAX)}`);
      }
    }
  }
  return lines.join("\n");
};

/** Extract a JSON array/object from a free-text reply: a fenced ```json block first, else a balanced structure from the first `[`/`{`. Null when none is found. */
const extractJson = (text: string): string | null => {
  const fenced = /```(?:json)?\s*(?<body>[\s\S]*?)```/iu.exec(text);
  if (fenced?.groups?.body) {
    return fenced.groups.body.trim();
  }
  const bracket = text.indexOf("[");
  const brace = text.indexOf("{");
  const start =
    bracket === -1 ? brace : brace === -1 ? bracket : Math.min(bracket, brace);
  if (start === -1) {
    return null;
  }
  const open = text[start];
  const close = open === "[" ? "]" : "}";
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < text.length; i += 1) {
    const c = text[i];
    if (inStr) {
      if (esc) {
        esc = false;
      } else if (c === "\\") {
        esc = true;
      } else if (c === '"') {
        inStr = false;
      }
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === open) {
      depth += 1;
    } else if (c === close) {
      depth -= 1;
      if (depth === 0) {
        return text.slice(start, i + 1);
      }
    }
  }
  return null;
};

/** Parse the judge's free-text reply into verdicts; null on any parse/shape failure (degrade, never throw). Unknown verdict strings coerce to "unaudited". */
export const parseAuditReply = (replyText: string): ClaimAudit[] | null => {
  const raw = extractJson(replyText);
  if (raw === null) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) {
    return null;
  }
  const out: ClaimAudit[] = [];
  for (const row of parsed) {
    if (!row || typeof row !== "object") {
      continue;
    }
    const r = row as { index?: unknown; verdict?: unknown; reason?: unknown };
    if (typeof r.index !== "number") {
      continue;
    }
    const verdict: ClaimVerdict =
      typeof r.verdict === "string" &&
      REAL_VERDICTS.has(r.verdict as ClaimVerdict)
        ? (r.verdict as ClaimVerdict)
        : "unaudited";
    out.push({
      index: r.index,
      reason: typeof r.reason === "string" ? r.reason : "",
      verdict,
    });
  }
  return out;
};

/**
 * The default judge: omp's ephemeral side turn. Returns null (⇒ the audit is
 * "unaudited") unless BOTH a side-turn method and an active model are present;
 * any throw (no model, a tools:false rejection on tool-heavy history, a provider
 * error, the 30s timeout) also degrades to null. Never throws.
 */
export const ephemeralJudge = (ctx: ExtensionContext): ClaimJudge | null => {
  const run = ctx.runEphemeralTurn;
  if (typeof run !== "function" || !ctx.model) {
    return null;
  }
  return async (items) => {
    const signal = AbortSignal.timeout(AUDIT_TIMEOUT_MS);
    const turn = (toolsOff: boolean) =>
      run.call(ctx, {
        promptText: buildAuditPrompt(items),
        ...(toolsOff ? { tools: false } : {}),
        // keep multi-claim JSON intact (default collapses repeated lines)
        dedupeReply: false,
        // defeat the 4 KiB reply cap
        replyMaxBytes: Number.POSITIVE_INFINITY,
        signal,
      });
    try {
      let result: Awaited<ReturnType<typeof turn>>;
      try {
        result = await turn(true);
      } catch (error) {
        // Some transports refuse `tools: false` (native-tools models, or tool-call history — the
        // normal state mid-analysis, when record_finding asks). The side turn discards any tool
        // call anyway, so retry once with the catalog sent; anything else still degrades.
        if (
          !(error instanceof Error) ||
          !error.message.includes("tools: false")
        ) {
          throw error;
        }
        result = await turn(false);
      }
      return parseAuditReply(result.replyText);
    } catch {
      return null;
    }
  };
};

/**
 * Run the judge over the evidence-backed claims and assemble the outcome. Nothing
 * to audit (no judge, no items, or mode "off") ⇒ `audited:false`. A null reply ⇒
 * `audited:false` with a reason. A valid reply ⇒ `audited:true`, with any claim
 * the judge omitted individually marked "unaudited".
 */
export const auditClaims = async (
  items: readonly AuditClaimInput[],
  judge: ClaimJudge | null,
  mode: AuditMode
): Promise<AuditOutcome> => {
  const byIndex = new Map<number, ClaimAudit>();
  if (mode === "off" || items.length === 0 || !judge) {
    return {
      audited: false,
      byIndex,
      itemCount: items.length,
      unauditedReason: judge ? undefined : "no model / side turns unavailable",
    };
  }
  let verdicts: ClaimAudit[] | null;
  try {
    verdicts = await judge(items);
  } catch {
    verdicts = null;
  }
  if (verdicts === null) {
    return {
      audited: false,
      byIndex,
      itemCount: items.length,
      unauditedReason: "the audit side turn returned no usable verdict",
    };
  }
  for (const v of verdicts) {
    byIndex.set(v.index, v);
  }
  for (const item of items) {
    if (!byIndex.has(item.index)) {
      byIndex.set(item.index, {
        index: item.index,
        reason: "not returned by the auditor",
        verdict: "unaudited",
      });
    }
  }
  return { audited: true, byIndex, itemCount: items.length };
};

/** The claims a strict audit must withhold on: an explicit unsupported/overreach verdict (never an "unaudited" / infra failure — strict fails open). */
export const flaggedVerdicts = (outcome: AuditOutcome): ClaimAudit[] =>
  [...outcome.byIndex.values()].filter(
    (v) => v.verdict === "unsupported" || v.verdict === "overreach"
  );
