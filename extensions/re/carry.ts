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
import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import { relocateAnchor } from "./anchor.ts";
import type { AnchorFingerprint } from "./anchor.ts";
import { checkRizinCommand, loadCatalog } from "./catalog.ts";
import type { RzCatalog } from "./catalog.ts";
import { branchEntries } from "./entries.ts";
import { recordEvidence } from "./evidence.ts";
import { collectFindings } from "./findings.ts";
import type { FindingConfidence, FindingRecord } from "./findings.ts";
import {
  canonicalExcerpt,
  canonicalHash,
  maskAddresses,
  shiftHash,
} from "./format.ts";
import { normalizeAddr, resolveNumericAddr, validateAddr } from "./rizin.ts";
import type { RzSession } from "./rizin.ts";
import { inSequence } from "./sequence.ts";
import { ensureRizin, getState } from "./state.ts";
import { cleanStderr, runRizinCommand } from "./tools-rizin.ts";
import { trySha256File } from "./verify.ts";

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

/** One finding from the manifest's `findings` block (report.ts) — what `--inherit` re-proves. */
export interface ManifestFinding {
  id: string;
  claim: string;
  evidenceIds: string[];
  addr: string | null;
  confidence: FindingConfidence;
}

export interface CarryManifest {
  binarySha256: string | null;
  entries: ManifestEntry[];
  /** Absent (empty) on manifests written before findings shipped. */
  findings: ManifestFinding[];
}

export type CarryStatus =
  | "holds"
  | "relocated"
  | "drifted"
  | "broken"
  | "unchecked";

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
  /** holds/relocated only: the `{ command, addr }` that reproduced it on this build — what `--inherit` re-runs to record fresh evidence. */
  rerun?: { command: string; addr?: string };
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
  /** Set by `--inherit`: which findings were re-proven on this build, and which need another look. */
  inheritance?: InheritOutcome;
}

export interface InheritOutcome {
  /** Findings re-recorded on this build: old finding id → new finding id. */
  inherited: {
    fromId: string;
    toId: string;
    claim: string;
    status: "holds" | "relocated";
  }[];
  /** Findings that no longer hold as written (drifted/broken) or couldn't be re-checked — the analysis agenda. */
  agenda: {
    fromId: string;
    claim: string;
    status: CarryStatus;
    rows: CarryEvidenceRow[];
  }[];
  /** Findings skipped because this branch already has a live finding with the same claim. */
  alreadyPresent: number;
}
const okNum = (v: unknown, max: number) =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max;

/**
 * Shape-check a manifest entry's anchor fingerprint. Untrusted input: the name and
 * offset are only displayed, the delta becomes part of an address (so it must be a
 * small non-negative integer), and the mnemonics only feed the similarity score.
 * Anything malformed drops the fingerprint (the entry just can't be relocated).
 */
const parseAnchor = (raw: unknown): AnchorFingerprint | null => {
  const a = raw as
    | Partial<Record<keyof AnchorFingerprint, unknown>>
    | null
    | undefined;
  if (!a || typeof a !== "object") {
    return null;
  }
  if (
    typeof a.anchor !== "string" ||
    typeof a.function !== "string" ||
    typeof a.offset !== "string"
  ) {
    return null;
  }
  if (
    !okNum(a.delta, 2 ** 24) ||
    !okNum(a.size, 2 ** 30) ||
    !okNum(a.nbbs, 2 ** 24)
  ) {
    return null;
  }
  if (
    !Array.isArray(a.mnemonics) ||
    a.mnemonics.length === 0 ||
    !a.mnemonics.every((m) => typeof m === "string")
  ) {
    return null;
  }
  return {
    anchor: a.anchor,
    delta: a.delta as number,
    function: a.function,
    mnemonics: a.mnemonics as string[],
    nbbs: a.nbbs as number,
    offset: a.offset,
    size: a.size as number,
  };
};
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

/** A manifest entry's `args` as `{ command, addr? }`, or null when it carries no command string. */
const manifestArgs = (
  args: { command?: unknown; addr?: unknown } | null | undefined
): { command: string; addr?: string } | null => {
  if (!args || typeof args.command !== "string") {
    return null;
  }
  return typeof args.addr === "string" && args.addr
    ? { addr: args.addr, command: args.command }
    : { command: args.command };
};

/** One manifest `entries` row, or undefined when it has no evidence id (rows are untrusted; optional fields default). */
const parseManifestEntry = (e: unknown): ManifestEntry | undefined => {
  const row = e as Record<string, unknown> | null;
  if (!row || typeof row !== "object" || typeof row.evidenceId !== "string") {
    return undefined;
  }
  return {
    anchor: parseAnchor(row.anchor),
    args: manifestArgs(
      row.args as { command?: unknown; addr?: unknown } | null | undefined
    ),
    binarySha256: str(row.binarySha256),
    canonicalExcerpt: str(row.canonicalExcerpt),
    claims: Array.isArray(row.claims)
      ? row.claims.filter((c): c is string => typeof c === "string")
      : [],
    command: str(row.command),
    commands: Array.isArray(row.commands)
      ? row.commands.filter((c): c is string => typeof c === "string")
      : null,
    evidenceId: row.evidenceId,
    reproHash: str(row.reproHash),
    shiftHash: str(row.shiftHash),
    tool: str(row.tool) ?? "unknown",
  };
};

/** One manifest `findings` row, or undefined when it lacks an id, claim or evidence list. */
const parseManifestFinding = (f: unknown): ManifestFinding | undefined => {
  const row = f as Record<string, unknown> | null;
  if (
    !row ||
    typeof row.id !== "string" ||
    typeof row.claim !== "string" ||
    !Array.isArray(row.evidenceIds)
  ) {
    return undefined;
  }
  return {
    addr: str(row.addr),
    claim: row.claim,
    confidence:
      row.confidence === "confirmed" || row.confidence === "speculative"
        ? row.confidence
        : "likely",
    evidenceIds: row.evidenceIds.filter(
      (x): x is string => typeof x === "string"
    ),
    id: row.id,
  };
};

/** Parse and shape-check a manifest's JSON text. Throws a clear error on anything that isn't a manifest; tolerates missing optional fields per entry. */
export const parseManifest = (text: string): CarryManifest => {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `omp-re: carry: manifest is not valid JSON (${error instanceof Error ? error.message : String(error)})`,
      { cause: error }
    );
  }
  const obj = raw as { binarySha256?: unknown; entries?: unknown } | null;
  if (!obj || typeof obj !== "object" || !Array.isArray(obj.entries)) {
    throw new Error(
      "omp-re: carry: not a verification manifest (no `entries` array) — pass the <report>.manifest.json written by /re report <path>"
    );
  }
  const entries = (obj.entries as unknown[])
    .map(parseManifestEntry)
    .filter((e) => e !== undefined);
  const rawFindings = (raw as { findings?: unknown }).findings;
  const findings = (Array.isArray(rawFindings) ? rawFindings : [])
    .map(parseManifestFinding)
    .filter((f) => f !== undefined);
  return { binarySha256: str(obj.binarySha256), entries, findings };
};

/**
 * The `{ command, addr }` to re-run for a manifest entry. Prefers the structured
 * `args` (manifests since carry shipped); falls back to splitting the recorded
 * line on its trailing ` @ <addr>` (what `checkRizinCommand` appends), leaving
 * `@!<blocksize>` alone since that is part of the command, not a seek.
 */
export const entryRequest = (
  entry: ManifestEntry
): { command: string; addr?: string } | undefined => {
  if (entry.args) {
    return entry.args;
  }
  const line =
    entry.commands?.length === 1
      ? entry.commands[0]
      : (entry.command ?? undefined);
  if (!line) {
    return undefined;
  }
  const match = /^(?<command>.*\S)\s+@\s+(?<addr>[^!\s]\S*)$/u.exec(
    line.trim()
  );
  if (match?.groups) {
    return { addr: match.groups.addr, command: match.groups.command };
  }
  return { command: line.trim() };
};

/**
 * Line diff (LCS) of two short texts: unchanged lines prefixed `  `, removed `- `,
 * added `+ `. Lines are matched on `key(line)` (default: the line itself) but
 * printed as written, so with an address mask a line that only moved shows as
 * unchanged (new form) and the diff keeps to what really changed. Inputs are
 * canonical excerpts (≤20 lines), so the O(n·m) table is trivial.
 */
export const lineDiff = (
  before: string,
  after: string,
  key: (line: string) => string = (line) => line
): string[] => {
  const a = before === "" ? [] : before.split("\n");
  const b = after === "" ? [] : after.split("\n");
  const ka = a.map(key);
  const kb = b.map(key);
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () =>
    Array.from({ length: b.length + 1 }, () => 0)
  );
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      lcs[i][j] =
        ka[i] === kb[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (ka[i] === kb[j]) {
      out.push(`  ${b[j]}`);
      i += 1;
      j += 1;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push(`- ${a[i]}`);
      i += 1;
    } else {
      out.push(`+ ${b[j]}`);
      j += 1;
    }
  }
  for (; i < a.length; i += 1) {
    out.push(`- ${a[i]}`);
  }
  for (; j < b.length; j += 1) {
    out.push(`+ ${b[j]}`);
  }
  return out;
};

/** Keep only changed lines and `context` unchanged lines around each, eliding the rest as `  …` — a hunk view of a {@link lineDiff}. */
export const compactDiff = (diff: readonly string[], context = 2): string[] => {
  const changed = diff.map((line) => !line.startsWith("  "));
  const keep = diff.map((_, i) =>
    changed.slice(Math.max(0, i - context), i + context + 1).some(Boolean)
  );
  const out: string[] = [];
  for (const [i, line] of diff.entries()) {
    if (keep[i]) {
      out.push(line);
    } else if (out.at(-1) !== "  …") {
      out.push("  …");
    }
  }
  return out;
};

const RANK: Record<CarryStatus, number> = {
  broken: 4,
  drifted: 3,
  holds: 1,
  relocated: 2,
  unchecked: 0,
};

/** Roll evidence statuses up to claims: worst checked status wins; all-unchecked stays unchecked. Claim order follows first appearance in the manifest. */
export const rollUpClaims = (
  manifest: CarryManifest,
  evidence: readonly CarryEvidenceRow[]
): CarryClaimRow[] => {
  const statusById = new Map(
    evidence.map((row) => [row.evidenceId, row.status])
  );
  const claims = new Map<string, string[]>();
  for (const entry of manifest.entries) {
    for (const text of entry.claims) {
      const ids = claims.get(text) ?? [];
      if (!ids.includes(entry.evidenceId)) {
        ids.push(entry.evidenceId);
      }
      claims.set(text, ids);
    }
  }
  return [...claims.entries()].map(([text, evidenceIds]) => {
    let status: CarryStatus = "unchecked";
    for (const id of evidenceIds) {
      const s = statusById.get(id) ?? "unchecked";
      if (RANK[s] > RANK[status]) {
        status = s;
      }
    }
    return { evidenceIds, status, text };
  });
};

/**
 * Whether a re-run's output still says what the recorded one did: the exact
 * canonical hash, or — when the manifest carries one — the address-masked
 * `shiftHash`, which forgives a rebuild that only moved code. Returns the holds
 * detail, or undefined when the output really changed.
 */
const compareOutput = (
  entry: ManifestEntry,
  output: string,
  binaryPath: string
): string | undefined => {
  if (canonicalHash(output, binaryPath) === entry.reproHash) {
    return "output identical";
  }
  if (entry.shiftHash && shiftHash(output, binaryPath) === entry.shiftHash) {
    return "output identical apart from shifted addresses";
  }
  return undefined;
};
// An excerpt that hit its byte cap ends mid-line, at a different column on each side; drop that partial line so it never shows as a change.
const whole = (excerpt: string) =>
  excerpt.length >= EXCERPT_MAX_BYTES
    ? excerpt.slice(0, Math.max(0, excerpt.lastIndexOf("\n")))
    : excerpt;

/** Line diff of the recorded canonical excerpt against the new output's, capped; undefined when the excerpts are equal (the change lies further down). */
const excerptDiff = (
  recordedExcerpt: string,
  output: string,
  binaryPath: string
): string[] | undefined => {
  const newExcerpt = canonicalExcerpt(output, binaryPath);
  if (recordedExcerpt === newExcerpt) {
    return undefined;
  }
  const diff = lineDiff(
    whole(recordedExcerpt),
    whole(newExcerpt),
    maskAddresses
  );
  if (!diff.some((line) => !line.startsWith("  "))) {
    return undefined;
  }
  return diff.length > MAX_DIFF_LINES
    ? [
        ...diff.slice(0, MAX_DIFF_LINES),
        `  … ${diff.length - MAX_DIFF_LINES} more diff line(s)`,
      ]
    : diff;
};

/**
 * Find the anchor's function in this build by fingerprint and re-run the command
 * there. The new function's name is folded back to the recorded one before
 * comparing, so a pure rename compares equal. Returns the row fields — relocated
 * when the output then matches (exactly or apart from addresses), drifted with the
 * relocation noted and a diff when it doesn't — or undefined when nothing matches
 * the fingerprint or the relocated line can't run.
 */
const tryRelocated = async (
  rz: RzSession,
  catalog: RzCatalog,
  entry: ManifestEntry,
  request: { command: string; addr?: string },
  fp: AnchorFingerprint,
  binaryPath: string
): Promise<Omit<CarryEvidenceRow, "evidenceId" | "tool"> | undefined> => {
  const found = await relocateAnchor(rz, fp);
  if (!found) {
    return undefined;
  }
  const check = checkRizinCommand(catalog, request.command, found.addr);
  if (!check.ok) {
    return undefined;
  }
  const { output } = await rz.cmdWithStderr(check.line, {
    timeoutMs: CARRY_COMMAND_TIMEOUT_MS,
  });
  const folded =
    found.function === fp.function
      ? output
      : output.split(found.function).join(fp.function);
  const relocation = {
    addr: found.addr,
    from: `${fp.function} @ ${fp.offset}`,
    similarity: found.similarity,
    to: `${found.function} @ ${found.offset}`,
  };
  const renamed = found.function !== fp.function;
  const moved = normalizeAddr(found.offset) !== normalizeAddr(fp.offset);
  let how = `found at ${found.offset}`;
  if (renamed && moved) {
    how = `moved to ${found.function} @ ${found.offset}`;
  } else if (renamed) {
    how = `renamed to ${found.function}`;
  } else if (moved) {
    how = `moved from ${fp.offset} to ${found.offset}`;
  }
  const where = `${fp.function} ${how} (code similarity ${found.similarity})`;
  const same = compareOutput(entry, folded, binaryPath);
  if (same) {
    return {
      command: check.line,
      detail: `${where}; ${same}`,
      relocation,
      rerun: { addr: found.addr, command: request.command },
      status: "relocated",
    };
  }
  const diff = excerptDiff(entry.canonicalExcerpt ?? "", folded, binaryPath);
  return {
    command: check.line,
    detail: `${where}; output changed${diff ? "" : " beyond the recorded 20-line excerpt"}`,
    relocation,
    status: "drifted",
    ...(diff ? { diff } : {}),
  };
};

/** A carry row without its identity (evidence id and tool), which the caller adds. */
type CarryRowFields = Omit<CarryEvidenceRow, "evidenceId" | "tool">;

/** The read-only line `request` runs as, through rizin_command's own gate, or the "unchecked" row explaining why it can't run here. */
const gateLine = async (request: {
  command: string;
  addr?: string;
}): Promise<{ line: string } | CarryRowFields> => {
  try {
    const catalog = await loadCatalog();
    const check = checkRizinCommand(
      catalog,
      request.command,
      request.addr === undefined ? undefined : validateAddr(request.addr)
    );
    return check.ok
      ? { line: check.line }
      : {
          command: request.command,
          detail: `not runnable here: ${check.reason}`,
          status: "unchecked",
        };
  } catch (error) {
    return {
      command: request.command,
      detail: `not runnable here: ${error instanceof Error ? error.message : String(error)}`,
      status: "unchecked",
    };
  }
};

/** The "broken" row for a command that now prints nothing (or only an error) where it used to print something; undefined when the output is fine. */
const silentRow = (
  line: string,
  output: string,
  stderr: string,
  recordedExcerpt: string
): CarryRowFields | undefined => {
  if (output.trim() !== "") {
    return;
  }
  const errors = cleanStderr(stderr);
  if (!errors && recordedExcerpt.trim() === "") {
    return;
  }
  const said = errors ? `: ${errors.split("\n").at(-1)}` : "";
  return {
    command: line,
    detail: `command now produces no output${said}`,
    status: "broken",
  };
};

/** Whether a symbolic anchor (a symbol or flag name) no longer resolves to an address in the open build. */
const symbolicAnchorGone = async (
  rz: RzSession,
  addr: string
): Promise<boolean> => {
  try {
    await resolveNumericAddr(rz, addr);
    return false;
  } catch {
    return true;
  }
};

/** The "drifted" row: what changed (as a diff when the excerpt shows it) and, for a numeric anchor, why it wasn't relocated. */
const driftRow = (
  line: string,
  recordedExcerpt: string,
  output: string,
  binaryPath: string,
  anchor: { fingerprinted: boolean; numericAddr: string | undefined }
): CarryRowFields => {
  const diff = excerptDiff(recordedExcerpt, output, binaryPath);
  const parts = [
    diff
      ? "output changed"
      : "output changed beyond the recorded 20-line excerpt (re-run to see it)",
  ];
  if (anchor.numericAddr !== undefined) {
    parts.push(
      `pinned to numeric address ${anchor.numericAddr}${anchor.fingerprinted ? "; no function matching its fingerprint was found elsewhere" : " — the code it named may have moved in this build"}`
    );
  }
  return {
    command: line,
    detail: parts.join("; "),
    status: "drifted",
    ...(diff ? { diff } : {}),
  };
};

/** Re-run a gated entry and classify the result: holds, relocated, drifted, or broken. */
const rerunEntry = async (
  ctx: ExtensionContext,
  entry: ManifestEntry,
  request: { command: string; addr?: string },
  line: string,
  binaryPath: string
): Promise<CarryRowFields> => {
  const rz = await ensureRizin(ctx);
  const catalog = await loadCatalog();
  const fp = entry.anchor ?? undefined;
  const relocate = async (): Promise<CarryRowFields | undefined> => {
    if (!fp) {
      return;
    }
    return await tryRelocated(rz, catalog, entry, request, fp, binaryPath);
  };
  // A symbolic anchor (sym.decrypt_config, a flag) that no longer resolves means the thing the
  // claim is about is gone under that name; with a fingerprint it may just have been renamed,
  // so look for it before calling it broken. A numeric anchor always "resolves", so it is
  // judged by its output (and relocated by fingerprint below when that output changed).
  const numericAnchor =
    request.addr !== undefined && /^(?:0x[0-9a-f]+|\d+)$/iu.test(request.addr);
  if (
    request.addr !== undefined &&
    !numericAnchor &&
    (await symbolicAnchorGone(rz, request.addr))
  ) {
    return (
      (await relocate()) ?? {
        command: line,
        detail: `anchor \`${request.addr}\` no longer resolves in this binary${fp ? " and no function matching its fingerprint was found" : ""}`,
        status: "broken",
      }
    );
  }
  const { output, stderr } = await rz.cmdWithStderr(line, {
    timeoutMs: CARRY_COMMAND_TIMEOUT_MS,
  });
  const recordedExcerpt = entry.canonicalExcerpt ?? "";
  const silent = silentRow(line, output, stderr, recordedExcerpt);
  if (silent) {
    const moved = numericAnchor ? await relocate() : null;
    return moved ?? silent;
  }
  const same = compareOutput(entry, output, binaryPath);
  if (same) {
    return { command: line, detail: same, rerun: request, status: "holds" };
  }
  // Drifted at a numeric anchor: the code it named may simply have moved. Relocate by
  // fingerprint and re-run there; keep the drift only if the code isn't found elsewhere.
  if (numericAnchor) {
    const moved = await relocate();
    if (
      moved &&
      request.addr !== undefined &&
      moved.relocation?.addr !== normalizeAddr(request.addr)
    ) {
      return moved;
    }
  }
  return driftRow(line, recordedExcerpt, output, binaryPath, {
    fingerprinted: fp !== undefined,
    numericAddr: numericAnchor ? request.addr : undefined,
  });
};

/** Classify one manifest entry on the open build. Never throws: an infrastructure failure is "unchecked". */
const carryEntry = async (
  ctx: ExtensionContext,
  entry: ManifestEntry,
  binaryPath: string
): Promise<CarryRowFields> => {
  const request =
    entry.tool === "rizin_command" ? entryRequest(entry) : undefined;
  if (!request || !entry.reproHash) {
    return {
      command: entry.command ?? undefined,
      detail: entry.commands?.length
        ? "provenance-only: no reproducible hash to compare (re-run by hand)"
        : "legacy: no reproducible hash recorded",
      status: "unchecked",
    };
  }
  const gated = await gateLine(request);
  if (!("line" in gated)) {
    return gated;
  }
  try {
    return await rerunEntry(ctx, entry, request, gated.line, binaryPath);
  } catch (error) {
    return {
      command: gated.line,
      detail: `re-run failed: ${error instanceof Error ? error.message : String(error)}`,
      status: "unchecked",
    };
  }
};

/**
 * Re-run every reproducible manifest entry against the currently-open binary and
 * classify it. Never throws for a single entry — any per-entry failure degrades
 * that entry to "unchecked" (an infra problem) or "broken" (the anchor is gone).
 */
export const buildCarry = async (
  ctx: ExtensionContext,
  manifest: CarryManifest
): Promise<CarryResult> => {
  const state = getState(ctx);
  const binaryPath = state.binaryPath ?? undefined;
  if (!binaryPath) {
    throw new Error(
      "omp-re: carry: no binary open — /re open <the new build> first, or pass --against <path>"
    );
  }
  const toSha256 =
    state.binarySha256 ?? (await trySha256File(binaryPath)) ?? null;

  const evidence: CarryEvidenceRow[] = [];
  const seen = new Set<string>();
  await inSequence(manifest.entries, async (entry) => {
    if (seen.has(entry.evidenceId)) {
      return;
    }
    seen.add(entry.evidenceId);
    const row = await carryEntry(ctx, entry, binaryPath);
    evidence.push({ evidenceId: entry.evidenceId, tool: entry.tool, ...row });
  });

  return {
    claims: rollUpClaims(manifest, evidence),
    evidence,
    fromSha256: manifest.binarySha256,
    toPath: binaryPath,
    toSha256,
  };
};

const counts = (
  rows: readonly { status: CarryStatus }[]
): Record<CarryStatus, number> => {
  const c: Record<CarryStatus, number> = {
    broken: 0,
    drifted: 0,
    holds: 0,
    relocated: 0,
    unchecked: 0,
  };
  for (const row of rows) {
    c[row.status] += 1;
  }
  return c;
};

const short = (sha: string | null) =>
  sha ? `${sha.slice(0, 12)}…` : "unknown";

/** The one-line summary plus per-claim lines (non-holding first), for notify/console. */
export const formatCarrySummary = (result: CarryResult): string => {
  const c = counts(result.claims);
  const lines = [
    `omp-re: carry ${short(result.fromSha256)} → ${short(result.toSha256)} — ${c.holds} hold, ${c.relocated} relocated, ${c.drifted} drifted, ${c.broken} BROKEN, ${c.unchecked} unchecked (of ${result.claims.length} claim(s))`,
  ];
  if (result.fromSha256 && result.fromSha256 === result.toSha256) {
    lines.push(
      "  (same binary the report was written against — this is /re verify; open the new build to carry onto it)"
    );
  }
  const order: CarryStatus[] = [
    "broken",
    "drifted",
    "unchecked",
    "relocated",
    "holds",
  ];
  for (const status of order) {
    for (const claim of result.claims.filter((cl) => cl.status === status)) {
      lines.push(`  ${status.toUpperCase().padEnd(9)} ${claim.text}`);
    }
  }
  return lines.join("\n");
};
const cell = (s: string) => s.replaceAll("|", "\\|").replaceAll("\n", " ");

/** The full carry report as Markdown: claim matrix, then per-evidence detail with diffs for drifted records. */
export const formatCarryMarkdown = (
  result: CarryResult,
  manifestPath: string
): string => {
  const c = counts(result.claims);
  const evidenceById = new Map(
    result.evidence.map((row) => [row.evidenceId, row])
  );
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
    ...result.claims.map(
      (cl) =>
        `| ${cl.status} | ${cell(cl.text)} | ${cl.evidenceIds.map((id) => `\`${id.slice(0, 8)}\` ${evidenceById.get(id)?.status ?? "unchecked"}`).join(", ")} |`
    ),
    "",
    "## Evidence",
    "",
  ];
  for (const row of result.evidence) {
    out.push(
      `### \`${row.evidenceId.slice(0, 8)}\` — ${row.status}`,
      "",
      `- **Tool:** ${row.tool}`
    );
    if (row.command) {
      out.push(`- **Command:** \`${row.command}\``);
    }
    if (row.relocation) {
      out.push(
        `- **Relocated:** ${row.relocation.from} → ${row.relocation.to} (similarity ${row.relocation.similarity})`
      );
    }
    out.push(`- **Detail:** ${row.detail}`, "");
    if (row.diff && row.diff.length > 0) {
      out.push("```diff", ...compactDiff(row.diff), "```", "");
    }
  }
  return out.join("\n");
};

/** Map a finding's address through a relocation: its old function name → the new name, its old start offset → the new one; anything else stays as is (undefined). */
const followRelocation = (
  addr: string,
  relocation: { from: string; to: string; addr: string }
): string | undefined => {
  const [fromName, fromOffset] = relocation.from.split(" @ ");
  const [toName, toOffset] = relocation.to.split(" @ ");
  if (addr === fromName && toName) {
    return toName;
  }
  if (
    fromOffset &&
    toOffset &&
    normalizeAddr(addr) === normalizeAddr(fromOffset)
  ) {
    return toOffset;
  }
  return undefined;
};

/**
 * `/re carry <manifest> [--strict] [--out <path>]`: load the manifest, carry it
 * onto the open binary, and report. Interactive → notify the summary; headless →
 * console, with `process.exitCode = 1` on any broken claim (and, under
 * `--strict`, any drifted or unchecked one). `--out` also writes the Markdown
 * carry report and a `<out>.json` sidecar of the full result.
 */
/**
 * `--inherit`: turn the carry into this build's starting point. For each manifest
 * finding whose claim holds or relocated, every evidence row that reproduced is
 * re-run through `rizin_command`'s own code path and recorded as fresh evidence
 * bound to THIS binary (never copied from the manifest), and the finding is
 * re-recorded citing only that evidence, with its provenance. A finding with no
 * reproduced evidence, or one that drifted or broke, goes on the agenda instead.
 * Idempotent: a claim already live on this branch is not inherited twice.
 */
export const inheritFindings = async (
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  manifest: CarryManifest,
  result: CarryResult
): Promise<InheritOutcome> => {
  const statusByClaim = new Map(result.claims.map((c) => [c.text, c.status]));
  const rowById = new Map(result.evidence.map((r) => [r.evidenceId, r]));
  const present = new Set(
    collectFindings(branchEntries(ctx)).map((f) => f.claim)
  );
  const outcome: InheritOutcome = {
    agenda: [],
    alreadyPresent: 0,
    inherited: [],
  };

  await inSequence(manifest.findings, async (finding) => {
    if (present.has(finding.claim)) {
      outcome.alreadyPresent += 1;
      return;
    }
    const status = statusByClaim.get(finding.claim) ?? "unchecked";
    const rows = finding.evidenceIds
      .map((id) => rowById.get(id))
      .filter((r): r is CarryEvidenceRow => r !== undefined);
    const reproduced = rows.filter(
      (
        r
      ): r is CarryEvidenceRow & {
        rerun: NonNullable<CarryEvidenceRow["rerun"]>;
      } =>
        (r.status === "holds" || r.status === "relocated") &&
        r.rerun !== undefined
    );
    if (
      (status !== "holds" && status !== "relocated") ||
      reproduced.length === 0
    ) {
      outcome.agenda.push({
        claim: finding.claim,
        fromId: finding.id,
        rows,
        status,
      });
      return;
    }

    const newEvidence: string[] = [];
    await inSequence(reproduced, async (row) => {
      const res = await runRizinCommand(ctx, row.rerun.command, row.rerun.addr);
      if (res.isError) {
        return;
      }
      newEvidence.push(
        await recordEvidence(
          pi,
          ctx,
          "rizin_command",
          row.rerun,
          res.content,
          res.details
        )
      );
    });
    if (newEvidence.length === 0) {
      outcome.agenda.push({
        claim: finding.claim,
        fromId: finding.id,
        rows,
        status: "unchecked",
      });
      return;
    }
    // An address the finding was about follows its evidence's anchor when that anchor relocated.
    const relocationOf = reproduced.find((r) => r.relocation)?.relocation;
    const anchorMoved =
      relocationOf && finding.addr
        ? followRelocation(finding.addr, relocationOf)
        : undefined;
    const id = randomUUID();
    const openSha = getState(ctx).binarySha256;
    // the address follows its relocated anchor; otherwise the original one (when there was one)
    const findingAddr = anchorMoved || finding.addr;
    const record: FindingRecord = {
      claim: finding.claim,
      evidenceIds: newEvidence,
      id,
      ...(findingAddr ? { addr: findingAddr } : {}),
      audit: {
        reason:
          "re-verified by /re carry; the report's support audit re-checks it",
        verdict: "inherited",
      },
      confidence: finding.confidence,
      ...(openSha ? { binarySha256: openSha } : {}),
      inherited: {
        carryStatus: status,
        fromBinarySha256: manifest.binarySha256,
        fromFindingId: finding.id,
        ...(relocationOf
          ? {
              relocation: {
                from: relocationOf.from,
                similarity: relocationOf.similarity,
                to: relocationOf.to,
              },
            }
          : {}),
      },
    };
    pi.appendEntry("re.finding", record);
    present.add(finding.claim);
    outcome.inherited.push({
      claim: finding.claim,
      fromId: finding.id,
      status,
      toId: id,
    });
  });
  return outcome;
};

/** The notify level for a carry summary: a failure is an error, drift a warning, anything else info. */
const notifyLevel = (
  failed: boolean,
  drifted: boolean
): "error" | "warning" | "info" => {
  if (failed) {
    return "error";
  }
  return drifted ? "warning" : "info";
};

/** The agenda as a prompt for the model: each finding that no longer holds as written, with the evidence change under it. */
export const formatAgendaPrompt = (
  outcome: InheritOutcome,
  toSha256: string | null
): string => {
  const lines = [
    `These findings from the earlier report do not carry over unchanged to this build${toSha256 ? ` (\`${toSha256.slice(0, 12)}…\`)` : ""}. For each one, re-examine it with the RE tools, then record_finding a revised claim on fresh evidence, or leave it out if it no longer stands:`,
    "",
  ];
  for (const [i, item] of outcome.agenda.entries()) {
    lines.push(`${i + 1}. [${item.status}] ${item.claim}`);
    for (const row of item.rows) {
      lines.push(
        `   - evidence ${row.evidenceId.slice(0, 8)}${row.command ? ` \`${row.command}\`` : ""}: ${row.status} — ${row.detail}`
      );
      if (row.diff?.length) {
        lines.push(
          "     ```diff",
          ...compactDiff(row.diff).map((d) => `     ${d}`),
          "     ```"
        );
      }
    }
  }
  return lines.join("\n");
};

/** Read and parse a manifest file, naming the file when it can't be read. */
const readManifest = async (manifestPath: string): Promise<CarryManifest> => {
  let text: string;
  try {
    text = await readFile(manifestPath, "utf-8");
  } catch (error) {
    throw new Error(
      `omp-re: carry: could not read manifest ${manifestPath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
  }
  return parseManifest(text);
};

/** Run `--inherit` and describe it: the summary line, and the agenda prompt when findings need another look. */
const inheritAndSummarize = async (
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  manifest: CarryManifest,
  result: CarryResult
): Promise<{ line: string; agendaPrompt?: string }> => {
  const inheritance = await inheritFindings(pi, ctx, manifest, result);
  result.inheritance = inheritance;
  const present = inheritance.alreadyPresent
    ? `, ${inheritance.alreadyPresent} already present`
    : "";
  const none =
    manifest.findings.length === 0
      ? " (this manifest has no findings — record them with record_finding before /re report)"
      : "";
  return {
    line: `inherit: ${inheritance.inherited.length} finding(s) re-proven on this build and recorded, ${inheritance.agenda.length} need another look${present}${none}`,
    ...(inheritance.agenda.length > 0
      ? { agendaPrompt: formatAgendaPrompt(inheritance, result.toSha256) }
      : {}),
  };
};

/** Write the Markdown carry report and its JSON sidecar; returns the summary line saying where (or why not). */
const writeCarryFiles = async (
  result: CarryResult,
  manifestPath: string,
  out: string
): Promise<string> => {
  try {
    await writeFile(out, formatCarryMarkdown(result, manifestPath), "utf-8");
    await writeFile(
      `${out}.json`,
      `${JSON.stringify(result, null, 2)}\n`,
      "utf-8"
    );
    return `carry report written to ${out} (+ ${out}.json)`;
  } catch (error) {
    return `carry report not written: ${error instanceof Error ? error.message : String(error)}`;
  }
};

/** Report a carry: notify in the UI (the agenda goes into the editor unless it was already sent), or print headless and set a failing exit code. */
const deliverCarry = (
  ctx: ExtensionContext,
  summary: string,
  outcome: { failed: boolean; drifted: boolean },
  agenda: string | undefined
): void => {
  if (ctx.hasUI) {
    ctx.ui.notify(summary, notifyLevel(outcome.failed, outcome.drifted));
    if (agenda) {
      ctx.ui.setEditorText(agenda);
    }
    return;
  }
  if (outcome.failed) {
    console.error(summary);
    // Same deliberate headless signal as /re verify and the report gate: a finding that no
    // longer holds on the new build must fail the pipeline. process.exitCode, never process.exit.
    process.exitCode = 1;
    if (agenda) {
      console.error(agenda);
    }
    return;
  }
  console.log(summary);
  if (agenda) {
    console.log(agenda);
  }
};

export const carryManifest = async (
  ctx: ExtensionContext,
  manifestPath: string,
  opts: {
    strict?: boolean;
    out?: string;
    inherit?: ExtensionAPI;
    resolve?: boolean;
  } = {}
): Promise<CarryResult> => {
  const manifest = await readManifest(manifestPath);
  const result = await buildCarry(ctx, manifest);
  const c = counts(result.claims);
  const failed =
    c.broken > 0 ||
    (opts.strict === true &&
      (c.relocated > 0 || c.drifted > 0 || c.unchecked > 0));

  const lines = [formatCarrySummary(result)];
  let agendaPrompt: string | undefined;
  if (opts.inherit) {
    const inherited = await inheritAndSummarize(
      opts.inherit,
      ctx,
      manifest,
      result
    );
    lines.push(inherited.line);
    ({ agendaPrompt } = inherited);
  }
  if (opts.out) {
    lines.push(await writeCarryFiles(result, manifestPath, opts.out));
  }

  // --resolve: hand the agenda straight to the model as a user turn (it has the RE tools and
  // record_finding in this session, where the fresh evidence lives). Otherwise it goes into the editor,
  // like /re cite, for the analyst to send or edit.
  let unsentAgenda = agendaPrompt;
  if (
    opts.resolve === true &&
    agendaPrompt !== undefined &&
    opts.inherit !== undefined
  ) {
    opts.inherit.sendUserMessage(agendaPrompt);
    lines.push(
      `resolve: sent ${result.inheritance?.agenda.length ?? 0} finding(s) to the model to re-examine`
    );
    unsentAgenda = undefined;
  }
  deliverCarry(
    ctx,
    lines.join("\n"),
    { drifted: c.drifted > 0, failed },
    unsentAgenda
  );
  return result;
};
