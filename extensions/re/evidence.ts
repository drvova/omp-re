/**
 * Evidence store: a SHA-256 content-addressed blob store (temp-file-then-
 * rename, idempotent) plus a central `tool_result` hook that appends an
 * `re.evidence` custom entry after every successful read-tier RE tool call
 * and every successful `rizin_command`.
 *
 * `pi.appendEntry()` persists the entry to the session but does NOT send it
 * to the LLM, so the model sees a tool result once and never re-reads its own
 * evidence log; `/re evidence`, `/re cite`, the mutate tools' grounding, and
 * `/re report` read it back from the current session branch. When the tool
 * spilled truncated output to a session artifact, the entry records that
 * `artifactId` too, so the full output stays recoverable from the evidence.
 */
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir } from "@oh-my-pi/pi-utils";

import { RE_EVIDENCE_TOOL_NAMES } from "./audit.ts";
import { branchEntries, customEntries } from "./entries.ts";
import { normalizeAddr } from "./rizin.ts";
import { getState } from "./state.ts";

/** Write content to the content-addressed blob store, returning its SHA-256 hex hash. Idempotent: skips the write if the target already exists. Atomic: writes to a temp file in the same directory, then renames. */
export const writeBlob = async (content: string): Promise<string> => {
  const hash = createHash("sha256").update(content, "utf-8").digest("hex");
  const dir = join(
    getAgentDir(),
    "re",
    "blobs",
    hash.slice(0, 2),
    hash.slice(2, 4)
  );
  const target = join(dir, hash);

  try {
    await stat(target);
    // already stored
    return hash;
  } catch {
    // not yet stored — fall through and write it
  }

  await mkdir(dir, { mode: 0o700, recursive: true });
  const tmp = join(dir, `.${hash}.${process.pid}.${randomUUID()}.tmp`);
  await writeFile(tmp, content, { mode: 0o600 });
  await rename(tmp, target);
  return hash;
};

/** Read a previously written blob by its SHA-256 hash. Returns null when the blob is missing (never throws) — a missing blob must degrade to "no evidence" for the adviser, not crash it. */
export const readBlob = async (hash: string): Promise<string | null> => {
  const target = join(
    getAgentDir(),
    "re",
    "blobs",
    hash.slice(0, 2),
    hash.slice(2, 4),
    hash
  );
  try {
    return await readFile(target, "utf-8");
  } catch {
    return null;
  }
};

/** Truncate to at most maxBytes, cutting on a UTF-8 character boundary (never mid-codepoint, and — since maxBytes comfortably exceeds the disassembly-only prefix's length — never mid-prefix either). */
const truncateUtf8Safe = (text: string, maxBytes: number): string => {
  const buf = Buffer.from(text, "utf-8");
  if (buf.length <= maxBytes) {
    return text;
  }
  let end = maxBytes;
  // Back off while we're in the middle of a multi-byte UTF-8 sequence (continuation bytes are 10xxxxxx).
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) {
    end -= 1;
  }
  return buf.subarray(0, end).toString("utf-8");
};

const EVIDENCE_SUMMARY_MAX_BYTES = 512;

/** Join every text content block into one string; image blocks contribute nothing. */
const extractText = (
  content: readonly { type: string; text?: string }[]
): string =>
  content
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n");

/**
 * Rebuild the in-memory evidence index from the current branch. The index is
 * process memory only: on `--continue`, a session switch, a branch, or `/tree`
 * navigation, the branch's `re.evidence` entries are the truth, and every
 * mutate tool's grounding lookup must see exactly those.
 */
export const rebuildEvidenceIndex = (ctx: ExtensionContext): void => {
  const state = getState(ctx);
  state.evidenceByAddr.clear();
  state.evidenceCount = 0;
  for (const entry of customEntries(branchEntries(ctx), "re.evidence")) {
    const data = entry.data as { id?: unknown; ea?: unknown } | undefined;
    if (!data || typeof data.id !== "string") {
      continue;
    }
    state.evidenceCount += 1;
    if (typeof data.ea === "string" && data.ea) {
      state.evidenceByAddr.set(normalizeAddr(data.ea), data.id);
    }
  }
};

/**
 * Append one `re.evidence` record for a successful evidence-tier tool result and
 * return its id. Shared by the `tool_result` hook and by `/re carry --inherit`,
 * which re-runs a carried command and must record it exactly as `rizin_command`
 * would — same blob store, same reproducibility fields, same binary binding.
 * Throws on a blob-store failure; the caller decides how loud that is.
 */
export const recordEvidence = async (
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  toolName: string,
  input: unknown,
  content: readonly { type: string; text?: string }[],
  rawDetails: unknown
): Promise<string> => {
  const state = getState(ctx);
  const rawText = extractText(content);
  const outputHash = await writeBlob(rawText);
  const summary = truncateUtf8Safe(rawText, EVIDENCE_SUMMARY_MAX_BYTES);

  const details = (rawDetails ?? {}) as {
    ea?: unknown;
    artifactId?: unknown;
    commands?: unknown;
    reproHash?: unknown;
    canonicalExcerpt?: unknown;
    shiftHash?: unknown;
  };
  const ea = typeof details.ea === "string" ? details.ea : undefined;
  const artifactId =
    typeof details.artifactId === "string" ? details.artifactId : undefined;
  const commands =
    Array.isArray(details.commands) &&
    details.commands.every((c) => typeof c === "string")
      ? (details.commands as string[])
      : undefined;
  const reproHash =
    typeof details.reproHash === "string" ? details.reproHash : undefined;
  const canonicalExcerpt =
    typeof details.canonicalExcerpt === "string"
      ? details.canonicalExcerpt
      : undefined;
  const shiftHash =
    typeof details.shiftHash === "string" ? details.shiftHash : undefined;
  // Stamped at open time (index.ts): binds this evidence to the exact binary bytes it was taken
  // against, so `/re verify` re-runs against the right binary. Absent on a resume whose re.binary
  // entry predates the field — such evidence is then "unverifiable (legacy)", never a failure.
  const binarySha256 =
    typeof state.binarySha256 === "string" ? state.binarySha256 : undefined;

  const id = randomUUID();
  state.evidenceCount += 1;
  if (ea) {
    state.evidenceByAddr.set(normalizeAddr(ea), id);
  }

  pi.appendEntry("re.evidence", {
    id,
    tool: toolName,
    args: input,
    ea,
    outputHash,
    ...(artifactId ? { artifactId } : {}),
    ...(commands ? { commands } : {}),
    ...(reproHash ? { reproHash } : {}),
    ...(canonicalExcerpt ? { canonicalExcerpt } : {}),
    ...(shiftHash ? { shiftHash } : {}),
    ...(binarySha256 ? { binarySha256 } : {}),
    summary,
  });
  return id;
};

/** The trailing tag appended to every evidence-tier tool result: the id prefix record_finding accepts. */
export const evidenceTag = (id: string): string =>
  `[evidence ${id.slice(0, 8)} — cite it in record_finding]`;

export const registerEvidenceStore = (pi: ExtensionAPI): void => {
  pi.on("tool_result", async (event, ctx) => {
    if (event.isError) {
      return;
    }
    if (RE_EVIDENCE_TOOL_NAMES[event.toolName] !== true) {
      return;
    }

    try {
      const id = await recordEvidence(
        pi,
        ctx,
        event.toolName,
        event.input,
        event.content,
        event.details
      );
      // Tag the result the model sees with its evidence id: the record itself goes to the session
      // via appendEntry, which never reaches the model, so without this tag record_finding would ask
      // for ids the model has no way to learn. A separate trailing block, so the tool's own text
      // (and the hashes taken over it above) are untouched.
      return {
        content: [
          ...event.content,
          { text: evidenceTag(id), type: "text" as const },
        ],
      };
    } catch (error) {
      // A blob-store failure (disk full, EACCES, ...) must degrade to "no evidence
      // recorded" for this call, not crash the tool_result pipeline.
      const msg = `omp-re: evidence recording failed: ${error instanceof Error ? error.message : String(error)}`;
      if (ctx.hasUI) {
        ctx.ui.notify(msg, "error");
      } else {
        pi.logger.error(msg);
      }
    }
  });
};
