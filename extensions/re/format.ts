/**
 * Shared tool-result formatting: every read/triage tool sends the model the
 * real data (not just a count — see tools-read.ts header comment for why),
 * truncated to a context-friendly size.
 *
 * When output is truncated and a tool context is available, the untruncated
 * text is saved to the session's artifact store (the same mechanism omp's
 * built-in tools use) and the result ends with `[full output:
 * artifact://<id>]`, so nothing rizin returned is lost — the model can `read`
 * it back. The truncate-from-head algorithm is a local port of omp's
 * (two independent limits, whichever is hit first wins; never returns a
 * partial line) so this module stays importable without loading the host.
 */
import { createHash } from "node:crypto";

import type {
  AgentToolResult,
  ExtensionContext,
} from "@oh-my-pi/pi-coding-agent";

const MAX_LINES = 2000;
const MAX_BYTES = 50 * 1024;

/** `details` every omp-re tool result carries: the address it concerns (for evidence keying), a short summary, and the header line renderers show. */
export interface ReToolDetails {
  ea?: string;
  summary: string;
  header: string;
  truncated?: boolean;
  /** Session artifact holding the untruncated output, when it was truncated and saving succeeded. */
  artifactId?: string;
  /** decompile_function only: which decompiler produced the code. */
  decompiler?: string;
  /** rizin_command only: the exact rizin line(s) that produced this output, for the verification manifest and re-run. */
  commands?: string[];
  /** SHA-256 of the CANONICALIZED raw output — the verification key. Distinct from the evidence record's `outputHash`, which hashes the model-facing text (header + session-specific truncation footer) and is therefore not reproducible. */
  reproHash?: string;
  /** First lines of the canonical output, for human diffing in the manifest. */
  canonicalExcerpt?: string;
  /** SHA-256 of the canonical output with addresses masked (see {@link maskAddresses}) — the shift-tolerant key `/re carry` compares on another build. */
  shiftHash?: string;
}

export type ReToolResult = AgentToolResult<ReToolDetails>;

interface TruncationResult {
  content: string;
  truncated: boolean;
  totalLines: number;
  totalBytes: number;
  outputLines: number;
  outputBytes: number;
}

const splitLinesForCounting = (content: string): string[] => {
  if (content.length === 0) {
    return [];
  }
  const lines = content.split("\n");
  if (content.endsWith("\n")) {
    lines.pop();
  }
  return lines;
};

/** Format bytes as human-readable size. */
const formatSize = (bytes: number): string => {
  if (bytes < 1024) {
    return `${bytes}B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)}KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
};

/**
 * Truncate content from the head (keep first N lines/bytes). Never returns a
 * partial line; if the first line alone exceeds the byte limit, returns empty
 * content rather than a fragment.
 */
const truncateHead = (
  content: string,
  maxLines = MAX_LINES,
  maxBytes = MAX_BYTES
): TruncationResult => {
  const totalBytes = Buffer.byteLength(content, "utf-8");
  const lines = splitLinesForCounting(content);
  const totalLines = lines.length;

  if (totalLines <= maxLines && totalBytes <= maxBytes) {
    return {
      content,
      outputBytes: totalBytes,
      outputLines: totalLines,
      totalBytes,
      totalLines,
      truncated: false,
    };
  }

  const firstLineBytes = Buffer.byteLength(lines[0] ?? "", "utf-8");
  if (firstLineBytes > maxBytes) {
    return {
      content: "",
      outputBytes: 0,
      outputLines: 0,
      totalBytes,
      totalLines,
      truncated: true,
    };
  }

  const outputLinesArr: string[] = [];
  let outputBytesCount = 0;
  for (let i = 0; i < lines.length && i < maxLines; i += 1) {
    const line = lines[i] ?? "";
    // +1 for the joining newline
    const lineBytes = Buffer.byteLength(line, "utf-8") + (i > 0 ? 1 : 0);
    if (outputBytesCount + lineBytes > maxBytes) {
      break;
    }
    outputLinesArr.push(line);
    outputBytesCount += lineBytes;
  }

  const outputContent = outputLinesArr.join("\n");
  return {
    content: outputContent,
    outputBytes: Buffer.byteLength(outputContent, "utf-8"),
    outputLines: outputLinesArr.length,
    totalBytes,
    totalLines,
    truncated: true,
  };
};

export interface ResultOptions {
  ea?: string;
  /** When set, truncated output is spilled to this session's artifact store under `tool`'s name. */
  ctx?: ExtensionContext;
  tool?: string;
  /** Truncation hint for the model when no artifact could be saved. */
  narrowHint?: string;
  decompiler?: string;
  /** rizin_command only: the exact rizin line(s) recorded for the verification manifest. */
  commands?: string[];
  /** rizin_command only: SHA-256 of the canonicalized raw output (the reproducibility key). */
  reproHash?: string;
  /** rizin_command only: a short canonical excerpt for human diffing. */
  canonicalExcerpt?: string;
  /** rizin_command only: SHA-256 of the address-masked canonical output (the shift-tolerant carry key). */
  shiftHash?: string;
}

const spill = async (
  full: string,
  options: ResultOptions
): Promise<string | undefined> => {
  if (!options.ctx) {
    return undefined;
  }
  try {
    return await options.ctx.sessionManager.saveArtifact(
      full,
      options.tool ?? "omp-re"
    );
  } catch {
    // A save failure (disk full, EACCES) must never turn a successful call into an error; the result just stays truncated.
    return undefined;
  }
};

/** Assemble `${lead}${body}` with truncation, artifact spill, and the standard details shape. `lead` is the header line plus newline, or a fixed prefix that must stay at byte 0. */
const buildResult = async (
  lead: string,
  header: string,
  body: string,
  options: ResultOptions
): Promise<ReToolResult> => {
  const truncation = truncateHead(body);
  let text = `${lead}${truncation.content}`;
  let artifactId: string | undefined;
  if (truncation.truncated) {
    artifactId = await spill(`${lead}${body}`, options);
    const shown = `${truncation.outputLines} of ${truncation.totalLines} lines (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)})`;
    text += artifactId
      ? `\n\n[Output truncated: ${shown}. Full output: artifact://${artifactId}]`
      : `\n\n[Output truncated: ${shown}. ${options.narrowHint ?? "Full output was larger."}]`;
  }
  return {
    content: [{ text, type: "text" }],
    details: {
      ea: options.ea,
      header,
      summary: text.slice(0, 512),
      ...(truncation.truncated ? { truncated: true } : {}),
      ...(artifactId ? { artifactId } : {}),
      ...(options.decompiler ? { decompiler: options.decompiler } : {}),
      ...(options.commands ? { commands: options.commands } : {}),
      ...(options.reproHash ? { reproHash: options.reproHash } : {}),
      ...(options.canonicalExcerpt
        ? { canonicalExcerpt: options.canonicalExcerpt }
        : {}),
      ...(options.shiftHash ? { shiftHash: options.shiftHash } : {}),
    },
  };
};

/**
 * JSON for a model's context: an array is one compact row per line (a third of
 * the tokens of pretty-printing, and line truncation then always cuts between
 * whole rows), any other value is pretty-printed. Both forms are valid JSON.
 */
export const formatJson = (data: unknown): string => {
  if (!Array.isArray(data)) {
    return JSON.stringify(data, null, 2);
  }
  if (data.length === 0) {
    return "[]";
  }
  return `[\n${data.map((row) => `  ${JSON.stringify(row)}`).join(",\n")}\n]`;
};

const ANSI_ESCAPE = /\u001B\[[0-9;?]*[A-Za-z]/gu;

/**
 * Normalize raw rizin output so an independent re-run on the same binary and the
 * same pinned rizin build hashes identically: strip ANSI escapes, fold CR/CRLF to
 * LF, right-trim every line, drop trailing blank lines, and redact the open
 * binary's absolute path to a stable `<BINARY>` token (rizin prints it in headers).
 * This canonical projection — never the raw ANSI bytes — is what `reproHash` is a
 * SHA-256 of. Prefer a command's JSON (`*j`) form where possible: rizin JSON is
 * ANSI-free and field-order-stable within a version, so it canonicalizes cleanly.
 */
export const canonicalizeRizinOutput = (
  raw: string,
  binaryPath?: string
): string => {
  let text = raw.replace(ANSI_ESCAPE, "").replaceAll(/\r\n?/gu, "\n");
  if (binaryPath && binaryPath.length > 0) {
    text = text.split(binaryPath).join("<BINARY>");
  }
  const lines = text.split("\n").map((line) => line.replace(/[ \t]+$/u, ""));
  while (lines.length > 0 && lines.at(-1) === "") {
    lines.pop();
  }
  return lines.join("\n");
};

/** SHA-256 hex of the canonical form of `raw` (see {@link canonicalizeRizinOutput}) — the reproducibility key recorded as `reproHash` and recomputed at verify time. */
export const canonicalHash = (raw: string, binaryPath?: string): string =>
  createHash("sha256")
    .update(canonicalizeRizinOutput(raw, binaryPath), "utf-8")
    .digest("hex");

/**
 * Mask addresses in canonical rizin output where they are positional, not semantic,
 * so a rebuild that only moves code compares equal: the leading address of a
 * listing/disassembly line, `@ 0x…` (XREF comments, seeks), branch and call
 * targets, every hex value on a RIP-relative line (its displacement and the
 * resolved-target comment), and address-derived auto-names (`fcn.000011fd`,
 * `loc.…`). Immediates in other operands are kept — a changed constant still
 * changes the result. Shaped around rizin's text disassembly and listings; JSON
 * output is left as is (its offsets are decimal), so it compares exactly.
 */
export const maskAddresses = (canonical: string): string =>
  canonical
    .split("\n")
    .map((line) => {
      const ripMasked = /\brip\b/u.test(line)
        ? line.replaceAll(/0x[0-9a-fA-F]+/gu, "<ADDR>")
        : line;
      return ripMasked
        .replace(
          /^(?<gutter>[\s|\\/:.,=<>`'+*!^-]*)0x[0-9a-fA-F]+/u,
          "$<gutter><ADDR>"
        )
        .replaceAll(/@ 0x[0-9a-fA-F]+/gu, "@ <ADDR>")
        .replaceAll(
          /\b(?<mnemonic>call|jmp|j[a-z]{1,4}|bl|b|b\.[a-z]{2}|cbn?z|tbn?z|loop[a-z]*)(?<gap>\s+)0x[0-9a-fA-F]+/gu,
          "$<mnemonic>$<gap><ADDR>"
        )
        .replaceAll(
          /\b(?<prefix>fcn|sub|loc|case|switch|entry|section)\.[0-9a-fA-F]{4,}\b/gu,
          "$<prefix>.<ADDR>"
        );
    })
    .join("\n");

/** SHA-256 hex of the address-masked canonical output — equal across builds that differ only in where the code sits. */
export const shiftHash = (raw: string, binaryPath?: string): string =>
  createHash("sha256")
    .update(maskAddresses(canonicalizeRizinOutput(raw, binaryPath)), "utf-8")
    .digest("hex");

/** The first `maxLines` lines (≤ `maxBytes`) of the canonical output, stored for human diffing in the verification manifest. Display-only — never hashed. */
export const canonicalExcerpt = (
  raw: string,
  binaryPath?: string,
  maxLines = 20,
  maxBytes = 1024
): string => {
  const head = canonicalizeRizinOutput(raw, binaryPath)
    .split("\n")
    .slice(0, maxLines)
    .join("\n");
  return head.length <= maxBytes ? head : head.slice(0, maxBytes);
};

/** A tool result whose content is the real JSON payload (not just a count), truncated defensively for huge outputs. */
export const jsonResult = (
  header: string,
  data: unknown,
  options: ResultOptions = {}
): Promise<ReToolResult> =>
  buildResult(`${header}\n`, header, formatJson(data), {
    narrowHint: "Narrow with offset/limit or filter.",
    ...options,
  });

/** Same idea for plain-text output (disassembly, decompiled code, triage stdout). */
export const textResult = (
  header: string,
  body: string,
  options: ResultOptions = {}
): Promise<ReToolResult> => buildResult(`${header}\n`, header, body, options);

/** Like textResult, but keeps `prefix` at byte 0 of the content (the disassembly-only label). */
export const prefixedTextResult = (
  prefix: string,
  body: string,
  options: ResultOptions = {}
): Promise<ReToolResult> => buildResult(prefix, prefix.trim(), body, options);

/** Plain, untruncated one-off result (mutations, hashes, session setup). */
export const plainResult = (text: string, ea?: string): ReToolResult => ({
  content: [{ text, type: "text" }],
  details: {
    ea,
    header: text.split("\n")[0] ?? text,
    summary: text.slice(0, 512),
  },
});
