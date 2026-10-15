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
import type { AgentToolResult, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

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

function splitLinesForCounting(content: string): string[] {
	if (content.length === 0) return [];
	const lines = content.split("\n");
	if (content.endsWith("\n")) lines.pop();
	return lines;
}

/** Format bytes as human-readable size. */
function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes}B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

/**
 * Truncate content from the head (keep first N lines/bytes). Never returns a
 * partial line; if the first line alone exceeds the byte limit, returns empty
 * content rather than a fragment.
 */
function truncateHead(content: string, maxLines = MAX_LINES, maxBytes = MAX_BYTES): TruncationResult {
	const totalBytes = Buffer.byteLength(content, "utf-8");
	const lines = splitLinesForCounting(content);
	const totalLines = lines.length;

	if (totalLines <= maxLines && totalBytes <= maxBytes) {
		return { content, truncated: false, totalLines, totalBytes, outputLines: totalLines, outputBytes: totalBytes };
	}

	const firstLineBytes = Buffer.byteLength(lines[0] ?? "", "utf-8");
	if (firstLineBytes > maxBytes) {
		return { content: "", truncated: true, totalLines, totalBytes, outputLines: 0, outputBytes: 0 };
	}

	const outputLinesArr: string[] = [];
	let outputBytesCount = 0;
	for (let i = 0; i < lines.length && i < maxLines; i++) {
		const line = lines[i] ?? "";
		const lineBytes = Buffer.byteLength(line, "utf-8") + (i > 0 ? 1 : 0); // +1 for the joining newline
		if (outputBytesCount + lineBytes > maxBytes) break;
		outputLinesArr.push(line);
		outputBytesCount += lineBytes;
	}

	const outputContent = outputLinesArr.join("\n");
	return {
		content: outputContent,
		truncated: true,
		totalLines,
		totalBytes,
		outputLines: outputLinesArr.length,
		outputBytes: Buffer.byteLength(outputContent, "utf-8"),
	};
}

export interface ResultOptions {
	ea?: string;
	/** When set, truncated output is spilled to this session's artifact store under `tool`'s name. */
	ctx?: ExtensionContext;
	tool?: string;
	/** Truncation hint for the model when no artifact could be saved. */
	narrowHint?: string;
	decompiler?: string;
}

async function spill(full: string, options: ResultOptions): Promise<string | undefined> {
	if (!options.ctx) return undefined;
	try {
		return await options.ctx.sessionManager.saveArtifact(full, options.tool ?? "omp-re");
	} catch {
		// A save failure (disk full, EACCES) must never turn a successful call into an error; the result just stays truncated.
		return undefined;
	}
}

/** Assemble `${lead}${body}` with truncation, artifact spill, and the standard details shape. `lead` is the header line plus newline, or a fixed prefix that must stay at byte 0. */
async function buildResult(lead: string, header: string, body: string, options: ResultOptions): Promise<ReToolResult> {
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
		content: [{ type: "text", text }],
		details: {
			ea: options.ea,
			summary: text.slice(0, 512),
			header,
			...(truncation.truncated ? { truncated: true } : {}),
			...(artifactId ? { artifactId } : {}),
			...(options.decompiler ? { decompiler: options.decompiler } : {}),
		},
	};
}

/**
 * JSON for a model's context: an array is one compact row per line (a third of
 * the tokens of pretty-printing, and line truncation then always cuts between
 * whole rows), any other value is pretty-printed. Both forms are valid JSON.
 */
export function formatJson(data: unknown): string {
	if (!Array.isArray(data)) return JSON.stringify(data, null, 2);
	if (data.length === 0) return "[]";
	return `[\n${data.map((row) => `  ${JSON.stringify(row)}`).join(",\n")}\n]`;
}

/** A tool result whose content is the real JSON payload (not just a count), truncated defensively for huge outputs. */
export function jsonResult(header: string, data: unknown, options: ResultOptions = {}): Promise<ReToolResult> {
	return buildResult(`${header}\n`, header, formatJson(data), {
		narrowHint: "Narrow with offset/limit or filter.",
		...options,
	});
}

/** Same idea for plain-text output (disassembly, decompiled code, triage stdout). */
export function textResult(header: string, body: string, options: ResultOptions = {}): Promise<ReToolResult> {
	return buildResult(`${header}\n`, header, body, options);
}

/** Like textResult, but keeps `prefix` at byte 0 of the content (the disassembly-only label). */
export function prefixedTextResult(prefix: string, body: string, options: ResultOptions = {}): Promise<ReToolResult> {
	return buildResult(prefix, prefix.trim(), body, options);
}

/** Plain, untruncated one-off result (mutations, hashes, session setup). */
export function plainResult(text: string, ea?: string): ReToolResult {
	return { content: [{ type: "text", text }], details: { ea, summary: text.slice(0, 512), header: text.split("\n")[0] ?? text } };
}
