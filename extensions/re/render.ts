/**
 * omp-native transcript rendering for every RE tool: a compact call line
 * (title + the address/query it targets), and a result block with a status
 * icon, the tool's own header line ("206 functions", "decompiled 0x4da0
 * (pdg)"), and a collapsible body. Decompiler output is syntax-highlighted as
 * C with omp's own highlighter; list payloads stay collapsed behind their
 * header until expanded.
 *
 * Rendering is presentation only: the model still receives the full text
 * content, and nothing here feeds the evidence store.
 */
import { highlightCode, type Theme, type ToolRenderResultOptions } from "@oh-my-pi/pi-coding-agent";
import { Text, type Component } from "@oh-my-pi/pi-tui";
import type { ReToolDetails } from "./format.ts";

/** How a result body is shown: "code" highlights C (decompiler output), "json" highlights JSON and stays collapsed, "text" shows plain lines, "none" shows only the header. */
export type BodyStyle = "code" | "json" | "text" | "none";

export interface RenderSpec {
	/** Short title shown in the transcript, e.g. "Decompile". */
	title: string;
	/** Which argument names the call's subject (address, query, path), shown after the title. */
	subject?: string;
	body: BodyStyle;
}

const COLLAPSED_LINES = 6;
const EXPANDED_LINES = 400;

type RenderArgs = Record<string, unknown>;

interface RenderableResult {
	content: { type: string; text?: string }[];
	details?: ReToolDetails;
	isError?: boolean;
}

function firstText(result: RenderableResult): string {
	const block = result.content.find((c) => c.type === "text" && typeof c.text === "string");
	return block?.text ?? "";
}

function callLine(spec: RenderSpec, args: RenderArgs | undefined, theme: Theme): string {
	const parts = [theme.fg("toolTitle", theme.bold(spec.title))];
	const subject = spec.subject ? args?.[spec.subject] : undefined;
	if (typeof subject === "string" && subject.length > 0) parts.push(theme.fg("accent", subject));
	const meta: string[] = [];
	for (const key of ["offset", "limit", "filter"]) {
		const value = args?.[key];
		if (value !== undefined && value !== "") meta.push(`${key}:${String(value)}`);
	}
	if (meta.length > 0) parts.push(theme.fg("dim", meta.join(" ")));
	return parts.join(" ");
}

/** Split the content text into the header the details recorded and the body below it. */
function splitBody(text: string, details: ReToolDetails | undefined): { header: string; body: string } {
	const header = details?.header ?? text.split("\n")[0] ?? "";
	if (text.startsWith(`${header}\n`)) return { header, body: text.slice(header.length + 1) };
	if (text.startsWith(header)) return { header, body: text.slice(header.length).replace(/^\s*\n?/, "") };
	const nl = text.indexOf("\n");
	return nl === -1 ? { header: text, body: "" } : { header: text.slice(0, nl), body: text.slice(nl + 1) };
}

/** omp's highlighter, degrading to plain lines: a renderer must never be the thing that breaks the transcript. */
function highlighted(code: string, lang: string, theme: Theme): string[] {
	try {
		return highlightCode(code, lang, theme);
	} catch {
		return code.split("\n").map((line) => theme.fg("toolOutput", line));
	}
}

function bodyLines(style: BodyStyle, body: string, details: ReToolDetails | undefined, theme: Theme): string[] {
	if (style === "none" || body.trim() === "") return [];
	// Drop the trailing truncation/artifact notice; the header meta already says so.
	const trimmed = body.replace(/\n\n\[Output truncated:[^\n]*\]$/, "");
	if (style === "code" && details?.decompiler && details.decompiler !== "disasm") return highlighted(trimmed, "c", theme);
	if (style === "json") return highlighted(trimmed, "json", theme);
	return trimmed.split("\n").map((line) => theme.fg("toolOutput", line));
}

/** renderCall/renderResult for one RE tool, following the shape omp's built-in tools use. */
export function reRenderers(spec: RenderSpec) {
	return {
		renderCall(args: RenderArgs, _options: ToolRenderResultOptions, theme: Theme): Component {
			return new Text(callLine(spec, args, theme), 0, 0);
		},

		renderResult(result: RenderableResult, options: ToolRenderResultOptions, theme: Theme, args?: RenderArgs): Component {
			const text = firstText(result);
			if (options.isPartial) {
				const frames = theme.spinnerFrames;
				const spinner =
					options.spinnerFrame !== undefined && frames.length > 0
						? frames[options.spinnerFrame % frames.length]
						: theme.styledSymbol("status.running", "accent");
				return new Text(`${spinner} ${theme.fg("muted", text || `${spec.title}…`)}`, 0, 0);
			}
			if (result.isError) {
				const message = text.split("\n")[0] || "failed";
				return new Text(`${theme.styledSymbol("status.error", "error")} ${theme.fg("error", message)}`, 0, 0);
			}

			const details = result.details;
			const { header, body } = splitBody(text, details);
			const meta: string[] = [];
			if (details?.decompiler === "disasm") meta.push(theme.fg("warning", "disassembly only"));
			if (details?.truncated) meta.push(theme.fg("warning", "truncated"));
			if (details?.artifactId) meta.push(theme.fg("dim", `artifact://${details.artifactId}`));
			const subject = spec.subject ? args?.[spec.subject] : undefined;
			const headLine = [
				theme.styledSymbol("status.success", "success"),
				theme.fg("toolTitle", header),
				...(typeof subject === "string" && !header.includes(subject) ? [theme.fg("dim", `(${subject})`)] : []),
				...meta,
			].join(" ");

			const lines = bodyLines(spec.body, body, details, theme);
			const limit = options.expanded ? EXPANDED_LINES : spec.body === "json" ? 0 : COLLAPSED_LINES;
			const shown = lines.slice(0, limit);
			const out = [headLine, ...shown];
			const hidden = lines.length - shown.length;
			if (hidden > 0) out.push(theme.fg("dim", `… ${hidden} more line${hidden === 1 ? "" : "s"}${options.expanded ? "" : " (expand to show)"}`));
			return new Text(out.join("\n"), 0, 0);
		},
	};
}
