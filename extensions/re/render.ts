/**
 * omp-native transcript rendering for every RE tool, for both of omp's
 * surfaces:
 *
 * - `renderCall`/`renderResult` (the ANSI transcript): a compact call line
 *   (title + the address/query it targets), and a result block with a status
 *   icon, the tool's own header line and a collapsible body.
 * - `describeCall`/`describeResult` (Tern and other TSP terminals): the same
 *   facts as a native tool view — head with title, target, and meta; the body
 *   as a `code` node the terminal highlights and clamps itself.
 *
 * Without these, omp shows RE tools as a generic card of raw text. How one
 * tool is shown is the engine's to say (the `render` hint of its
 * description); this module draws from the hint, the call's arguments and
 * the result. The model still receives the full text.
 */
import { highlightCode, type Theme, type ToolRenderResultOptions } from "@oh-my-pi/pi-coding-agent";
import { Text, type Component } from "@oh-my-pi/pi-tui";
import { code, span, text } from "@oh-my-pi/pi-tui/native/describe";
import type { NativeToolHead, NativeToolView } from "@oh-my-pi/pi-tui/tools";

/**
 * How every RE tool is presented: `discoverable`, never `essential`. omp mounts
 * a discoverable tool as an `xd://<name>` device instead of putting its schema
 * in the model's top-level tool list, so the RE tools cost the context nothing
 * until they are used. The model reads a device's documentation with
 * `read xd://<name>`, calls it directly with `write xd://<name>`, or — to
 * compose, loop, and build its own helpers — from omp's `eval` tool as
 * `await tool.<name>({ ... })`. Every one of those paths goes through omp's own
 * tool wrapper: the tool's approval tier and omp's tool events. (With omp's
 * `tools.xdev` setting off, omp lists discoverable tools top-level instead.)
 */
export const RE_LOAD_MODE = "discoverable" as const;

/** How a result body is shown: "json" highlights JSON and stays collapsed, "text" shows plain lines, "none" shows only the header. */
export type BodyStyle = "json" | "text" | "none";

export interface RenderSpec {
	/** Short title shown in the transcript. */
	title: string;
	/** Which argument names the call's subject (address, query, path), shown after the title. */
	subject?: string;
	body: BodyStyle;
}

const COLLAPSED_LINES = 6;
const EXPANDED_LINES = 400;
/** Error gist length in a native head; the full message goes in the body. */
const ERROR_GIST_CHARS = 120;

/** A call's arguments as omp hands them to a renderer: whatever the model sent. */
type RenderArgs = unknown;

interface RenderableResult {
	content: { type: string; text?: string }[];
	details?: { truncated?: boolean; artifactId?: string };
	isError?: boolean;
}

function firstText(result: RenderableResult): string {
	const block = result.content.find((c) => c.type === "text" && typeof c.text === "string");
	return block?.text ?? "";
}

function subjectOf(spec: RenderSpec, args: RenderArgs): string | undefined {
	const subject = spec.subject && args !== null && typeof args === "object" ? (args as Record<string, unknown>)[spec.subject] : undefined;
	return typeof subject === "string" && subject.length > 0 ? subject : undefined;
}

function callLine(spec: RenderSpec, args: RenderArgs, theme: Theme): string {
	const parts = [theme.fg("toolTitle", theme.bold(spec.title))];
	const subject = subjectOf(spec, args);
	if (subject) parts.push(theme.fg("accent", subject));
	return parts.join(" ");
}

/** The result's first line is its header; the rest is the body. */
function splitBody(text: string): { header: string; body: string } {
	const nl = text.indexOf("\n");
	return nl === -1 ? { header: text, body: "" } : { header: text.slice(0, nl), body: text.slice(nl + 1) };
}

/** omp's highlighter, degrading to plain lines: a renderer must never be the thing that breaks the transcript. */
function highlighted(source: string, lang: string, theme: Theme): string[] {
	try {
		return highlightCode(source, lang, theme);
	} catch {
		return source.split("\n").map((line) => theme.fg("toolOutput", line));
	}
}

function bodyLines(style: BodyStyle, body: string, theme: Theme): string[] {
	if (style === "none" || body.trim() === "") return [];
	if (style === "json") return highlighted(body, "json", theme);
	return body.split("\n").map((line) => theme.fg("toolOutput", line));
}

function nativeHead(spec: RenderSpec, args: RenderArgs, meta: NativeToolHead["meta"] = []): NativeToolHead {
	const subject = subjectOf(spec, args);
	return { title: spec.title, ...(subject ? { target: subject } : {}), meta };
}

function nativeBody(style: BodyStyle, body: string) {
	if (style === "none" || body.trim() === "") return undefined;
	if (style === "json") return code(body, { lang: "json", preview: { lines: 6 } });
	return code(body, { preview: { lines: 12 } });
}

/** renderCall/renderResult and describeCall/describeResult for one RE tool, following the shape omp's built-in tools use. */
export function reRenderers(spec: RenderSpec) {
	return {
		renderCall(args: RenderArgs, _options: ToolRenderResultOptions, theme: Theme): Component {
			return new Text(callLine(spec, args, theme), 0, 0);
		},

		renderResult(result: RenderableResult, options: ToolRenderResultOptions, theme: Theme, args?: RenderArgs): Component {
			const shown = firstText(result);
			if (options.isPartial) {
				const frames = theme.spinnerFrames;
				const spinner = options.spinnerFrame !== undefined && frames.length > 0 ? frames[options.spinnerFrame % frames.length] : theme.styledSymbol("status.running", "accent");
				return new Text(`${spinner} ${theme.fg("muted", shown || `${spec.title}…`)}`, 0, 0);
			}
			if (result.isError) {
				const message = shown.split("\n")[0] || "failed";
				return new Text(`${theme.styledSymbol("status.error", "error")} ${theme.fg("error", message)}`, 0, 0);
			}

			const details = result.details;
			const { header, body } = splitBody(shown);
			const meta: string[] = [];
			if (details?.truncated) meta.push(theme.fg("warning", "truncated"));
			if (details?.artifactId) meta.push(theme.fg("dim", `artifact://${details.artifactId}`));
			const subject = subjectOf(spec, args);
			const headLine = [theme.styledSymbol("status.success", "success"), theme.fg("toolTitle", header), ...(subject && !header.includes(subject) ? [theme.fg("dim", `(${subject})`)] : []), ...meta].join(" ");

			const lines = bodyLines(spec.body, body, theme);
			const limit = options.expanded ? EXPANDED_LINES : spec.body === "json" ? 0 : COLLAPSED_LINES;
			const visible = lines.slice(0, limit);
			const out = [headLine, ...visible];
			const hidden = lines.length - visible.length;
			if (hidden > 0) out.push(theme.fg("dim", `… ${hidden} more line${hidden === 1 ? "" : "s"}${options.expanded ? "" : " (expand to show)"}`));
			return new Text(out.join("\n"), 0, 0);
		},

		describeCall(args: RenderArgs): NativeToolView {
			return { tool: nativeHead(spec, args), inline: true };
		},

		describeResult(result: RenderableResult, options: ToolRenderResultOptions, args?: RenderArgs): NativeToolView {
			const shown = firstText(result);
			if (options.isPartial) {
				return { tool: nativeHead(spec, args, [[span(shown || `${spec.title}…`, "muted", { fx: "shimmer" })]]), inline: true };
			}
			if (result.isError) {
				const full = shown.trim() || "failed";
				const first = full.split("\n", 1)[0]!.trim();
				const gist = first.length > ERROR_GIST_CHARS ? `${first.slice(0, ERROR_GIST_CHARS - 1)}…` : first;
				return {
					tool: nativeHead(spec, args, [[span(`— ${gist}`, "muted")]]),
					tone: "error",
					inline: true,
					...(gist === full ? {} : { body: [text([span(full, "error")], { wrap: "word" })] }),
				};
			}
			const details = result.details;
			const { header, body } = splitBody(shown);
			const meta = [header, ...(details?.truncated ? [[span("truncated", "warning")]] : []), ...(details?.artifactId ? [[span(`artifact://${details.artifactId}`, "muted")]] : [])];
			const node = nativeBody(spec.body, body);
			return node ? { tool: nativeHead(spec, args, meta), body: [node] } : { tool: nativeHead(spec, args, meta), inline: true };
		},
	};
}
