/**
 * omp-native transcript rendering for every RE tool, for both of omp's
 * surfaces:
 *
 * - `renderCall`/`renderResult` (the ANSI transcript): a compact call line
 *   (title + the address/query it targets), and a result block with a status
 *   icon, the tool's own header line ("206 functions", "decompiled 0x4da0
 *   (pdg)"), and a collapsible body. Decompiler output is syntax-highlighted
 *   as C with omp's own highlighter.
 * - `describeCall`/`describeResult` (Tern and other TSP terminals): the same
 *   facts as a native tool view — head with title, target, and meta; the body
 *   as a `code` node the terminal highlights and clamps itself.
 *
 * Without these, omp shows RE tools as a generic card of raw text. Rendering
 * is presentation only: the model still receives the full text content, and
 * nothing here feeds the evidence store.
 */
import { highlightCode } from "@oh-my-pi/pi-coding-agent";
import type { Theme, ToolRenderResultOptions } from "@oh-my-pi/pi-coding-agent";
import { Text } from "@oh-my-pi/pi-tui";
import type { Component } from "@oh-my-pi/pi-tui";
import { code, span, text } from "@oh-my-pi/pi-tui/native/describe";
import type { NativeToolHead, NativeToolView } from "@oh-my-pi/pi-tui/tools";

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
/** Error gist length in a native head; the full message goes in the body. */
const ERROR_GIST_CHARS = 120;

type RenderArgs = Record<string, unknown>;

interface RenderableResult {
  content: { type: string; text?: string }[];
  details?: ReToolDetails;
  isError?: boolean;
}

const firstText = (result: RenderableResult): string => {
  const block = result.content.find(
    (c) => c.type === "text" && typeof c.text === "string"
  );
  return block?.text ?? "";
};

const callLine = (
  spec: RenderSpec,
  args: RenderArgs | undefined,
  theme: Theme
): string => {
  const parts = [theme.fg("toolTitle", theme.bold(spec.title))];
  const subject = spec.subject ? args?.[spec.subject] : undefined;
  if (typeof subject === "string" && subject.length > 0) {
    parts.push(theme.fg("accent", subject));
  }
  const meta: string[] = [];
  for (const key of ["offset", "limit", "filter"]) {
    const value = args?.[key];
    if (value !== undefined && value !== "") {
      meta.push(`${key}:${String(value)}`);
    }
  }
  if (meta.length > 0) {
    parts.push(theme.fg("dim", meta.join(" ")));
  }
  return parts.join(" ");
};

/** Split the content text into the header the details recorded and the body below it. */
const splitBody = (
  content: string,
  details: ReToolDetails | undefined
): { header: string; body: string } => {
  const header = details?.header ?? content.split("\n")[0] ?? "";
  if (content.startsWith(`${header}\n`)) {
    return { body: content.slice(header.length + 1), header };
  }
  if (content.startsWith(header)) {
    return {
      body: content.slice(header.length).replace(/^\s*\n?/u, ""),
      header,
    };
  }
  const nl = content.indexOf("\n");
  return nl === -1
    ? { body: "", header: content }
    : { body: content.slice(nl + 1), header: content.slice(0, nl) };
};

/** omp's highlighter, degrading to plain lines: a renderer must never be the thing that breaks the transcript. */
const highlighted = (source: string, lang: string, theme: Theme): string[] => {
  try {
    return highlightCode(source, lang, theme);
  } catch {
    return source.split("\n").map((line) => theme.fg("toolOutput", line));
  }
};

/** Drop the trailing truncation/artifact notice; the header meta already says so. */
const withoutNotice = (body: string): string =>
  body.replace(/\n\n\[Output truncated:[^\n]*\]$/u, "");

const bodyLines = (
  style: BodyStyle,
  body: string,
  details: ReToolDetails | undefined,
  theme: Theme
): string[] => {
  if (style === "none" || body.trim() === "") {
    return [];
  }
  const trimmed = withoutNotice(body);
  if (
    style === "code" &&
    details?.decompiler &&
    details.decompiler !== "disasm"
  ) {
    return highlighted(trimmed, "c", theme);
  }
  if (style === "json") {
    return highlighted(trimmed, "json", theme);
  }
  return trimmed.split("\n").map((line) => theme.fg("toolOutput", line));
};

const nativeHead = (
  spec: RenderSpec,
  args: RenderArgs | undefined,
  meta: NativeToolHead["meta"] = []
): NativeToolHead => {
  const subject = spec.subject ? args?.[spec.subject] : undefined;
  return {
    title: spec.title,
    ...(typeof subject === "string" && subject.length > 0
      ? { target: subject }
      : {}),
    meta,
  };
};

/** The result body as a native node: C for decompiler output, JSON for list payloads, plain text otherwise. */
const nativeBody = (
  style: BodyStyle,
  body: string,
  details: ReToolDetails | undefined
) => {
  if (style === "none" || body.trim() === "") {
    return;
  }
  const source = withoutNotice(body);
  if (
    style === "code" &&
    details?.decompiler &&
    details.decompiler !== "disasm"
  ) {
    return code(source, { lang: "c", preview: { lines: 12 } });
  }
  if (style === "json") {
    return code(source, { lang: "json", preview: { lines: 6 } });
  }
  return code(source, { preview: { lines: 12 } });
};

/** renderCall/renderResult and describeCall/describeResult for one RE tool, following the shape omp's built-in tools use. */
export const reRenderers = (spec: RenderSpec) => ({
  describeCall(args: RenderArgs): NativeToolView {
    return { inline: true, tool: nativeHead(spec, args) };
  },

  describeResult(
    result: RenderableResult,
    options: ToolRenderResultOptions,
    args?: RenderArgs
  ): NativeToolView {
    const textContent = firstText(result);
    if (options.isPartial) {
      const progress = textContent || `${spec.title}…`;
      return {
        inline: true,
        tool: nativeHead(spec, args, [
          [span(progress, "muted", { fx: "shimmer" })],
        ]),
      };
    }
    if (result.isError) {
      const full = textContent.trim() || "failed";
      const first = full.split("\n", 1)[0]!.trim();
      const gist =
        first.length > ERROR_GIST_CHARS
          ? `${first.slice(0, ERROR_GIST_CHARS - 1)}…`
          : first;
      return {
        inline: true,
        tone: "error",
        tool: nativeHead(spec, args, [[span(`— ${gist}`, "muted")]]),
        ...(gist === full
          ? {}
          : { body: [text([span(full, "error")], { wrap: "word" })] }),
      };
    }
    const { details } = result;
    const { header, body } = splitBody(textContent, details);
    const meta = [
      header,
      ...(details?.decompiler === "disasm"
        ? [[span("disassembly only", "warning")]]
        : []),
      ...(details?.truncated ? [[span("truncated", "warning")]] : []),
      ...(details?.artifactId
        ? [[span(`artifact://${details.artifactId}`, "muted")]]
        : []),
    ];
    const node = nativeBody(spec.body, body, details);
    return node
      ? {
          body: [node],
          tool: nativeHead(spec, args, meta),
          ...(details?.decompiler === "disasm"
            ? { tone: "warning" as const }
            : {}),
        }
      : { inline: true, tool: nativeHead(spec, args, meta) };
  },

  renderCall(
    args: RenderArgs,
    _options: ToolRenderResultOptions,
    theme: Theme
  ): Component {
    return new Text(callLine(spec, args, theme), 0, 0);
  },

  renderResult(
    result: RenderableResult,
    options: ToolRenderResultOptions,
    theme: Theme,
    args?: RenderArgs
  ): Component {
    const resultText = firstText(result);
    if (options.isPartial) {
      const frames = theme.spinnerFrames;
      const spinner =
        options.spinnerFrame !== undefined && frames.length > 0
          ? frames[options.spinnerFrame % frames.length]
          : theme.styledSymbol("status.running", "accent");
      return new Text(
        `${spinner} ${theme.fg("muted", resultText || `${spec.title}…`)}`,
        0,
        0
      );
    }
    if (result.isError) {
      const message = resultText.split("\n")[0] || "failed";
      return new Text(
        `${theme.styledSymbol("status.error", "error")} ${theme.fg("error", message)}`,
        0,
        0
      );
    }

    const { details } = result;
    const { header, body } = splitBody(resultText, details);
    const meta: string[] = [];
    if (details?.decompiler === "disasm") {
      meta.push(theme.fg("warning", "disassembly only"));
    }
    if (details?.truncated) {
      meta.push(theme.fg("warning", "truncated"));
    }
    if (details?.artifactId) {
      meta.push(theme.fg("dim", `artifact://${details.artifactId}`));
    }
    const subject = spec.subject ? args?.[spec.subject] : undefined;
    const headLine = [
      theme.styledSymbol("status.success", "success"),
      theme.fg("toolTitle", header),
      ...(typeof subject === "string" && !header.includes(subject)
        ? [theme.fg("dim", `(${subject})`)]
        : []),
      ...meta,
    ].join(" ");

    const lines = bodyLines(spec.body, body, details, theme);
    const limit = options.expanded
      ? EXPANDED_LINES
      : spec.body === "json"
        ? 0
        : COLLAPSED_LINES;
    const shown = lines.slice(0, limit);
    const out = [headLine, ...shown];
    const hidden = lines.length - shown.length;
    if (hidden > 0) {
      out.push(
        theme.fg(
          "dim",
          `… ${hidden} more line${hidden === 1 ? "" : "s"}${options.expanded ? "" : " (expand to show)"}`
        )
      );
    }
    return new Text(out.join("\n"), 0, 0);
  },
});
