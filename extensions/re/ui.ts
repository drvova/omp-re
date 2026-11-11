/**
 * What omp-re draws in omp's terminal: the status band above the editor, and
 * the overlays a `/re` line or a shortcut opens — a list to pick from, a
 * function's code. Everything shown is data the engine sent (a session's
 * state, a view: docs/engine-protocol.md); this module lays it out and reads
 * the keys.
 */
import { getSymbolTheme, highlightCode, type ExtensionContext, type Theme } from "@oh-my-pi/pi-coding-agent";
import { fuzzyFilter, matchesKey, SelectList, truncateToWidth, type Component, type KeybindingsManager, type SelectItem, type SelectListTheme, type TUI } from "@oh-my-pi/pi-tui";
import type { JsonObject } from "./engine.ts";
import type { SessionState } from "./host.ts";

type Level = "info" | "warning" | "error";

/** A view as the engine answers one. */
type View =
	| { type: "notice"; text: string; level: Level }
	| { type: "panel"; title: string; hint: string; rows: Row[] }
	| {
			type: "code";
			title: string;
			disasm: string[];
			decompile?: { label: string; note: string; tone: "dim" | "warning"; code: string; language?: string };
			noDecompile: string;
			ask: string;
			xrefs: ViewRequest;
	  };

interface ViewRequest {
	kind: string;
	arg?: JsonObject;
}

interface Row {
	value: string;
	label: string;
	description?: string;
	enter: { draft: string } | { view: ViewRequest };
}

/** Asks the engine for a view of the session `ctx` is in. */
export type ViewSource = (ctx: ExtensionContext, request: ViewRequest) => Promise<View>;

function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes}B`;
	const units = ["K", "M", "G", "T"];
	let value = bytes;
	let unit = -1;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit++;
	}
	return `${value.toFixed(1).replace(/\.0$/, "")}${units[unit]}`;
}

function bandLines(facts: JsonObject, theme: Theme, width: number): string[] {
	const info = [facts.format, facts.arch, facts.os].filter(Boolean).join(" ");
	const prot = Array.isArray(facts.prot) ? facts.prot.join(",") : "";
	const groups = [facts.name, info, facts.entry ? `entry ${facts.entry}` : null, typeof facts.size === "number" ? formatSize(facts.size) : null, prot || null].filter(Boolean);
	const counts = [`${facts.fnCount ?? 0} fn`, `${facts.findings ?? 0} findings`, `${facts.evidence ?? 0} evidence`].join(" · ");
	return [truncateToWidth(theme.fg("accent", groups.join("  ")), width), truncateToWidth(theme.fg("muted", counts), width)];
}

/** Mount the status band for the state the engine last sent. The widget closes over that snapshot, so drawing it asks nothing. */
export function drawStatusBand(ctx: ExtensionContext, state: SessionState): void {
	if (!ctx.hasUI || !state.facts) return;
	const facts = state.facts;
	try {
		ctx.ui.setWidget(
			"re.hud",
			(_tui: TUI, theme: Theme) => ({
				render: (width: number) => bandLines(facts, theme, width),
				invalidate() {},
			}),
			{ placement: "aboveEditor" },
		);
	} catch {
		// A context omp has since retired cannot be drawn on; the next state redraws.
	}
}

const VISIBLE_ROWS = 12;

function selectListTheme(theme: Theme): SelectListTheme {
	return {
		selectedPrefix: (t) => theme.fg("accent", t),
		selectedText: (t) => theme.fg("accent", t),
		description: (t) => theme.fg("dim", t),
		scrollInfo: (t) => theme.fg("dim", t),
		noMatch: (t) => theme.fg("muted", t),
		symbols: getSymbolTheme(),
	};
}

/** A scrollable list filtered by typing. The filter fuzzy-matches the label only, so an address in the description never pollutes a match; esc clears it, then closes. */
function pickerPanel(theme: Theme, panel: { title: string; hint: string; rows: Row[] }, choose: (row: Row) => Promise<"close" | "keep">, done: (result: undefined) => void): Component {
	const items: SelectItem[] = panel.rows.map((row, index) => ({ value: String(index), label: row.label, description: row.description }));
	let filter = "";
	let list = build();

	function build(): SelectList {
		const shown = filter !== "" ? fuzzyFilter(items, filter, (item) => item.label) : items;
		const made = new SelectList(shown, VISIBLE_ROWS, selectListTheme(theme));
		made.onSelect = async (item) => {
			if ((await choose(panel.rows[Number(item.value)]!)) !== "keep") done(undefined);
		};
		made.onCancel = () => done(undefined);
		return made;
	}

	return {
		render(width: number): string[] {
			const filterLine = filter !== "" ? `${theme.fg("dim", "/")}${filter}` : theme.fg("dim", "(type to filter)");
			const lines = [theme.fg("accent", panel.title) + theme.fg("dim", ` ${items.length}`), filterLine, ...list.render(width), theme.fg("dim", panel.hint)];
			return lines.map((line) => truncateToWidth(line, width));
		},
		handleInput(data: string) {
			if (matchesKey(data, "escape")) {
				if (filter === "") done(undefined);
				else {
					filter = "";
					list = build();
				}
			} else if (data === "\x7f" || data === "\b") {
				filter = filter.slice(0, -1);
				list = build();
			} else if (data.length === 1 && data >= " " && data <= "~") {
				filter += data;
				list = build();
			} else {
				list.handleInput(data);
			}
		},
		invalidate() {
			list.invalidate();
		},
	};
}

/** Fixed-width text with a scroll offset — not a SelectList, whose columns and truncation would reflow disassembly and pseudo-C alike. */
function codeView(options: {
	title: string;
	disasm: string[];
	decompiled: string[] | null;
	decompileLabel: string;
	theme: Theme;
	keybindings: KeybindingsManager;
	onNoDecompile: () => void;
	onXrefs: () => void;
	onAsk: () => void;
	done: (result: undefined) => void;
}): Component {
	const { theme, decompiled } = options;
	const disasm = options.disasm.map((line) => theme.fg("text", line));
	let showDecompiled = false;
	let offset = 0;
	const current = () => (showDecompiled && decompiled ? decompiled : disasm);

	return {
		render(width: number): string[] {
			const lines = current();
			const window = lines.slice(offset, offset + VISIBLE_ROWS);
			const position = lines.length > VISIBLE_ROWS ? ` · ${offset + 1}-${Math.min(offset + VISIBLE_ROWS, lines.length)}/${lines.length}` : "";
			return [
				theme.fg("accent", `${options.title} · ${showDecompiled ? options.decompileLabel : "disasm"}`),
				...(window.length > 0 ? window : [theme.fg("dim", "(nothing to show)")]),
				theme.fg("dim", `d decomp · x xrefs · a ask · esc back${position}`),
			].map((line) => truncateToWidth(line, width));
		},
		handleInput(data: string) {
			const keys = options.keybindings;
			if (matchesKey(data, "escape")) options.done(undefined);
			else if (data === "d") {
				if (!decompiled) options.onNoDecompile();
				else {
					showDecompiled = !showDecompiled;
					offset = 0;
				}
			} else if (data === "x") options.onXrefs();
			else if (data === "a") options.onAsk();
			else {
				if (keys.matches(data, "tui.select.up")) offset -= 1;
				else if (keys.matches(data, "tui.select.down")) offset += 1;
				else if (keys.matches(data, "tui.select.pageUp")) offset -= VISIBLE_ROWS;
				else if (keys.matches(data, "tui.select.pageDown")) offset += VISIBLE_ROWS;
				offset = Math.min(Math.max(0, offset), Math.max(0, current().length - 1));
			}
		},
		invalidate() {},
	};
}

/** omp's highlighter, degrading to plain lines: drawing must never be what breaks the overlay. */
function highlighted(code: string, language: string | undefined, theme: Theme): string[] {
	if (language) {
		try {
			return highlightCode(code, language, theme);
		} catch {
			// plain lines below
		}
	}
	return code.split("\n").map((line) => theme.fg("text", line));
}

/**
 * Ask the engine for a view and show it over the editor: a notice is said, a
 * panel or a function's code is an overlay that stays until dismissed.
 * Answers whether something was shown, which is what keeps the list it was
 * opened from on screen.
 */
export async function openView(ctx: ExtensionContext, source: ViewSource, request: ViewRequest): Promise<boolean> {
	if (!ctx.hasUI) return false;
	let view: View;
	try {
		view = await source(ctx, request);
	} catch (error) {
		ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
		return false;
	}
	if (view.type === "notice") {
		ctx.ui.notify(view.text, view.level);
		return false;
	}
	if (view.type === "panel") {
		const choose = async (row: Row): Promise<"close" | "keep"> => {
			if ("draft" in row.enter) {
				// Closed before the draft lands: a notice raised under an open overlay can render beneath it.
				ctx.ui.setEditorText(row.enter.draft);
				return "close";
			}
			return (await openView(ctx, source, row.enter.view)) ? "keep" : "close";
		};
		await ctx.ui.custom<undefined>((_tui, theme, _keybindings, done) => pickerPanel(theme, view, choose, done), { overlay: true });
		return true;
	}
	await ctx.ui.custom<undefined>(
		(_tui, theme, keybindings, done) =>
			codeView({
				title: view.title,
				disasm: view.disasm,
				decompiled: view.decompile ? [theme.fg(view.decompile.tone, view.decompile.note), ...highlighted(view.decompile.code, view.decompile.language, theme)] : null,
				decompileLabel: view.decompile?.label ?? "decompile",
				theme,
				keybindings,
				onNoDecompile: () => ctx.ui.notify(view.noDecompile, "info"),
				onXrefs: () => void openView(ctx, source, view.xrefs),
				onAsk: () => {
					ctx.ui.setEditorText(view.ask);
					done(undefined);
				},
				done,
			}),
		{ overlay: true },
	);
	return true;
}
