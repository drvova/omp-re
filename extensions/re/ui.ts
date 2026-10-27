/**
 * RE surface: an always-visible binary-facts status band plus transient,
 * dismissable overlays opened by slash commands and shortcuts.
 * `binaryFacts()` is this package's single source of truth for
 * reverser-relevant state (format, arch, entry, protections, counts);
 * `refreshStatusBand` mounts it via `ctx.ui.setWidget` above the editor.
 */
import { basename } from "node:path";
import { getSymbolTheme, highlightCode, type ExtensionAPI, type ExtensionContext, type Theme } from "@oh-my-pi/pi-coding-agent";
import {
	fuzzyFilter,
	matchesKey,
	SelectList,
	truncateToWidth,
	type Component,
	type KeybindingsManager,
	type SelectItem,
	type SelectListTheme,
	type TUI,
} from "@oh-my-pi/pi-tui";
import { RE_ALL_TOOL_NAMES } from "./audit.ts";
import { decompileAt } from "./decompile.ts";
import { disassembleAt } from "./disasm.ts";
import { branchEntries, customEntries } from "./entries.ts";
import { type FindingRecord, findingNote, liveFindings } from "./findings.ts";
import { addrOf, codeSize, eaFromOffset, type RzSession } from "./rizin.ts";
import { ensureRizin, getState } from "./state.ts";

/** The live rizin session for UI use, or null (with the reason already shown) when there is none. Respawns transparently like the tools do, so a panel opened after a branch change still works. */
async function uiSession(ctx: ExtensionContext): Promise<RzSession | null> {
	if (!getState(ctx).binaryPath) {
		ctx.ui.notify("omp-re: no binary open — use /re open <path> first", "error");
		return null;
	}
	try {
		return await ensureRizin(ctx);
	} catch (err) {
		ctx.ui.notify(err instanceof Error ? err.message : String(err), "error");
		return null;
	}
}

/** Static facts an `ij`/`iej` pair answers for a given rizin process — invariant for its lifetime, unlike the function count (which annotations can change). */
interface BinInfo {
	core: { size: number; format: string };
	bin: {
		arch: string;
		bits: number;
		os: string;
		class: string;
		stripped: boolean;
		static: boolean;
		pie?: boolean;
		nx: boolean;
		canary: boolean;
	};
}

const binInfoCache = new WeakMap<RzSession, { info: BinInfo | null; entry: number | null }>();

async function loadBinInfo(rz: RzSession): Promise<{ info: BinInfo | null; entry: number | null }> {
	const cached = binInfoCache.get(rz);
	if (cached) return cached;
	const info = await rz.cmdj<BinInfo>("ij").catch(() => null);
	const iej = await rz.cmdj<Array<{ vaddr: number; type?: string }>>("iej").catch(() => null);
	const program = iej?.find((e) => e.type === "program") ?? iej?.[0];
	const result = { info, entry: program?.vaddr ?? null };
	binInfoCache.set(rz, result);
	return result;
}

/** Reverser-relevant facts about the currently open binary, plus live counts. Single source of truth for the status-band presenter — never derive display strings anywhere else. */
export interface BinaryFacts {
	name: string;
	path: string | null;
	size: number | null;
	format: string | null;
	arch: string | null;
	os: string | null;
	entry: string | null;
	prot: string[];
	fnCount: number;
	findings: number;
	evidence: number;
}

export async function binaryFacts(ctx: ExtensionContext): Promise<BinaryFacts> {
	const state = getState(ctx);
	const facts: BinaryFacts = {
		name: state.binaryPath ? basename(state.binaryPath) : "no binary",
		path: state.binaryPath,
		size: null,
		format: null,
		arch: null,
		os: null,
		entry: null,
		prot: [],
		fnCount: 0,
		findings: liveFindings(ctx).length,
		evidence: state.evidenceCount,
	};

	// Never spawn from the status band: it only describes a process that is already up.
	const rz = state.rz;
	if (!rz || rz.isClosed) return facts;

	facts.fnCount = Number.parseInt((await rz.cmd("aflc").catch(() => "0")).trim(), 10) || 0;
	const { info, entry } = await loadBinInfo(rz);
	if (info?.bin) {
		const bin = info.bin;
		facts.format = bin.class ?? null;
		facts.arch = bin.arch ? `${bin.arch}/${bin.bits}` : null;
		facts.os = bin.os ?? null;
		const prot: string[] = [];
		if (bin.stripped) prot.push("stripped");
		if (bin.static) prot.push("static");
		if (bin.pie) prot.push("pie");
		if (bin.nx) prot.push("nx");
		if (bin.canary) prot.push("canary");
		facts.prot = prot;
	}
	facts.size = info?.core?.size ?? null;
	facts.entry = entry != null ? eaFromOffset(entry) : null;
	return facts;
}

function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes}B`;
	const units = ["K", "M", "G", "T"];
	let value = bytes;
	let unitIndex = -1;
	while (value >= 1024 && unitIndex < units.length - 1) {
		value /= 1024;
		unitIndex++;
	}
	return `${value.toFixed(1).replace(/\.0$/, "")}${units[unitIndex]}`;
}

function renderBand(f: BinaryFacts, theme: Theme, width: number): string[] {
	const info = [f.format, f.arch, f.os].filter(Boolean).join(" ");
	const groups = [f.name, info, f.entry ? `entry ${f.entry}` : null, f.size != null ? formatSize(f.size) : null, f.prot.join(",") || null].filter(Boolean);
	const line1 = theme.fg("accent", groups.join("  "));
	const metrics = [`${f.fnCount} fn`, `${f.findings} findings`, `${f.evidence} evidence`].join(" · ");
	const line2 = theme.fg("muted", metrics);
	return [truncateToWidth(line1, width), truncateToWidth(line2, width)];
}

/** The widget factory closes over one already-computed BinaryFacts snapshot; render() never re-fetches, so it stays a pure, synchronous presenter as the Component contract requires. */
function makeHud(facts: BinaryFacts): (tui: TUI, theme: Theme) => Component {
	return (_tui: TUI, theme: Theme) => ({
		render(width: number): string[] {
			return renderBand(facts, theme, width);
		},
		invalidate() {},
	});
}

/**
 * Exported so index.ts can force an immediate refresh right after opening a
 * binary — session_start handlers across extensions are not guaranteed to run
 * in a particular order. With no binary open the band reads "no binary".
 */
export async function refreshStatusBand(ctx: ExtensionContext): Promise<void> {
	if (!ctx.hasUI) return;
	try {
		const facts = await binaryFacts(ctx);
		ctx.ui.setWidget("re.hud", makeHud(facts), { placement: "aboveEditor" });
	} catch {
		// best-effort: a stale ctx or dead rizin process must never crash the primary flow
	}
}

const MAX_VISIBLE_ROWS = 12;
const DEFAULT_HINT = "enter select · esc close";

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

interface PickerOptions {
	title: string;
	items: SelectItem[];
	/** Invoked on Enter. Return "close" to dismiss the panel, "keep" to leave it open. */
	onChoose?: (item: SelectItem) => "close" | "keep" | Promise<"close" | "keep">;
	/** Right-hand hint text, e.g. "enter open · esc back". */
	hint?: string;
	done: (result: undefined) => void;
}

/** A scrollable, fuzzy-filterable list: a SelectList wrapped in custom panel chrome (title + count, a styled filter line, a custom hint, and esc clears the filter then closes). The filter is driven here and fuzzy-matches on `label` only (omp's fuzzyFilter), so addresses in `value` don't pollute matches; the SelectList is rebuilt on each filter change. */
function makePickerPanel(theme: Theme, opts: PickerOptions): Component {
	const allItems = opts.items;
	let filter = "";
	let selectList = buildSelectList();

	function buildSelectList(): SelectList {
		const filtered = filter !== "" ? fuzzyFilter(allItems, filter, (item) => item.label) : allItems;
		const sl = new SelectList(filtered, MAX_VISIBLE_ROWS, selectListTheme(theme));
		sl.onSelect = async (item) => {
			if ((await opts.onChoose?.(item)) !== "keep") opts.done(undefined);
		};
		sl.onCancel = () => opts.done(undefined);
		return sl;
	}

	return {
		render(width: number): string[] {
			const filterLine = filter !== "" ? `${theme.fg("dim", "/")}${filter}` : theme.fg("dim", "(type to filter)");
			const count = theme.fg("dim", ` ${allItems.length}`);
			const lines = [theme.fg("accent", opts.title) + count, filterLine, ...selectList.render(width), theme.fg("dim", opts.hint ?? DEFAULT_HINT)];
			return lines.map((l) => truncateToWidth(l, width));
		},
		handleInput(data: string) {
			if (matchesKey(data, "escape")) {
				if (filter !== "") {
					filter = "";
					selectList = buildSelectList();
				} else {
					opts.done(undefined);
				}
				return;
			}
			if (data === "\x7f" || data === "\b") {
				filter = filter.slice(0, -1);
				selectList = buildSelectList();
				return;
			}
			if (data.length === 1 && data >= " " && data <= "~") {
				filter += data;
				selectList = buildSelectList();
				return;
			}
			selectList.handleInput(data);
		},
		invalidate() {
			selectList.invalidate();
		},
	};
}

/**
 * Overlay when the interactive TUI is available; falls back to a plain
 * notification otherwise (headless/print/RPC modes, where `ctx.ui.custom` is
 * a no-op that would otherwise hang the command indefinitely).
 */
async function showPanel(ctx: ExtensionContext, opts: Omit<PickerOptions, "done">): Promise<void> {
	if (!ctx.hasUI) {
		const body = opts.items.length > 0 ? opts.items.map((item) => item.label).join("\n") : "(nothing to show)";
		ctx.ui.notify(`${opts.title}\n${body}`.slice(0, 4000), "info");
		return;
	}
	await ctx.ui.custom<undefined>((_tui, theme, _keybindings, done) => makePickerPanel(theme, { ...opts, done }), { overlay: true });
}

export async function showFunctionsPanel(ctx: ExtensionContext): Promise<void> {
	const rz = await uiSession(ctx);
	if (!rz) return;
	interface Fn {
		addr?: number;
		offset?: number;
		name: string;
		size?: number;
		realsz?: number;
	}
	const fns = (await rz.cmdj<Fn[]>("aflj").catch(() => null)) ?? [];
	const items: SelectItem[] = fns.flatMap((fn) => {
		const addr = addrOf(fn);
		if (addr === undefined) return [];
		const value = eaFromOffset(addr);
		const size = codeSize(fn);
		return [{ value, label: fn.name, description: size !== undefined ? `${value} · ${size}b` : value }];
	});
	await showPanel(ctx, {
		title: "omp-re: functions",
		items,
		onChoose: async (item) => {
			await showCodeView(ctx, item.value, item.label);
			return "keep" as const;
		},
		hint: "enter open · type to filter · esc close",
	});
}

type CodeViewMode = "disasm" | "decompile";

/**
 * Fixed-width addressed-text viewer with a scroll offset — deliberately not
 * SelectList, whose column layout and truncation would reflow disassembly and
 * pseudo-C alike. Decompiled code is syntax-highlighted with omp's own
 * highlighter (once, at open).
 */
function makeCodeView(opts: {
	title: string;
	disasmLines: string[];
	decompileLines: string[] | null;
	decompileLabel: string;
	theme: Theme;
	keybindings: KeybindingsManager;
	onToggle: () => boolean;
	onXrefs: () => void;
	onAsk: () => void;
	done: (result: undefined) => void;
}): Component {
	let mode: CodeViewMode = "disasm";
	let offset = 0;
	const theme = opts.theme;
	const disasm = opts.disasmLines.map((l) => theme.fg("text", l));
	const decompiled = opts.decompileLines;

	function current(): string[] {
		return mode === "decompile" && decompiled ? decompiled : disasm;
	}

	function clamp(): void {
		offset = Math.min(Math.max(0, offset), Math.max(0, current().length - 1));
	}

	return {
		render(width: number): string[] {
			const lines = current();
			const window = lines.slice(offset, offset + MAX_VISIBLE_ROWS);
			const label = mode === "decompile" ? opts.decompileLabel : "disasm";
			const position = lines.length > MAX_VISIBLE_ROWS ? ` · ${offset + 1}-${Math.min(offset + MAX_VISIBLE_ROWS, lines.length)}/${lines.length}` : "";
			const rendered = [
				theme.fg("accent", `${opts.title} · ${label}`),
				...(window.length > 0 ? window : [theme.fg("dim", "(nothing to show)")]),
				theme.fg("dim", `d decomp · x xrefs · a ask · esc back${position}`),
			];
			return rendered.map((l) => truncateToWidth(l, width));
		},
		handleInput(data: string) {
			if (matchesKey(data, "escape")) {
				opts.done(undefined);
				return;
			}
			if (data === "d") {
				if (opts.onToggle()) {
					mode = mode === "disasm" ? "decompile" : "disasm";
					offset = 0;
				}
				return;
			}
			if (data === "x") {
				opts.onXrefs();
				return;
			}
			if (data === "a") {
				opts.onAsk();
				return;
			}
			const kb = opts.keybindings;
			if (kb.matches(data, "tui.select.up")) offset -= 1;
			else if (kb.matches(data, "tui.select.down")) offset += 1;
			else if (kb.matches(data, "tui.select.pageUp")) offset -= MAX_VISIBLE_ROWS;
			else if (kb.matches(data, "tui.select.pageDown")) offset += MAX_VISIBLE_ROWS;
			else return;
			clamp();
		},
		invalidate() {},
	};
}

interface RzXrefRow {
	from?: number;
	type: string;
}

/** Name the function containing each xref site (rizin's axtj carries none). Bounded: past the cap, rows keep their bare address. */
async function labelXrefs(rz: RzSession, rows: RzXrefRow[]): Promise<SelectItem[]> {
	const LABEL_CAP = 64;
	const items: SelectItem[] = [];
	for (const [index, row] of rows.entries()) {
		if (typeof row.from !== "number") continue;
		const ea = eaFromOffset(row.from);
		let label = ea;
		if (index < LABEL_CAP) {
			const fn = (await rz.cmdj<{ name?: string }[]>(`afij @ ${ea}`).catch(() => null))?.[0];
			if (fn?.name) label = `${fn.name} (${ea})`;
		}
		items.push({ value: ea, label, description: row.type });
	}
	return items;
}

/**
 * The code-view surface: disassembly (default) or decompiled pseudo-C, with
 * xref following and a model hand-off key. Writes no `re.evidence` entry —
 * evidence means "the agent observed this"; recording a human's browsing
 * would let a claim be credited to something the model never actually saw.
 */
export async function showCodeView(ctx: ExtensionContext, addr: string, name?: string, depth = 0): Promise<void> {
	const session = await uiSession(ctx);
	if (!session) return;
	const rz: RzSession = session;
	if (depth > 8) {
		ctx.ui.notify("omp-re: xref chain too deep — stopping to avoid an unbounded loop", "info");
		return;
	}

	const outcome = await decompileAt(rz, addr).catch(() => null);
	const disasm = await disassembleAt(rz, addr).catch(() => null);
	const disasmLines = disasm?.lines ?? [];
	if (disasmLines.length === 0 && !outcome) {
		ctx.ui.notify(`omp-re: no code at ${addr}`, "error");
		return;
	}

	if (!ctx.hasUI) {
		ctx.ui.notify(`${name ?? addr}\n${disasmLines.join("\n")}`.slice(0, 4000), "info");
		return;
	}

	async function followXrefs(): Promise<void> {
		const rows = ((await rz.cmdj<RzXrefRow[]>(`axtj @ ${addr}`).catch(() => null)) ?? []).filter((row) => typeof row.from === "number");
		if (rows.length === 0) {
			ctx.ui.notify(`omp-re: no xrefs to ${addr}`, "info");
			return;
		}
		await showPanel(ctx, {
			title: `omp-re: xrefs to ${name ?? addr}`,
			items: await labelXrefs(rz, rows),
			onChoose: async (item) => {
				await showCodeView(ctx, item.value, item.label, depth + 1);
				return "keep" as const;
			},
			hint: "enter open · esc back",
		});
	}

	await ctx.ui.custom<undefined>(
		(_tui, theme, keybindings, done) => {
			let decompileLines: string[] | null = null;
			let decompileLabel = "decompile";
			if (outcome?.kind === "disasm") {
				decompileLines = [theme.fg("warning", outcome.prefix?.trim() ?? ""), ...outcome.code.split("\n").map((l) => theme.fg("text", l))];
				decompileLabel = "decompile (disassembly only)";
			} else if (outcome) {
				decompileLines = [theme.fg("dim", `// decompiled with ${outcome.kind}`), ...highlightCode(outcome.code, "c", theme)];
			}
			return makeCodeView({
				title: name ?? addr,
				disasmLines,
				decompileLines,
				decompileLabel,
				theme,
				keybindings,
				onToggle: () => {
					if (!decompileLines) {
						ctx.ui.notify("omp-re: no decompiler output for this function", "info");
						return false;
					}
					return true;
				},
				onXrefs: () => {
					void followXrefs();
				},
				onAsk: () => {
					ctx.ui.setEditorText(
						`Analyze function ${name ?? addr} at ${addr}. Use the RE tools to gather evidence first; report only what the evidence supports.`,
					);
					done(undefined);
				},
				done,
			});
		},
		{ overlay: true },
	);
}

export interface EvidenceRecord {
	id: string;
	tool: string;
	ea?: string;
	summary: string;
	artifactId?: string;
}

/** Evidence on the current branch, oldest first. */
export function evidenceRecords(ctx: ExtensionContext): EvidenceRecord[] {
	return customEntries(branchEntries(ctx), "re.evidence")
		.map((entry) => entry.data as EvidenceRecord)
		.filter((data) => typeof data?.id === "string");
}

/** Prefix match: the picker only ever displays an 8-char slice of the UUID, so retyping what's shown could never satisfy an exact-equality lookup. Shared by `showEvidencePanel`, `/re cite`, and `/re` argument completion so there is exactly one lookup rule. */
export function findEvidence(ctx: ExtensionContext, id: string): EvidenceRecord | undefined {
	const all = evidenceRecords(ctx);
	return all.find((e) => e.id === id) ?? all.find((e) => e.id.startsWith(id));
}

function evidenceDetail(match: EvidenceRecord): string {
	const full = match.artifactId ? `\n\nfull output: artifact://${match.artifactId}` : "";
	return `[${match.tool}:${match.ea ?? "?"}]\n\n${match.summary}${full}`;
}

export async function showEvidencePanel(ctx: ExtensionContext, id?: string): Promise<void> {
	if (id) {
		const match = findEvidence(ctx, id);
		if (match) ctx.ui.notify(evidenceDetail(match), "info");
		else ctx.ui.notify(`omp-re: no evidence found with id ${id}`, "error");
		return;
	}

	const all = evidenceRecords(ctx);
	const items: SelectItem[] = all.map((e) => ({
		value: e.id,
		label: `[${e.id.slice(0, 8)}] ${e.tool} @ ${e.ea ?? "?"}`,
		description: e.summary?.split("\n")[0]?.slice(0, 80),
	}));
	await showPanel(ctx, {
		title: "omp-re: evidence",
		items,
		onChoose: (item) => {
			const match = all.find((e) => e.id === item.value);
			if (!match) return "keep" as const;
			// Close the panel and prefill a citation: a notify raised under an open overlay can render underneath it.
			citeEvidence(ctx, match);
			return "close" as const;
		},
		hint: "enter cite · type to filter · esc close",
	});
}

/** Pull one evidence record into the editor as a prefilled message, so a follow-up carries its exact recorded content. */
export function citeEvidence(ctx: ExtensionContext, rec: EvidenceRecord): void {
	ctx.ui.setEditorText(`Re: evidence ${rec.id.slice(0, 8)} (${rec.tool} @ ${rec.ea ?? "?"})\n\n${rec.summary}\n\n`);
}

interface RzString {
	vaddr?: number;
	string: string;
}

export async function showStringsPanel(ctx: ExtensionContext): Promise<void> {
	const rz = await uiSession(ctx);
	if (!rz) return;
	const strings = ((await rz.cmdj<RzString[]>("izj").catch(() => null)) ?? []).filter((s) => typeof s.vaddr === "number");
	const items: SelectItem[] = strings.map((s) => ({ value: eaFromOffset(s.vaddr!), label: s.string, description: eaFromOffset(s.vaddr!) }));
	await showPanel(ctx, {
		title: "omp-re: strings",
		items,
		onChoose: async (item) => {
			const rows = ((await rz.cmdj<RzXrefRow[]>(`axtj @ ${item.value}`).catch(() => null)) ?? []).filter((row) => typeof row.from === "number");
			if (rows.length === 0) {
				// Close first: a notify raised under an open overlay can render underneath it.
				ctx.ui.notify("omp-re: no xrefs to that string", "info");
				return "close" as const;
			}
			if (rows.length === 1) {
				const ea = eaFromOffset(rows[0]!.from!);
				await showCodeView(ctx, ea);
				return "keep" as const;
			}
			await showPanel(ctx, {
				title: `omp-re: xrefs to ${JSON.stringify(item.label.slice(0, 40))}`,
				items: await labelXrefs(rz, rows),
				onChoose: async (xref) => {
					await showCodeView(ctx, xref.value, xref.label);
					return "keep" as const;
				},
				hint: "enter open · esc back",
			});
			return "keep" as const;
		},
		hint: "enter open · type to filter · esc close",
	});
}

interface RzImport {
	name: string;
	plt?: number;
}

export async function showImportsPanel(ctx: ExtensionContext): Promise<void> {
	const rz = await uiSession(ctx);
	if (!rz) return;
	const imports = (await rz.cmdj<RzImport[]>("iij").catch(() => null)) ?? [];
	const items: SelectItem[] = imports.map((imp) => ({
		value: imp.plt ? eaFromOffset(imp.plt) : "",
		label: imp.name,
		description: imp.plt ? eaFromOffset(imp.plt) : "(no PLT)",
	}));
	await showPanel(ctx, {
		title: "omp-re: imports",
		items,
		onChoose: async (item) => {
			if (item.value === "") {
				ctx.ui.notify("omp-re: no PLT stub for that import", "info");
				return "close" as const;
			}
			const rows = ((await rz.cmdj<RzXrefRow[]>(`axtj @ ${item.value}`).catch(() => null)) ?? []).filter((row) => typeof row.from === "number");
			if (rows.length === 0) {
				await showCodeView(ctx, item.value, item.label);
				return "keep" as const;
			}
			await showPanel(ctx, {
				title: `omp-re: callers of ${item.label}`,
				items: await labelXrefs(rz, rows),
				onChoose: async (xref) => {
					await showCodeView(ctx, xref.value, xref.label);
					return "keep" as const;
				},
				hint: "enter open · esc back",
			});
			return "keep" as const;
		},
		hint: "enter open · type to filter · esc close",
	});
}

export function registerUI(pi: ExtensionAPI): void {
	// Only RE tools change what the band shows, and the refresh is fire-and-forget: its rizin
	// query can queue behind a long decompile, which must never hold up a tool result.
	pi.on("tool_result", (event, ctx) => {
		if (RE_ALL_TOOL_NAMES[event.toolName] === true) void refreshStatusBand(ctx);
	});

	pi.registerShortcut("alt+g", {
		description: "omp-re: function navigator",
		handler: async (ctx) => {
			await showFunctionsPanel(ctx);
		},
	});
	pi.registerShortcut("alt+s", {
		description: "omp-re: strings panel",
		handler: async (ctx) => {
			await showStringsPanel(ctx);
		},
	});
	pi.registerShortcut("alt+i", {
		description: "omp-re: imports panel",
		handler: async (ctx) => {
			await showImportsPanel(ctx);
		},
	});
}

/** `/re findings [id]`: the live findings on this branch. Enter pulls one into the editor (claim, provenance, evidence ids) to discuss or revise; with an id, show its detail. */
export async function showFindingsPanel(ctx: ExtensionContext, id?: string): Promise<void> {
	const all = liveFindings(ctx);
	const detail = (f: FindingRecord) => `finding ${f.id.slice(0, 8)}: ${f.claim}\n${findingNote(f)}\nevidence: ${f.evidenceIds.map((e) => e.slice(0, 8)).join(", ")}`;
	if (id) {
		const match = all.find((f) => f.id === id) ?? all.find((f) => f.id.startsWith(id));
		if (match) ctx.ui.notify(detail(match), "info");
		else ctx.ui.notify(`omp-re: no live finding with id ${id}`, "error");
		return;
	}
	if (all.length === 0) {
		ctx.ui.notify("omp-re: no findings on this branch yet — the model records them with record_finding", "info");
		return;
	}
	await showPanel(ctx, {
		title: "omp-re: findings",
		items: all.map((f) => ({ value: f.id, label: `[${f.id.slice(0, 8)}] ${f.claim}`, description: `${f.confidence}${f.inherited ? " · inherited" : ""}${f.addr ? ` · ${f.addr}` : ""}` })),
		onChoose: (item) => {
			const match = all.find((f) => f.id === item.value);
			if (!match) return "keep" as const;
			ctx.ui.setEditorText(`Re: ${detail(match)}\n\n`);
			return "close" as const;
		},
		hint: "enter discuss · type to filter · esc close",
	});
}
