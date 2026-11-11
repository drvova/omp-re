/**
 * omp-re for omp. This is the sole auto-loaded extension of the `re/`
 * directory (omp's directory-with-index.ts convention); its sibling files are
 * plain modules.
 *
 * The reverse engineering is done by the engine, a Common Lisp program this
 * extension runs beside omp (engine.ts), and the model reaches it from omp's
 * own `eval` tool: the re-triage skill's library, loaded into a kernel, asks
 * the listener of bridge.ts. So nothing is registered with omp here that a
 * model or an operator calls — no tool, no slash command, no flag. What is
 * here is omp's side of a session: its life forwarded to the engine, the
 * lines kept through a compaction, and what the engine sends drawn (ui.ts).
 *
 * The factory runs once per omp session — the main session and each task
 * subagent get their own ExtensionAPI — while the engine and the listener
 * are one for the whole process (host.ts).
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Text } from "@oh-my-pi/pi-tui";
import { drawStatusBand, openView, type ViewSource } from "./ui.ts";
import { ask, cellEnded, cellStarted, enter, forgetSession, leaveSession, sessionOf, tell } from "./host.ts";
import { CONSTANTS, KEYS, type ToEngine, type ToHost } from "./protocol.ts";

/** The operator's switch for the whole plugin, read once when omp loads it: with it set, nothing below runs. */
const DISABLED = `${CONSTANTS.environmentPrefix}DISABLED`;

/**
 * How a cell that used the library before loading it fails, in each kernel's own words, and the line that loads it.
 * omp has no way to load a script into a kernel for the model (docs/omp-eval.md), and a JavaScript kernel loses
 * what was loaded at every timeout and interrupt; the skill says so, and this says it again where it happens.
 */
const UNLOADED = {
	js: { said: /\bre is not defined\b|Can't find variable: re\b/, load: "%load skill://re-triage/recipes.js" },
	py: { said: /name 'omp_re' is not defined/, load: "%load skill://re-triage/recipes.py" },
} as const;

export default async function (pi: ExtensionAPI): Promise<void> {
	if (process.env[DISABLED] === "1") return;
	enter(pi);
	/** Session id this instance last saw, to tell a branch into a new session file apart from navigation within one. */
	let lastSessionId: string | undefined;

	const seen = (ctx: ExtensionContext) => {
		lastSessionId = ctx.sessionManager.getSessionId();
		return sessionOf(pi, ctx, drawStatusBand);
	};
	const viewSource: ViewSource = (ctx, request) => ask(pi, ctx, "view", { kind: request.kind, arg: request.arg });

	// The line the engine asks to have shown when a binary is opened (the protocol's `transcript`).
	const openedLine: ToHost["transcript"]["params"]["type"] = "re.binary";
	pi.registerMessageRenderer(openedLine, (message, _options, theme) => new Text(theme.fg("accent", typeof message.content === "string" ? message.content : ""), 0, 0));

	/** omp entered a session, or moved within one. */
	const arrive = (ctx: ExtensionContext, event: Omit<ToEngine["event"]["params"], "session">) => {
		seen(ctx);
		return ask(pi, ctx, "event", event).catch((error) => tell(ctx, error instanceof Error ? error.message : String(error), "error"));
	};
	pi.on("session_start", async (_event, ctx) => {
		await arrive(ctx, { kind: "start" });
	});
	// A switch (/new, /resume, fork, handoff) leaves this session for another: its rizin is freed first.
	pi.on("session_before_switch", async (_event, ctx) => {
		await leaveSession(pi, ctx, false);
	});
	pi.on("session_switch", async (_event, ctx) => {
		await arrive(ctx, { kind: "switch" });
	});
	// A branch writes a new session file with the same history up to the branch point: the engine carries its rizin over.
	pi.on("session_branch", async (_event, ctx) => {
		const previous = lastSessionId;
		await arrive(ctx, { kind: "branch", ...(previous ? { previous } : {}) });
		if (previous && previous !== ctx.sessionManager.getSessionId()) forgetSession(previous);
	});
	pi.on("session_tree", async (_event, ctx) => {
		await arrive(ctx, { kind: "tree" });
	});
	pi.on("session_shutdown", async (_event, ctx) => {
		await leaveSession(pi, ctx, true);
	});

	pi.on("session.compacting", async (_event, ctx) => {
		const { lines } = await ask(pi, ctx, "preserved", {});
		return lines.length > 0 ? { context: lines } : undefined;
	});

	// The model's calls all arrive inside `eval`, so that is the one tool watched: which call a request belongs to, and when it is over.
	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName === "eval") cellStarted(pi, ctx, event.toolCallId);
	});
	pi.on("tool_execution_end", async (event, ctx) => {
		if (event.toolName === "eval") cellEnded(ctx, event.toolCallId);
	});
	pi.on("tool_result", async (event, ctx) => {
		if (event.toolName !== "eval") return;
		cellEnded(ctx, event.toolCallId);
		const unloaded = UNLOADED[event.input.language === "py" ? "py" : "js"];
		const text = event.content.map((part) => (part.type === "text" ? part.text : "")).join("\n");
		if (!event.isError || !unloaded.said.test(text)) return;
		return { content: [...event.content, { type: "text", text: `omp-re: its library is not loaded in this kernel. Run a cell that holds only this line, then run yours again: ${unloaded.load}` }] };
	});

	for (const { key, view } of KEYS.views) {
		pi.registerShortcut(key, {
			description: `omp-re: ${view}`,
			handler: async (ctx) => {
				seen(ctx);
				await openView(ctx, viewSource, { kind: view });
			},
		});
	}
}
