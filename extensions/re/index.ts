/**
 * omp-re for omp. This is the sole auto-loaded extension of the `re/`
 * directory (omp's directory-with-index.ts convention); its sibling files are
 * plain modules.
 *
 * The reverse engineering is done by the engine, a Common Lisp program this
 * extension runs beside omp (engine.ts). What is here is omp's side only: it
 * asks the engine what tools and `/re` subcommands it has and registers them
 * with omp under the engine's names, forwards calls and the session's life,
 * and draws what the engine sends (draw.ts, render.ts).
 *
 * The factory runs once per omp session — the main session and each task
 * subagent get their own ExtensionAPI — while the engine is one for the
 * whole process (host.ts).
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Text, type AutocompleteItem } from "@oh-my-pi/pi-tui";
import { drawStatusBand, openView, type ViewSource } from "./draw.ts";
import type { JsonObject } from "./engine.ts";
import { ask, engine, leaveSession, sessionOf, stateOf, tell } from "./host.ts";
import { RE_LOAD_MODE, reRenderers, type RenderSpec } from "./render.ts";

type Tier = "read" | "write" | "exec";

/** One case of an approval prompt's sentence, as the engine describes it (docs/engine-protocol.md, `approvalReason`). */
interface ReasonCase {
	when?: { arg: string; equals?: unknown; type?: string }[];
	parts: (string | { pieces: { arg: string; prefix?: string; missing?: string }[]; quote?: boolean; clip?: number })[];
}

interface DescribedTool {
	name: string;
	label?: string;
	description: string;
	parameters: Record<string, unknown>;
	approval: Tier;
	approvalReason?: ReasonCase[];
	render?: RenderSpec;
}

interface DescribedCommand {
	name: string;
	usage?: string;
	description: string;
	view?: boolean;
}

interface CallAnswer extends JsonObject {
	text: string;
	failed: boolean;
	details?: JsonObject;
}

interface CommandAnswer extends JsonObject {
	text: string;
	failed: boolean;
	level: "info" | "warning" | "error";
	draft?: { text: string; notice: string };
	userMessage?: string;
}

function argumentAt(args: unknown, path: string): unknown {
	let value = args;
	for (const key of path.split(".")) {
		if (value === null || typeof value !== "object") return undefined;
		value = (value as Record<string, unknown>)[key];
	}
	return value;
}

/** The sentence an approval prompt shows for one call, filled from its arguments. omp asks for it synchronously, so the engine sent it as data. */
function approvalSentence(cases: ReasonCase[], args: unknown): string | undefined {
	const holds = (condition: NonNullable<ReasonCase["when"]>[number]) => {
		const value = argumentAt(args, condition.arg);
		return condition.type !== undefined ? typeof value === condition.type : value === condition.equals;
	};
	const chosen = cases.find((one) => (one.when ?? []).every(holds));
	return chosen?.parts
		.map((part) => {
			if (typeof part === "string") return part;
			let filled = "";
			for (const piece of part.pieces) {
				const value = argumentAt(args, piece.arg);
				const said = typeof value === "string" || typeof value === "number" ? String(value) : Array.isArray(value) ? value.filter((item) => typeof item === "string").join(" ") : (piece.missing ?? "");
				if (said !== "") filled += (piece.prefix ?? "") + said;
			}
			if (part.clip !== undefined && filled.length > part.clip) filled = `${filled.slice(0, part.clip - 3)}...`;
			return part.quote ? JSON.stringify(filled) : filled;
		})
		.join("");
}

export default async function (pi: ExtensionAPI): Promise<void> {
	// The engine is asked here, once per session, because omp takes tool registrations only while the factory runs,
	// and which tools there are depends on the environment the session starts in.
	const { tools, commands } = await engine().request<{ tools: DescribedTool[]; commands: DescribedCommand[] }>("describe");
	const toolNames = new Set(tools.map((tool) => tool.name));
	/** Session id this instance last saw, to tell a branch into a new session file apart from navigation within one. */
	let lastSessionId: string | undefined;
	/** Latest context, for argument completion (which receives no ctx of its own). */
	let latestCtx: ExtensionContext | undefined;

	const seen = (ctx: ExtensionContext) => {
		latestCtx = ctx;
		lastSessionId = ctx.sessionManager.getSessionId();
		return sessionOf(pi, ctx, drawStatusBand);
	};
	const viewSource: ViewSource = (ctx, request) => ask(pi, ctx, "view", { kind: request.kind, arg: request.arg }) as never;

	for (const tool of tools) {
		const reasons = tool.approvalReason;
		pi.registerTool({
			name: tool.name,
			label: tool.label ?? tool.name,
			description: tool.description,
			approval: reasons ? (args: unknown) => ({ tier: tool.approval, reason: approvalSentence(reasons, args) }) : tool.approval,
			loadMode: RE_LOAD_MODE,
			parameters: tool.parameters,
			...(tool.render ? reRenderers(tool.render) : {}),
			execute: async (toolCallId, params, signal, onUpdate, ctx) => {
				seen(ctx);
				const answer = await ask<CallAnswer>(pi, ctx, "call", { name: tool.name, arguments: params as JsonObject, callId: toolCallId }, { signal, onUpdate });
				// A refusal has no details and is thrown, so eval sees a rejection it can catch; a tool's own failed result is returned as one.
				if (answer.failed && !answer.details) throw new Error(answer.text);
				return { content: [{ type: "text", text: answer.text }], details: answer.details, ...(answer.failed ? { isError: true } : {}) };
			},
		});
	}

	pi.registerMessageRenderer<{ path?: string }>("re.binary", (message, _options, theme) => {
		const path = message.details?.path;
		return new Text(theme.fg("accent", `[re: opened ${typeof path === "string" ? path : "?"}]`), 0, 0);
	});

	pi.registerFlag("binary", {
		description: "Path to a binary to open with rizin at startup",
		type: "string",
	});

	const event = (ctx: ExtensionContext, kind: string, more: JsonObject = {}) => {
		const previous = lastSessionId;
		seen(ctx);
		return ask(pi, ctx, "event", { kind, ...(kind === "branch" && previous ? { previous } : {}), ...more }).catch((error) =>
			tell(ctx, error instanceof Error ? error.message : String(error), "error"),
		);
	};
	pi.on("session_start", async (_event, ctx) => {
		const flag = pi.getFlag("binary");
		await event(ctx, "start", typeof flag === "string" && flag.length > 0 ? { binary: flag } : {});
	});
	// A switch (/new, /resume, fork, handoff) leaves this session for another: its rizin is freed first.
	pi.on("session_before_switch", async (_event, ctx) => {
		await leaveSession(pi, ctx, false);
	});
	pi.on("session_switch", async (_event, ctx) => {
		await event(ctx, "switch");
	});
	// A branch writes a new session file with the same history up to the branch point: the engine carries its rizin over.
	pi.on("session_branch", async (_event, ctx) => {
		await event(ctx, "branch");
	});
	pi.on("session_tree", async (_event, ctx) => {
		await event(ctx, "tree");
	});
	pi.on("session_shutdown", async (_event, ctx) => {
		await leaveSession(pi, ctx, true);
	});

	// A call omp's approval gate denied never reaches the engine; what the gate decided is forwarded so the audit log has it.
	pi.on("tool_approval_resolved", async (decided, ctx) => {
		if (!toolNames.has(decided.toolName)) return;
		await ask(pi, ctx, "approval", { callId: decided.toolCallId, tool: decided.toolName, approved: decided.approved, ...(decided.reason ? { reason: decided.reason } : {}) }).catch(() => {});
	});

	pi.on("session.compacting", async (_event, ctx) => {
		const { lines } = await ask<{ lines: string[] }>(pi, ctx, "preserved");
		return lines.length > 0 ? { context: lines } : undefined;
	});

	for (const [key, kind] of [
		["alt+g", "functions"],
		["alt+s", "strings"],
		["alt+i", "imports"],
	] as const) {
		pi.registerShortcut(key, {
			description: `omp-re: ${kind}`,
			handler: async (ctx) => {
				seen(ctx);
				await openView(ctx, viewSource, { kind });
			},
		});
	}

	function completeArguments(prefix: string): AutocompleteItem[] | null {
		const space = prefix.indexOf(" ");
		if (space === -1) {
			const lower = prefix.toLowerCase();
			const matches = commands
				.filter((command) => command.name.startsWith(lower))
				.map((command) => ({ value: `${command.name} `, label: command.name, description: command.description, hint: command.usage }));
			return matches.length > 0 ? matches : null;
		}
		const sub = prefix.slice(0, space).toLowerCase();
		if ((sub !== "cite" && sub !== "evidence") || !latestCtx) return null;
		const idPrefix = prefix.slice(space + 1).trim();
		const matches = (stateOf(latestCtx.sessionManager.getSessionId())?.evidence ?? [])
			.filter(([id]) => id.startsWith(idPrefix))
			.slice(0, 50)
			.map(([id, description]) => ({ value: `${sub} ${id.slice(0, 8)} `, label: id.slice(0, 8), description }));
		return matches.length > 0 ? matches : null;
	}

	pi.registerCommand("re", {
		description: `reverse engineering with rizin: ${commands.map((command) => command.name).join(" | ")}`,
		getArgumentCompletions: completeArguments,
		handler: async (args, ctx) => {
			seen(ctx);
			try {
				const words = args.trim().split(/\s+/).filter(Boolean);
				// A list is an overlay where there is a screen for one, and the same list as text where there is not.
				if (ctx.hasUI && words.length === 1 && commands.some((command) => command.view && command.name === words[0])) {
					await openView(ctx, viewSource, { kind: words[0]! });
					return;
				}
				const answer = await ask<CommandAnswer>(pi, ctx, "command", { line: args });
				if (answer.userMessage) pi.sendUserMessage(answer.userMessage);
				if (answer.draft && ctx.hasUI) {
					ctx.ui.setEditorText(answer.draft.text);
					tell(ctx, answer.draft.notice, answer.level);
				} else {
					tell(ctx, answer.text, answer.level);
				}
			} catch (error) {
				tell(ctx, error instanceof Error ? error.message : String(error), "error");
			}
		},
	});
}
