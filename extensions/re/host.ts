/**
 * omp's half of the engine's port: the one engine of this omp process, the
 * sessions it serves, and the answers to what it asks of omp
 * (docs/engine-protocol.md, "What the engine asks omp") — the session's
 * record, artifacts, the side model, telling the operator.
 */
import { readFile } from "node:fs/promises";
import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Engine, type HostHandler, type Json, type JsonObject } from "./engine.ts";

/** What omp draws between calls: the status band's facts and the evidence ids `/re cite` completes. Sent by the engine with every answer that may have changed them. */
export interface SessionState {
	facts: JsonObject | null;
	evidence: [id: string, description: string][];
}

interface Session {
	pi: ExtensionAPI;
	/** The latest context omp handed this session: what an engine request made outside any call is answered with. */
	ctx: ExtensionContext;
	state: SessionState;
	onState?: (ctx: ExtensionContext, state: SessionState) => void;
}

type Level = "info" | "warning" | "error";

interface Shared {
	sessions: Map<string, Session>;
	/** Tool calls under way, by the engine request that serves each: where its progress is shown. */
	updates: Map<number, (partial: AgentToolResult) => void>;
	tickers: Map<string, ReturnType<typeof setInterval>>;
	running?: Engine;
}

/**
 * What all of this omp process's sessions share. omp imports an extension
 * afresh for every session it loads it into, so a module-level variable
 * would be one per session; the engine is one per process, and so this is
 * kept on the process's global object.
 */
const shared: Shared = ((globalThis as Record<symbol, unknown>)[Symbol.for("omp-re.host")] ??= (() => {
	const made: Shared = { sessions: new Map(), updates: new Map(), tickers: new Map() };
	// omp ending any other way than by its sessions' shutdown: the child must not outlive it.
	process.on("exit", () => made.running?.kill());
	return made;
})()) as Shared;
const { sessions, updates, tickers } = shared;

/** Remember `ctx` as its session's latest and say which session a request is for. */
export function sessionOf(pi: ExtensionAPI, ctx: ExtensionContext, onState?: Session["onState"]): JsonObject {
	const id = ctx.sessionManager.getSessionId();
	const known = sessions.get(id);
	if (known) {
		known.ctx = ctx;
		known.pi = pi;
		if (onState) known.onState = onState;
	} else {
		sessions.set(id, { pi, ctx, state: { facts: null, evidence: [] }, onState });
	}
	return { id, cwd: ctx.cwd, hasUI: ctx.hasUI };
}

export function stateOf(sessionId: string): SessionState | undefined {
	return sessions.get(sessionId)?.state;
}

/** Take the state an engine answer carries, and redraw what shows it. */
export function applyState(sessionId: string, state: unknown): void {
	const session = sessions.get(sessionId);
	if (!session || state === null || typeof state !== "object") return;
	session.state = state as SessionState;
	session.onState?.(session.ctx, session.state);
}

/**
 * Tell the user something a `/re` line or a background open has to say. With
 * a UI it is a notification. Headless (`omp -p`) has no notification surface:
 * information goes to stdout, and anything else to stderr, an error with a
 * failing exit status, so a pipeline sees it.
 */
export function tell(ctx: ExtensionContext, text: string, level: Level = "info"): void {
	if (ctx.hasUI) {
		ctx.ui.notify(text, level);
		return;
	}
	if (level === "info") console.log(text);
	else console.error(text);
	if (level === "error") process.exitCode = 1;
}

/** Show a long analysis as under way, counting its seconds, until it is said to be over. */
function showProgress(key: string, text: string | null, show: (text: string | undefined) => void): void {
	const ticking = tickers.get(key);
	if (ticking) clearInterval(ticking);
	tickers.delete(key);
	if (text === null) {
		show(undefined);
		return;
	}
	const started = Date.now();
	show(text);
	const timer = setInterval(() => show(`${text} ${Math.round((Date.now() - started) / 1000)}s`), 1000);
	timer.unref?.();
	tickers.set(key, timer);
}

/** The side model's reply to `prompt`, or why there is none. Some transports refuse a turn with no tools; the reply to one with tools is as good, since a side turn runs none. */
export async function askSideModel(ctx: ExtensionContext, prompt: string, seconds: number): Promise<JsonObject> {
	const run = ctx.runEphemeralTurn;
	if (typeof run !== "function" || !ctx.model) return {};
	const signal = AbortSignal.timeout(seconds * 1000);
	const turn = (toolsOff: boolean) =>
		run.call(ctx, {
			promptText: prompt,
			...(toolsOff ? { tools: false as const } : {}),
			dedupeReply: false,
			replyMaxBytes: Number.POSITIVE_INFINITY,
			signal,
		});
	try {
		try {
			return { text: (await turn(true)).replyText };
		} catch (error) {
			if (!(error instanceof Error) || !error.message.includes("tools: false")) throw error;
			return { text: (await turn(false)).replyText };
		}
	} catch (error) {
		return { reason: `the audit side turn failed: ${error instanceof Error ? error.message : String(error)}`.split("\n", 1)[0]!.slice(0, 200) };
	}
}

function forSession(handle: (session: Session, params: JsonObject) => unknown | Promise<unknown>): HostHandler {
	return (params) => {
		const session = sessions.get(String(params.session));
		if (!session) throw new Error(`omp-re: omp has no session ${JSON.stringify(params.session)}`);
		return handle(session, params);
	};
}

/** The session's record as the engine reads it: the custom entries the engine wrote, on the current branch, root first. */
function record(ctx: ExtensionContext): JsonObject[] {
	const entries: JsonObject[] = [];
	for (const entry of ctx.sessionManager.getBranch()) {
		if (entry.type === "custom" && entry.customType.startsWith("re.")) entries.push({ id: entry.id, customType: entry.customType, data: entry.data as Json });
	}
	return entries;
}

const handlers: Record<string, HostHandler> = {
	entries: forSession(({ ctx }, { after, count }) => {
		const all = record(ctx);
		const held = typeof count === "number" ? count : 0;
		const continues = held <= all.length && (held === 0 || all[held - 1]!.id === after);
		return continues ? { append: all.slice(held) } : { all };
	}),
	append: forSession(({ pi, ctx }, { type, data }) => {
		pi.appendEntry(String(type), data);
		// appendEntry answers nothing; the entry it wrote is the branch's new leaf.
		return { id: ctx.sessionManager.getLeafId() };
	}),
	judge: forSession(({ ctx }, { prompt, seconds }) => askSideModel(ctx, String(prompt), typeof seconds === "number" ? seconds : 30)),
	saveArtifact: forSession(async ({ ctx }, { content, label }) => ({ id: await ctx.sessionManager.saveArtifact(String(content), String(label)) })),
	readArtifact: forSession(async ({ ctx }, { id }) => {
		const path = await ctx.sessionManager.getArtifactPath(String(id));
		return path ? { text: await readFile(path, "utf8") } : {};
	}),
	keepSession: forSession(async ({ pi, ctx }, { name }) => {
		// omp writes a session on its first model turn; a headless run that only ran a /re line would lose what it recorded.
		const manager = ctx.sessionManager as { ensureOnDisk?: () => Promise<void> };
		await manager.ensureOnDisk?.();
		// `omp -c` skips a session with no turn and no title. An interactive session is left for omp to title.
		if (!ctx.hasUI && !pi.getSessionName()) await pi.setSessionName(String(name));
		return {};
	}),
	notify: forSession(({ pi, ctx }, { text, level }) => {
		if (ctx.hasUI) ctx.ui.notify(String(text), level as Level);
		else if (level === "error") pi.logger.error(String(text));
		else pi.logger.warn(String(text));
	}),
	tell: forSession(({ ctx }, { text, level }) => tell(ctx, String(text), level as Level)),
	transcript: forSession(({ pi }, { type, text, details }) => {
		pi.sendMessage({ customType: String(type), content: String(text), display: true, details });
	}),
	state: ({ session, state }) => applyState(String(session), state),
	progress: forSession(({ ctx }, { request, text }) => {
		const update = typeof request === "number" ? updates.get(request) : undefined;
		const said = typeof text === "string" ? text : null;
		if (update) showProgress(`request ${request}`, said, (line) => line !== undefined && update({ content: [{ type: "text", text: line }], details: undefined }));
		else if (ctx.hasUI) showProgress(`session ${ctx.sessionManager.getSessionId()}`, said, (line) => ctx.ui.setStatus("re", line));
	}),
};

/** The engine, started on first need. A start that failed, or an engine that ended, is not kept: the next need starts another, and its sessions come back from their records. */
export function engine(): Engine {
	if (!shared.running) {
		const started = new Engine(handlers);
		shared.running = started;
		void started.exited.then(() => {
			if (shared.running === started) shared.running = undefined;
		});
	}
	return shared.running;
}

/** Ask the engine about `ctx`'s session, and take the state its answer carries. `onUpdate` is where a tool call's progress goes. */
export async function ask<T extends JsonObject = JsonObject>(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	method: string,
	params: JsonObject = {},
	options: { signal?: AbortSignal; onUpdate?: (partial: AgentToolResult) => void } = {},
): Promise<T> {
	const session = sessionOf(pi, ctx);
	let requestId: number | undefined;
	try {
		const answer = await engine().request<T>(method, { session, ...params }, options.signal, (id) => {
			requestId = id;
			if (options.onUpdate) updates.set(id, options.onUpdate);
		});
		applyState(session.id as string, method === "facts" ? answer : answer.state);
		return answer;
	} finally {
		if (requestId !== undefined) {
			updates.delete(requestId);
			showProgress(`request ${requestId}`, null, () => {});
		}
	}
}

/** omp left a session for another, or is done with it: the engine ends its processes. `over` when it is the session's end; the engine ends with the last of them, inside omp's shutdown budget. */
export async function leaveSession(pi: ExtensionAPI, ctx: ExtensionContext, over: boolean): Promise<void> {
	const id = ctx.sessionManager.getSessionId();
	const live = shared.running;
	if (live) await ask(pi, ctx, "event", { kind: over ? "shutdown" : "before-switch" }).catch(() => {});
	sessions.delete(id);
	if (over && live && sessions.size === 0) {
		shared.running = undefined;
		await live.stop();
	}
}
