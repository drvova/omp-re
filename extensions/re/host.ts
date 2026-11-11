/**
 * omp's half of the engine's port: the one engine of this omp process, the
 * sessions it serves, and the answers to what it asks of omp
 * (docs/engine-protocol.md, "What the engine asks omp") — the session's
 * record, artifacts, the side model, telling the operator.
 */
import { readFile } from "node:fs/promises";
import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { logger } from "@oh-my-pi/pi-utils";
import { Engine, type EngineRequest, type HostHandlers, type Json, type Start } from "./engine.ts";
import { launcher } from "./image.ts";
import { CONSTANTS, type Entry, type Level, PROTOCOL, type Session as SessionRef, type State, type ToEngine, type ToHost } from "./protocol.ts";

interface Session {
	pi: ExtensionAPI;
	/** The latest context omp handed this session: what an engine request made outside any call is answered with. */
	ctx: ExtensionContext;
	/** What the engine last said of the session (the protocol's `state`): what omp draws between calls, and the memory it hands back. */
	state: State;
	onState?: (ctx: ExtensionContext, state: State) => void;
}

/**
 * What this module touches of the omp process itself, outside omp's extension
 * API: a headless run's standard output and error and its exit status, the
 * process's log, and how the engine is started. They are here so a
 * test can put its own in their place instead of reaching for the process's.
 */
export interface Outside {
	/** A headless run's standard output: what a pipeline reads. */
	print(text: string): void;
	printError(text: string): void;
	/** Mark this omp process as having failed, for whoever reads its exit status. */
	failExit(): void;
	/** A line for omp's log file: what the engine wrote to its standard error, as it arrives. */
	log(line: string): void;
	/** How an engine is started: for each one, the ways of image.ts from the first. */
	engineCommand(): Start;
}

interface Shared {
	sessions: Map<string, Session>;
	/** The extension instances omp has loaded and not shut down: the engine ends with the last of them. */
	instances: Set<ExtensionAPI>;
	/** Tool calls under way, by the engine request that serves each: where its progress is shown. */
	updates: Map<number, (partial: AgentToolResult) => void>;
	tickers: Map<string, ReturnType<typeof setInterval>>;
	outside: Outside;
	running?: Engine;
}

/**
 * What all of this omp process's sessions share. omp imports an extension
 * afresh for every session it loads it into, so a module-level variable
 * would be one per session; the engine is one per process, and so this is
 * kept on the process's global object. The key carries the protocol
 * version: two copies of the plugin that speak different protocols, loaded
 * into one omp, each get their own engine instead of one talking to the
 * other's.
 */
const shared: Shared = ((globalThis as Record<symbol, unknown>)[Symbol.for(`omp-re.host/${PROTOCOL}`)] ??= {
	sessions: new Map(),
	instances: new Set(),
	updates: new Map(),
	tickers: new Map(),
	outside: {
		print: (text) => console.log(text),
		printError: (text) => console.error(text),
		failExit: () => {
			process.exitCode = 1;
		},
		log: (line) => logger.warn(`omp-re engine: ${line}`),
		engineCommand: () => launcher((line) => shared.outside.log(line)),
	},
} satisfies Shared) as Shared;
const { sessions, instances, updates, tickers } = shared;
export const outside = shared.outside;

/** Remember `ctx` as its session's latest and say which session a request is for. */
export function sessionOf(pi: ExtensionAPI, ctx: ExtensionContext, onState?: Session["onState"]): SessionRef {
	const id = ctx.sessionManager.getSessionId();
	let known = sessions.get(id);
	if (known) {
		known.ctx = ctx;
		known.pi = pi;
		if (onState) known.onState = onState;
	} else {
		known = { pi, ctx, state: { band: null, evidence: [], memory: {} }, onState };
		sessions.set(id, known);
	}
	return { id, cwd: ctx.cwd, hasUI: ctx.hasUI, memory: known.state.memory };
}

export function stateOf(sessionId: string): State | undefined {
	return sessions.get(sessionId)?.state;
}

/** Take the state the engine sent, and redraw what shows it. */
function applyState(sessionId: string, state: State): void {
	const session = sessions.get(sessionId);
	if (!session) return;
	session.state = state;
	session.onState?.(session.ctx, state);
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
	if (level === "info") outside.print(text);
	else outside.printError(text);
	if (level === "error") outside.failExit();
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

/**
 * Whether `error` is omp refusing a side turn with no tools. Some transports need the tool definitions sent, and omp
 * 18 says so only in the error's text ("… does not support tools: false …", agent-session.ts): there is no code or
 * class to test. If omp rewords it, the retry below stops happening and the audit says the side turn failed.
 */
function refusesToolFreeTurn(error: unknown): boolean {
	return error instanceof Error && error.message.includes("tools: false");
}

/** The side model's reply to `prompt`, or omp's reason there is none. The reply to a turn with tools is as good as one without, since a side turn runs none. */
export async function askSideModel(ctx: ExtensionContext, prompt: string, seconds: number): Promise<ToHost["judge"]["result"]> {
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
			if (!refusesToolFreeTurn(error)) throw error;
			return { text: (await turn(false)).replyText };
		}
	} catch (error) {
		return { reason: error instanceof Error ? error.message : String(error) };
	}
}

/**
 * Write the session's file now. omp writes one on a session's first model turn, so a headless run that only ran a
 * `/re` line would lose what it recorded. The session manager has `ensureOnDisk` for this, but omp 18's extension
 * API shows extensions a read-only view of the manager that leaves it out: there is no API to call. A manager
 * without the method is left as it is.
 */
async function writeSessionNow(ctx: ExtensionContext): Promise<void> {
	await (ctx.sessionManager as { ensureOnDisk?: () => Promise<void> }).ensureOnDisk?.();
}

function forSession<P extends { session: string }, R>(handle: (session: Session, params: P) => R): (params: P) => R {
	return (params) => {
		const session = sessions.get(params.session);
		if (!session) throw new Error(`omp-re: omp has no session ${JSON.stringify(params.session)}`);
		return handle(session, params);
	};
}

/** The session's record as the engine reads it: the custom entries the engine wrote, on the current branch, root first. */
function record(ctx: ExtensionContext): Entry[] {
	const entries: Entry[] = [];
	for (const entry of ctx.sessionManager.getBranch()) {
		if (entry.type === "custom" && entry.customType.startsWith(CONSTANTS.entryPrefix)) entries.push({ id: entry.id, customType: entry.customType, data: entry.data as Json });
	}
	return entries;
}

const handlers: HostHandlers = {
	entries: forSession(({ ctx }, { after, count }) => {
		const all = record(ctx);
		const continues = count <= all.length && (count === 0 || all[count - 1]!.id === after);
		return continues ? { append: all.slice(count) } : { all };
	}),
	append: forSession(({ pi, ctx }, { type, data }) => {
		pi.appendEntry(type, data);
		// appendEntry answers nothing; the entry it wrote is the branch's new leaf.
		const id = ctx.sessionManager.getLeafId();
		if (id === null) throw new Error("omp-re: omp did not write the entry");
		return { id };
	}),
	judge: forSession(({ ctx }, { prompt, seconds }) => askSideModel(ctx, prompt, seconds)),
	saveArtifact: forSession(async ({ ctx }, { content, label }) => {
		const id = await ctx.sessionManager.saveArtifact(content, label);
		return id === undefined ? {} : { id };
	}),
	readArtifact: forSession(async ({ ctx }, { id }) => {
		const path = await ctx.sessionManager.getArtifactPath(id);
		return path ? { text: await readFile(path, "utf8") } : {};
	}),
	keepSession: forSession(async ({ pi, ctx }, { name }) => {
		await writeSessionNow(ctx);
		// `omp -c` skips a session with no turn and no title. An interactive session is left for omp to title.
		if (!ctx.hasUI && !pi.getSessionName()) await pi.setSessionName(name);
		return {};
	}),
	notify: forSession(({ pi, ctx }, { text, level }) => {
		if (ctx.hasUI) ctx.ui.notify(text, level);
		else if (level === "error") pi.logger.error(text);
		else pi.logger.warn(text);
	}),
	tell: forSession(({ ctx }, { text, level }) => tell(ctx, text, level)),
	transcript: forSession(({ pi }, { type, text, details }) => {
		pi.sendMessage({ customType: type, content: text, display: true, details });
	}),
	state: ({ session, state }) => applyState(session, state),
	progress: forSession(({ ctx }, { request, text }) => {
		const update = request === null ? undefined : updates.get(request);
		if (update) showProgress(`request ${request}`, text, (line) => line !== undefined && update({ content: [{ type: "text", text: line }], details: undefined }));
		else if (ctx.hasUI) showProgress(`session ${ctx.sessionManager.getSessionId()}`, text, (line) => ctx.ui.setStatus("re", line));
	}),
};

/** The engine, started on first need. A start that failed, or an engine that ended, is not kept: the next need starts another, and its sessions come back from their records and the memory omp holds of them. */
export function engine(): Engine {
	if (!shared.running) {
		const started = new Engine({ command: outside.engineCommand(), handlers, log: (line) => outside.log(line) });
		shared.running = started;
		void started.exited.then(() => {
			if (shared.running === started) shared.running = undefined;
		});
	}
	return shared.running;
}

/** omp loaded the extension into a session: the engine is kept until `leaveSession` has ended every one of them. */
export function enter(pi: ExtensionAPI): void {
	instances.add(pi);
}

/** The engine's methods that are about a session. */
type SessionMethod = { [M in EngineRequest]: ToEngine[M]["params"] extends { session: SessionRef } ? M : never }[EngineRequest];

/** Ask the engine about `ctx`'s session, and take the state its answer carries. `onUpdate` is where a tool call's progress goes. */
export async function ask<M extends SessionMethod>(
	pi: ExtensionAPI,
	ctx: ExtensionContext,
	method: M,
	params: Omit<ToEngine[M]["params"], "session">,
	options: { signal?: AbortSignal; onUpdate?: (partial: AgentToolResult) => void } = {},
): Promise<ToEngine[M]["result"]> {
	const session = sessionOf(pi, ctx);
	let requestId: number | undefined;
	try {
		const answer: ToEngine[SessionMethod]["result"] = await engine().request<SessionMethod>(method, { session, ...params } as ToEngine[M]["params"], options.signal, (id) => {
			requestId = id;
			if (options.onUpdate) updates.set(id, options.onUpdate);
		});
		if ("state" in answer && answer.state) applyState(session.id, answer.state);
		return answer as ToEngine[M]["result"];
	} finally {
		if (requestId !== undefined) {
			updates.delete(requestId);
			showProgress(`request ${requestId}`, null, () => {});
		}
	}
}

/**
 * omp left a session for another, or is done with it: the engine ends its processes. `over` when omp is done with
 * the extension instance too; the engine ends with the last of them, inside omp's shutdown budget. A failure to say
 * so to an engine that is going anyway is logged, not raised: nothing can be done about it here.
 */
export async function leaveSession(pi: ExtensionAPI, ctx: ExtensionContext, over: boolean): Promise<void> {
	const id = ctx.sessionManager.getSessionId();
	const live = shared.running;
	if (live) await ask(pi, ctx, "event", { kind: over ? "shutdown" : "before-switch" }).catch((error) => outside.log(`leaving session ${id}: ${error instanceof Error ? error.message : String(error)}`));
	sessions.delete(id);
	if (!over) return;
	instances.delete(pi);
	if (live && instances.size === 0 && shared.running === live) {
		shared.running = undefined;
		await live.stop();
	}
}
