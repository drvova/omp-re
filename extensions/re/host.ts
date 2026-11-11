/**
 * omp's half of the engine's port: the one engine of this omp process, the
 * sessions it serves, and the answers to what it asks of omp
 * (docs/engine-protocol.md, "What the engine asks omp") — the session's
 * record, artifacts, the side model, telling the operator. And the way in
 * for the model: what a cell of omp's `eval` asks through the listener of
 * bridge.ts is answered here, for the session that cell belongs to.
 */
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { logger } from "@oh-my-pi/pi-utils";
import { type Bridge, type BridgeMethod, type Kernel, Refusal, startBridge } from "./bridge.ts";
import { Engine, type EngineRequest, type HostHandlers, type Json, type JsonObject, type Start } from "./engine.ts";
import { launcher } from "./image.ts";
import { CONSTANTS, type Entry, type Level, PROTOCOL, type Session as SessionRef, type State, type ToEngine, type ToHost } from "./protocol.ts";

interface Session {
	pi: ExtensionAPI;
	/** The latest context omp handed this session: what an engine request made outside any call is answered with. */
	ctx: ExtensionContext;
	/** What the engine last said of the session (the protocol's `state`): what omp draws between calls. */
	state: State;
	onState?: (ctx: ExtensionContext, state: State) => void;
	/** The `eval` call omp is running for the session, and how many requests its cell has made: what the audit log names each by. */
	cell?: { toolCallId: string; requests: number };
	/** What hangs up on the requests of the session's kernels that are still open. */
	open: Set<AbortController>;
}

/**
 * What this module touches of the omp process itself, outside omp's extension
 * API: a headless run's standard output and error and its exit status, the
 * process's log, how the engine is started, and the listener omp's eval
 * reaches it through. They are here so a test can put its own in their place
 * instead of reaching for the process's.
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
	/** Start the listener of bridge.ts. */
	listen: typeof startBridge;
}

interface Shared {
	sessions: Map<string, Session>;
	/** The extension instances omp has loaded and not shut down: the engine and the listener end with the last of them. */
	instances: Set<ExtensionAPI>;
	tickers: Map<string, ReturnType<typeof setInterval>>;
	outside: Outside;
	running?: Engine;
	listening?: Bridge;
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
	tickers: new Map(),
	outside: {
		print: (text) => console.log(text),
		printError: (text) => console.error(text),
		failExit: () => {
			process.exitCode = 1;
		},
		log: (line) => logger.warn(`omp-re engine: ${line}`),
		engineCommand: () => launcher((line) => shared.outside.log(line)),
		listen: startBridge,
	},
} satisfies Shared) as Shared;
const { sessions, instances, tickers } = shared;
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
		known = { pi, ctx, state: { band: null }, onState, open: new Set() };
		sessions.set(id, known);
	}
	return { id, cwd: ctx.cwd };
}

/** Take the state the engine sent, and redraw what shows it. */
function applyState(sessionId: string, state: State): void {
	const session = sessions.get(sessionId);
	if (!session) return;
	session.state = state;
	session.onState?.(session.ctx, state);
}

/**
 * Tell the user something that is said outside any call: a session's binary
 * that could not be analyzed again when the session came back. With a UI it
 * is a notification. Headless (`omp -p`) has no notification surface:
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
	// A cell's card is omp's, and shows nothing of a request under way inside it: the status line does.
	progress: forSession(({ ctx }, { text }) => {
		if (ctx.hasUI) showProgress(ctx.sessionManager.getSessionId(), text, (line) => ctx.ui.setStatus("re", line));
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

/** omp loaded the extension into a session: the engine and the listener are kept until `leaveSession` has ended every one of them. */
export function enter(pi: ExtensionAPI): void {
	instances.add(pi);
	shared.listening ??= outside.listen(answerKernel);
}

// --- what a cell of omp's eval asks ----------------------------------------------------------------

/** Two paths that name one file, however each was spelled. Windows compares without regard to case. */
function samePath(a: string, b: string): boolean {
	const real = (path: string) => {
		let whole = resolve(path);
		try {
			whole = realpathSync(whole);
		} catch {
			// A path that is not there is compared as written.
		}
		return process.platform === "win32" ? whole.toLowerCase() : whole;
	};
	return real(a) === real(b);
}

/**
 * The session a kernel serves. omp keys a kernel by the session's file and directory, or by the directory alone for
 * a session with no file (omp's eval/session-id.ts), and that key is all a kernel knows of its session; so the
 * session is found by the same two. Sessions with no file that work in one directory share one kernel, and nothing
 * in a request says which of them a cell belongs to: that is refused, not guessed.
 */
function sessionOfKernel(kernel: Kernel): Session {
	const live = new Map<string, Session>();
	for (const session of sessions.values()) {
		try {
			live.set(session.ctx.sessionManager.getSessionId(), session);
		} catch {
			// A context omp has retired names no session any more.
		}
	}
	const served = [...live.values()].filter(({ ctx }) => {
		const file = ctx.sessionManager.getSessionFile();
		return kernel.sessionFile ? file !== undefined && samePath(file, kernel.sessionFile) : file === undefined && samePath(ctx.sessionManager.getCwd(), kernel.cwd);
	});
	const where = kernel.sessionFile ? `with the session file ${kernel.sessionFile}` : `without a session file in ${kernel.cwd}`;
	if (served.length === 0) throw new Refusal(409, `omp-re: omp has no session ${where} that this plugin is loaded in`);
	if (served.length > 1) {
		throw new Refusal(409, `omp-re: ${served.length} sessions ${where} share this eval kernel, and a cell cannot say which of them it runs for. Give each a directory of its own, or let omp keep a session file.`);
	}
	return served[0]!;
}

/** Answer one request a kernel made through the listener. Hanging up cancels the engine's work on it. */
async function answerKernel(method: BridgeMethod, kernel: Kernel, body: JsonObject, hungUp: AbortSignal): Promise<Json> {
	const session = sessionOfKernel(kernel);
	if (method === "whoami") return { bridge: CONSTANTS.bridgeVersion };
	const over = new AbortController();
	const signal = AbortSignal.any([hungUp, over.signal]);
	session.open.add(over);
	try {
		if (method === "command") {
			if (typeof body.line !== "string") throw new Refusal(400, "omp-re: a line is a string");
			const { text, failed } = await ask(session.pi, session.ctx, "command", { line: body.line }, signal);
			return { text, failed };
		}
		const args = body.arguments ?? {};
		if (typeof body.name !== "string" || args === null || typeof args !== "object" || Array.isArray(args)) throw new Refusal(400, "omp-re: a call names a tool with a string and gives its arguments as one object");
		const callId = session.cell && `${session.cell.toolCallId}#${++session.cell.requests}`;
		const { text, failed, refused, raw, evidence } = await ask(session.pi, session.ctx, "call", { name: body.name, arguments: args, ...(callId ? { callId } : {}) }, signal);
		return { text, failed, ...(refused ? { refused } : {}), ...(raw === undefined ? {} : { raw }), ...(evidence === undefined ? {} : { evidence }) };
	} finally {
		session.open.delete(over);
	}
}

/** omp started running an `eval` call for `ctx`'s session: the requests its cell makes are counted under it. */
export function cellStarted(pi: ExtensionAPI, ctx: ExtensionContext, toolCallId: string): void {
	sessionOf(pi, ctx);
	sessions.get(ctx.sessionManager.getSessionId())!.cell = { toolCallId, requests: 0 };
}

/**
 * The `eval` call is over. A request its cell left open has nobody to answer: the kernel's hanging up says so for a
 * cell that timed out or was interrupted, and this says it for one that ended without waiting for what it asked.
 */
export function cellEnded(ctx: ExtensionContext, toolCallId: string): void {
	const session = sessions.get(ctx.sessionManager.getSessionId());
	if (session?.cell?.toolCallId !== toolCallId) return;
	session.cell = undefined;
	for (const request of session.open) request.abort();
}

/** The engine's methods that are about a session. */
type SessionMethod = { [M in EngineRequest]: ToEngine[M]["params"] extends { session: SessionRef } ? M : never }[EngineRequest];

/** Ask the engine about `ctx`'s session, and take the state its answer carries. Aborting `signal` tells the engine the asker gave up. */
export async function ask<M extends SessionMethod>(pi: ExtensionAPI, ctx: ExtensionContext, method: M, params: Omit<ToEngine[M]["params"], "session">, signal?: AbortSignal): Promise<ToEngine[M]["result"]> {
	const session = sessionOf(pi, ctx);
	const answer: ToEngine[SessionMethod]["result"] = await engine().request<SessionMethod>(method, { session, ...params } as ToEngine[M]["params"], signal);
	if ("state" in answer && answer.state) applyState(session.id, answer.state);
	return answer as ToEngine[M]["result"];
}

/** A session went on under another id (a branch into a new session file): what was held under the old one is dropped. */
export function forgetSession(id: string): void {
	sessions.delete(id);
}

/**
 * omp left a session for another, or is done with it: the engine ends its processes. `over` when omp is done with
 * the extension instance too; the engine and the listener end with the last of them, inside omp's shutdown budget. A failure to say
 * so to an engine that is going anyway is logged, not raised: nothing can be done about it here.
 */
export async function leaveSession(pi: ExtensionAPI, ctx: ExtensionContext, over: boolean): Promise<void> {
	const id = ctx.sessionManager.getSessionId();
	const live = shared.running;
	if (live) await ask(pi, ctx, "event", { kind: over ? "shutdown" : "before-switch" }).catch((error) => outside.log(`leaving session ${id}: ${error instanceof Error ? error.message : String(error)}`));
	for (const request of sessions.get(id)?.open ?? []) request.abort();
	sessions.delete(id);
	if (!over) return;
	instances.delete(pi);
	if (instances.size > 0) return;
	shared.listening?.stop();
	shared.listening = undefined;
	if (live && shared.running === live) {
		shared.running = undefined;
		await live.stop();
	}
}
