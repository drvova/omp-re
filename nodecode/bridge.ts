#!/usr/bin/env bun
/**
 * The stdio bridge between the nodecode cell and the omp-re engine.
 *
 * One JSON object per line in, one per line out — the framing nodecode's own
 * `nodecode rpc` uses. The cell (nodecode/*.lisp) spawns this once and keeps
 * it: the engine's rizin process is a session resource, and a spawn per call
 * would re-analyze the binary every time.
 *
 * Requests carry an `id`; every request gets exactly one reply with that id.
 *
 *   {"id":1,"op":"hello"}
 *     -> {"id":1,"ok":true,"version":"0.9.1","tools":[{name,description,approval,parameters}],"commands":[...]}
 *   {"id":2,"op":"call","session":"s1","tool":"rizin_command","args":{"command":"aflj"}}
 *     -> {"id":2,"ok":true,"text":"...","isError":false}
 *   {"id":3,"op":"command","session":"s1","name":"re","args":"status"}
 *     -> {"id":3,"ok":true,"text":"...","isError":false}
 *   {"id":4,"op":"close","session":"s1"}        -> {"id":4,"ok":true}
 *   {"op":"cancel","id":2}                      (no reply of its own: the cancelled call answers)
 *
 * `ok:false` with `error` is a failure of the bridge itself (a malformed
 * request); a tool that ran and failed is `ok:true` with `isError:true`, its
 * text being what the model reads. Calls on one session run one at a time, in
 * order — the engine's own contract inside omp; sessions run side by side.
 * Stdin closing is the shutdown signal: requests already read are answered,
 * then every session's rizin is closed.
 */
import { createInterface } from "node:readline";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { captureConsole, HeadlessSession, type CallResult } from "./host.ts";

interface Request {
	id?: number | string;
	op?: string;
	session?: string;
	tool?: string;
	name?: string;
	args?: unknown;
}

const stateDir = process.env.OMPRE_HEADLESS_STATE_DIR || undefined;
/**
 * A session nobody has called for this long is closed, which ends its rizin
 * process: a long-lived host opens many sessions and never says when one is
 * over. Nothing is lost — the session's branch is on disk, and its next call
 * reopens the binary and replays the annotations. 0 turns the reaper off.
 */
const idleMs = Math.max(0, Number(process.env.OMPRE_HEADLESS_IDLE_MINUTES ?? 30) || 0) * 60_000;
/** Per session: how many requests are queued or running, and when the last one finished. */
const activity = new Map<string, { busy: number; idleSince: number }>();
const sessions = new Map<string, Promise<HeadlessSession>>();
/** The tail of each session's queue: a call waits for the one before it. */
const queues = new Map<string, Promise<unknown>>();
const running = new Map<number | string, AbortController>();
/** Every request still being answered, so a clean shutdown can let them finish. */
const pending = new Set<Promise<void>>();

function version(): string {
	try {
		return (JSON.parse(readFileSync(join(import.meta.dir, "..", "package.json"), "utf8")) as { version: string }).version;
	} catch {
		return "unknown";
	}
}

function reply(frame: Record<string, unknown>): void {
	process.stdout.write(`${JSON.stringify(frame)}\n`);
}

function session(id: string): Promise<HeadlessSession> {
	let opened = sessions.get(id);
	if (!opened) {
		opened = HeadlessSession.open(id, { stateDir });
		sessions.set(id, opened);
		// An open that failed must not be the answer forever: the next request tries again.
		opened.catch(() => sessions.delete(id));
	}
	return opened;
}

function enqueue<T>(sessionId: string, work: () => Promise<T>): Promise<T> {
	const previous = queues.get(sessionId) ?? Promise.resolve();
	const use = activity.get(sessionId) ?? { busy: 0, idleSince: Date.now() };
	activity.set(sessionId, use);
	use.busy++;
	const tracked = async () => {
		try {
			return await work();
		} finally {
			use.busy--;
			use.idleSince = Date.now();
		}
	};
	const next = previous.then(tracked, tracked);
	queues.set(
		sessionId,
		next.catch(() => undefined),
	);
	return next;
}

async function closeSession(sessionId: string): Promise<void> {
	const opened = sessions.get(sessionId);
	sessions.delete(sessionId);
	queues.delete(sessionId);
	activity.delete(sessionId);
	if (opened) await (await opened).close();
}

function reapIdle(): void {
	const now = Date.now();
	for (const [sessionId, use] of activity) {
		if (use.busy === 0 && now - use.idleSince >= idleMs) void closeSession(sessionId).catch(() => {});
	}
}

async function handle(request: Request): Promise<void> {
	const { id, op } = request;
	if (op === "cancel") {
		if (id !== undefined) running.get(id)?.abort();
		return;
	}
	if (id === undefined) {
		reply({ ok: false, error: "a request needs an id" });
		return;
	}
	try {
		switch (op) {
			case "hello": {
				// The catalog is the same for every session; a session of its own keeps it off any real branch.
				const probe = await session("__catalog__");
				reply({ id, ok: true, version: version(), tools: probe.tools(), commands: probe.commands() });
				return;
			}
			case "call":
			case "command": {
				const sessionId = typeof request.session === "string" && request.session.length > 0 ? request.session : "default";
				const controller = new AbortController();
				running.set(id, controller);
				let result: CallResult;
				try {
					result = await enqueue(sessionId, async () => {
						const live = await session(sessionId);
						if (controller.signal.aborted) return { text: "omp-re: cancelled before it ran", isError: true };
						if (op === "call") return await live.callTool(String(request.tool ?? ""), request.args, controller.signal);
						return await live.runCommand(String(request.name ?? "re"), typeof request.args === "string" ? request.args : "");
					});
				} finally {
					running.delete(id);
				}
				reply({ id, ok: true, text: result.text, isError: result.isError });
				return;
			}
			case "close": {
				await closeSession(String(request.session ?? ""));
				reply({ id, ok: true });
				return;
			}
			default:
				reply({ id, ok: false, error: `unknown op ${JSON.stringify(op)}` });
		}
	} catch (err) {
		reply({ id, ok: false, error: err instanceof Error ? err.message : String(err) });
	}
}

/**
 * Stdin closing lets the requests already read finish (a piped batch gets all
 * its answers); a signal does not wait — it aborts them, and each still
 * answers before the sessions close.
 */
async function shutdown(abort: boolean): Promise<void> {
	if (abort) for (const controller of running.values()) controller.abort();
	while (pending.size > 0) await Promise.allSettled([...pending]);
	const open = [...sessions.values()];
	sessions.clear();
	await Promise.allSettled(open.map(async (opened) => (await opened).close()));
	// The engine's headless paths may have set a failing exit code for one command; the bridge itself ended cleanly.
	process.exit(0);
}

captureConsole();
// unref: the reaper must never be what keeps the bridge alive after stdin closes.
if (idleMs > 0) setInterval(reapIdle, Math.min(idleMs, 60_000)).unref();
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on("line", (line) => {
	if (!line.trim()) return;
	let request: Request;
	try {
		request = JSON.parse(line) as Request;
	} catch {
		reply({ ok: false, error: "a request is one JSON object on one line" });
		return;
	}
	if (request === null || typeof request !== "object" || Array.isArray(request)) {
		reply({ ok: false, error: "a request is one JSON object on one line" });
		return;
	}
	const work = handle(request);
	pending.add(work);
	void work.finally(() => pending.delete(work));
});
lines.on("close", () => void shutdown(false));
process.on("SIGTERM", () => void shutdown(true));
