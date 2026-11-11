/**
 * The way from omp's `eval` to the engine.
 *
 * omp gives an extension nothing to put into an eval kernel: no global, no
 * prelude, no module (docs/omp-eval.md). A kernel is a separate process, a
 * child of omp's, that may open a socket like any other. So this module
 * listens on the loopback interface, and the library the re-triage skill
 * loads into a kernel (skills/re-triage/recipes.js, recipes.py) is its
 * client: every `re.cmd(…)` a cell runs is one request here, passed on to
 * the engine for the session that cell belongs to (host.ts).
 *
 * One listener serves the whole omp process, on a port the system picks. A
 * request must carry the listener's token, 32 random bytes that exist only
 * in this process and in the file a kernel finds the listener by: a JSON
 * file named for omp's process id, readable by its owner alone, in a
 * directory only the owner can enter. A kernel looks for the file of its
 * parent process. Whoever can read that file can drive the engine — which
 * is any process of the same user, the user's own shell among them, and
 * nobody else (SECURITY.md).
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONSTANTS, type Json, type JsonObject } from "./protocol.ts";

/** What a kernel says of itself with every request: which of omp's kernels it is, and the session it serves as omp told it. */
export interface Kernel {
	language: "js" | "py";
	/** The session's file, where it has one. */
	sessionFile?: string;
	cwd: string;
}

/** What a kernel may ask. */
export const BRIDGE_METHODS = ["whoami", "call", "command"] as const;
export type BridgeMethod = (typeof BRIDGE_METHODS)[number];

/**
 * A request that is not served, with the HTTP status that says which kind of refusal it is: 400 for one that is not
 * a request, 409 for one whose session cannot be told. It is known by its `status`, not by its class: omp imports an
 * extension afresh for every session, so the listener and whoever answers it may hold two copies of this module.
 */
export class Refusal extends Error {
	constructor(
		readonly status: 400 | 409,
		message: string,
	) {
		super(message);
	}
}

/** Answers one request of a kernel. `signal` aborts when the kernel hangs up: its cell timed out or was interrupted. */
export type Answer = (method: BridgeMethod, kernel: Kernel, body: JsonObject, signal: AbortSignal) => Promise<Json>;

export interface Bridge {
	url: string;
	/** The file a kernel finds this listener by. */
	file: string;
	/** Stop listening, hang up on every kernel still waiting, and remove the file. */
	stop(): void;
}

/**
 * Where the file goes, most private first: the user's runtime directory where the system has one, else a directory
 * of the user's own under the temporary directory, named by user id since that directory is everybody's. Windows has
 * no user id and its temporary directory is already the user's own. The kernels' side works out the same two.
 */
export function bridgeDirectories(): string[] {
	const runtime = process.env.XDG_RUNTIME_DIR?.trim();
	const own = join(tmpdir(), `${CONSTANTS.bridgeDirectory}-${process.getuid?.() ?? "user"}`);
	return runtime ? [join(runtime, CONSTANTS.bridgeDirectory), own] : [own];
}

/** Make `directory` this user's alone, or say why it cannot be trusted with the token. */
function ownDirectory(directory: string): void {
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	const found = lstatSync(directory);
	if (!found.isDirectory()) throw new Error(`${directory} is not a directory`);
	const uid = process.getuid?.();
	// Someone else's directory under a shared temporary directory is one they can swap files in.
	if (uid !== undefined && found.uid !== uid) throw new Error(`${directory} belongs to another user`);
	if (uid !== undefined && (found.mode & 0o077) !== 0) chmodSync(directory, 0o700);
}

function alive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		// EPERM is a process that is there and someone else's.
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
}

/** Remove the files of omp processes that are gone: one that was killed never removed its own. */
function sweep(directory: string): void {
	for (const name of readdirSync(directory)) {
		const pid = /^(\d+)\.json$/.exec(name)?.[1];
		if (pid !== undefined && !alive(Number(pid))) rmSync(join(directory, name), { force: true });
	}
}

function writeDiscovery(content: string): string {
	const failures: string[] = [];
	for (const directory of bridgeDirectories()) {
		try {
			ownDirectory(directory);
			sweep(directory);
			const file = join(directory, `${process.pid}.json`);
			// A file left by an earlier process of the same id is replaced, never written through.
			rmSync(file, { force: true });
			writeFileSync(file, content, { mode: 0o600, flag: "wx" });
			return file;
		} catch (error) {
			failures.push(error instanceof Error ? error.message : String(error));
		}
	}
	throw new Error(`omp-re: no private place for the file omp's eval finds the engine by: ${failures.join("; ")}`);
}

const said = (status: number, body: Json) => Response.json(body, { status });

function readKernel(value: unknown): Kernel | undefined {
	if (value === null || typeof value !== "object") return undefined;
	const { language, sessionFile, cwd } = value as Record<string, unknown>;
	if ((language !== "js" && language !== "py") || typeof cwd !== "string") return undefined;
	if (sessionFile !== undefined && typeof sessionFile !== "string") return undefined;
	return { language, cwd, ...(sessionFile ? { sessionFile } : {}) };
}

/** Start listening, and leave the file kernels find the listener by. */
export function startBridge(answer: Answer): Bridge {
	const token = randomBytes(32).toString("hex");
	const expected = Buffer.from(`Bearer ${token}`);
	const authorized = (request: Request) => {
		const given = Buffer.from(request.headers.get("authorization") ?? "");
		return given.length === expected.length && timingSafeEqual(given, expected);
	};
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		// An analysis can be silent for minutes, and the body of a decompile is not small.
		idleTimeout: 0,
		maxRequestBodySize: 64 * 1024 * 1024,
		async fetch(request) {
			if (!authorized(request)) return said(401, { error: "omp-re: this request does not carry the token of omp's listener" });
			const { pathname } = new URL(request.url);
			const method = BRIDGE_METHODS.find((one) => pathname === `/v${CONSTANTS.bridgeVersion}/${one}`);
			if (request.method !== "POST" || !method) return said(404, { error: `omp-re: omp's listener has no ${request.method} ${pathname}` });
			let body: JsonObject;
			try {
				body = (await request.json()) as JsonObject;
			} catch {
				return said(400, { error: "omp-re: the request's body is not JSON" });
			}
			const kernel = readKernel(body?.kernel);
			if (!kernel) return said(400, { error: "omp-re: the request does not say which kernel sent it" });
			try {
				return said(200, await answer(method, kernel, body, request.signal));
			} catch (error) {
				const status = (error as { status?: unknown } | null)?.status;
				return said(status === 400 || status === 409 ? status : 500, { error: error instanceof Error ? error.message : String(error) });
			}
		},
	});
	const url = `http://127.0.0.1:${server.port}`;
	let file: string;
	try {
		file = writeDiscovery(`${JSON.stringify({ url, token, pid: process.pid, bridge: CONSTANTS.bridgeVersion })}\n`);
	} catch (error) {
		void server.stop(true);
		throw error;
	}
	return {
		url,
		file,
		stop() {
			rmSync(file, { force: true });
			void server.stop(true);
		},
	};
}
