/**
 * The engine process and the wire to it.
 *
 * omp-re's engine is Common Lisp (`engine/`). Under omp it runs as one SBCL
 * child for the whole omp process, started by `stdio/serve.lisp`, and the two
 * sides exchange JSON lines on the child's standard input and output:
 * docs/engine-protocol.md is the contract. This module starts the child,
 * frames and routes messages, and ends it; it knows nothing of what the
 * messages mean.
 */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getAgentDir } from "@oh-my-pi/pi-utils";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json | undefined };
export type JsonObject = { [key: string]: Json | undefined };

/** Answers one of the engine's own requests or notifications (docs/engine-protocol.md, "What the engine asks omp"). */
export type HostHandler = (params: JsonObject) => unknown | Promise<unknown>;

const PROTOCOL = 1;
const SERVE_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "stdio", "serve.lisp");
/** How much of the engine's standard error is kept to explain an exit. */
const LOG_TAIL_CHARS = 4096;
/** omp gives a session's shutdown handlers 2 s; the engine gets most of it to close its rizin processes, then is killed. */
const STOP_GRACE_MS = 1500;

function sbclPath(): string {
	return process.env.OMPRE_SBCL_PATH?.trim() || "sbcl";
}

function missingSbcl(path: string): Error {
	return new Error(
		`omp-re: SBCL was not found (tried ${JSON.stringify(path)}). omp-re's engine is Common Lisp and needs SBCL with the cl-ppcre library: install them (Debian/Ubuntu: apt install sbcl cl-ppcre; macOS: brew install sbcl, then cl-ppcre through Quicklisp; Windows: the installer from https://www.sbcl.org), or set OMPRE_SBCL_PATH to the sbcl executable.`,
	);
}

/** omp's environment as the engine reads it. The child was started once, so it is sent, and sent again when it changed. */
function environment(): JsonObject {
	const variables: JsonObject = {};
	for (const [name, value] of Object.entries(process.env)) {
		if (value !== undefined && (name.startsWith("OMPRE_") || name.toUpperCase() === "PATH")) variables[name.toUpperCase() === "PATH" ? "PATH" : name] = value;
	}
	return { variables, stateDir: getAgentDir() };
}

interface Pending {
	resolve: (result: Json) => void;
	reject: (error: Error) => void;
}

export class Engine {
	#child: ChildProcessWithoutNullStreams;
	#pending = new Map<number, Pending>();
	#nextId = 1;
	#buffered = "";
	#logTail = "";
	#sentEnvironment = "";
	#ready: Promise<void>;
	#failed: Error | undefined;
	#handlers: Record<string, HostHandler>;
	/** Settles when the child has exited. */
	readonly exited: Promise<void>;

	constructor(handlers: Record<string, HostHandler>) {
		this.#handlers = handlers;
		const path = sbclPath();
		// No shell: the arguments reach SBCL as they are on every platform.
		this.#child = spawn(path, ["--noinform", "--no-sysinit", "--no-userinit", "--disable-debugger", "--load", SERVE_SCRIPT], {
			stdio: ["pipe", "pipe", "pipe"],
			windowsHide: true,
		});
		const { promise: ready, resolve: becameReady, reject: neverReady } = Promise.withResolvers<void>();
		const { promise: exited, resolve: didExit } = Promise.withResolvers<void>();
		this.#ready = ready;
		this.exited = exited;
		// A failed start is reported by the request that needed the engine, not as an unhandled rejection.
		ready.catch(() => {});

		const fail = (error: Error) => {
			this.#failed ??= error;
			neverReady(this.#failed);
			for (const waiting of this.#pending.values()) waiting.reject(this.#failed);
			this.#pending.clear();
		};
		this.#child.on("error", (error: NodeJS.ErrnoException) => {
			fail(error.code === "ENOENT" ? missingSbcl(path) : new Error(`omp-re: the engine could not be started: ${error.message}`));
			didExit();
		});
		this.#child.on("exit", (code, signal) => {
			const log = this.#logTail.trim();
			fail(new Error(`omp-re: the engine process ended (${signal ?? `status ${code}`})${log ? `: ${log}` : ""}`));
			didExit();
		});
		// A write to a child that is already gone is reported through "exit", not thrown here.
		this.#child.stdin.on("error", () => {});
		this.#child.stderr.setEncoding("utf8");
		this.#child.stderr.on("data", (chunk: string) => {
			this.#logTail = (this.#logTail + chunk).slice(-LOG_TAIL_CHARS);
		});
		this.#child.stdout.setEncoding("utf8");
		this.#child.stdout.on("data", (chunk: string) => {
			this.#buffered += chunk;
			for (;;) {
				const end = this.#buffered.indexOf("\n");
				if (end === -1) break;
				const line = this.#buffered.slice(0, end).replace(/\r$/, "");
				this.#buffered = this.#buffered.slice(end + 1);
				let message: JsonObject;
				try {
					message = JSON.parse(line);
				} catch {
					continue;
				}
				if (message === null || typeof message !== "object") continue;
				if (message.ready !== undefined) becameReady();
				else if (typeof message.fatal === "string") fail(new Error(message.fatal));
				else this.#receive(message);
			}
		});
		this.#write({ id: this.#nextId++, method: "hello", params: { protocol: PROTOCOL, ...this.#takeEnvironment() } });
	}

	#write(message: JsonObject): void {
		if (this.#child.stdin.writable) this.#child.stdin.write(`${JSON.stringify(message)}\n`);
	}

	#takeEnvironment(): JsonObject {
		const current = environment();
		this.#sentEnvironment = JSON.stringify(current);
		return current;
	}

	#receive(message: JsonObject): void {
		const { id, method } = message;
		if (typeof method !== "string") {
			const waiting = typeof id === "number" ? this.#pending.get(id) : undefined;
			if (!waiting) return;
			this.#pending.delete(id as number);
			const error = message.error as JsonObject | undefined;
			if (error) waiting.reject(new Error(typeof error.message === "string" ? error.message : "omp-re: the engine refused the request"));
			else waiting.resolve(message.result ?? null);
			return;
		}
		const handler = this.#handlers[method];
		const params = (message.params ?? {}) as JsonObject;
		const answer = async () => (handler ? ((await handler(params)) ?? {}) : {});
		if (id === undefined) {
			void answer().catch(() => {});
			return;
		}
		answer().then(
			(result) => this.#write({ id, result: result as Json }),
			(error) => this.#write({ id, error: { message: error instanceof Error ? error.message : String(error) } }),
		);
	}

	/** Ask the engine `method`. Aborting `signal` tells the engine the caller gave up; the answer, which then says so, is still what settles this. */
	async request<T = JsonObject>(method: string, params: JsonObject = {}, signal?: AbortSignal, onId?: (id: number) => void): Promise<T> {
		await this.#ready;
		if (this.#failed) throw this.#failed;
		if (JSON.stringify(environment()) !== this.#sentEnvironment) this.#write({ method: "environment", params: this.#takeEnvironment() });
		const id = this.#nextId++;
		onId?.(id);
		const { promise, resolve, reject } = Promise.withResolvers<Json>();
		this.#pending.set(id, { resolve, reject });
		const cancel = () => this.#write({ method: "cancel", params: { id } });
		if (signal?.aborted) cancel();
		else signal?.addEventListener("abort", cancel, { once: true });
		this.#write({ id, method, params });
		try {
			return (await promise) as T;
		} finally {
			signal?.removeEventListener("abort", cancel);
		}
	}

	/** End the engine: ask it to close its rizin processes and leave, and kill it if it has not by the end of the grace period. */
	async stop(): Promise<void> {
		this.#write({ method: "shutdown", params: {} });
		this.#child.stdin.end();
		const timer = setTimeout(() => this.kill(), STOP_GRACE_MS);
		await this.exited;
		clearTimeout(timer);
	}

	kill(): void {
		this.#child.kill("SIGKILL");
	}

	get pid(): number | undefined {
		return this.#child.pid;
	}
}
