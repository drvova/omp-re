/**
 * The engine process and the wire to it.
 *
 * omp-re's engine is Common Lisp (`engine/`). Under omp it runs as one child
 * for the whole omp process — a saved image of the engine, or SBCL loading
 * `stdio/serve.lisp`; image.ts says which — and the two sides exchange JSON
 * lines on the child's standard input and output: docs/engine-protocol.md is
 * the contract and stdio/protocol.json its description, from which
 * protocol.ts is generated. This module starts the child, frames and routes
 * messages, bounds how long it waits, and ends the child; it knows nothing of
 * what the messages mean.
 */
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import { CONSTANTS, type Json, type JsonObject, PROTOCOL, TO_HOST, type ToEngine, type ToHost } from "./protocol.ts";

export type { Json, JsonObject };

type RequestOf<T> = { [M in keyof T]: T[M] extends { result: unknown } ? M : never }[keyof T];
type ResultOf<T, M extends keyof T> = T[M] extends { result: infer R } ? R : void;

/** What omp asks of the engine and is answered. */
export type EngineRequest = RequestOf<ToEngine>;
/** What omp tells the engine. */
export type EngineNotification = Exclude<keyof ToEngine, EngineRequest>;

/**
 * omp's answer to each thing the engine asks or tells it (docs/engine-protocol.md, "What the engine asks omp"). One
 * for every method the protocol has, so a method added to stdio/protocol.json fails the type check until it is
 * answered. `alive` is the wire's own and is answered here.
 */
export type HostHandlers = { [M in Exclude<keyof ToHost, "alive">]: (params: ToHost[M]["params"]) => ResultOf<ToHost, M> | Promise<ResultOf<ToHost, M>> };

/** How much of the engine's standard error is kept to explain an exit. */
const LOG_TAIL_CHARS = 4096;

/** How long the engine is waited for. A test starts an engine with shorter ones. */
export interface Deadlines {
	/** From wanting an engine to its answer to `hello`. A first start compiles the engine and saves an image of it, seconds on most machines; a start that takes this long is not coming. */
	startMs: number;
	/** omp gives a session's shutdown handlers 2 s; the engine gets most of it to close its rizin processes, then is killed. */
	stopGraceMs: number;
	/** The pace of the engine's `alive`. */
	beatMs: number;
}

export const DEADLINES: Deadlines = { startMs: 120_000, stopGraceMs: 1500, beatMs: CONSTANTS.aliveSeconds * 1000 };
/** An engine that has said nothing for this many beats, with a request waiting, is hung. */
const SILENT_BEATS = 6;
/** A request this many beats in a row do not name is not being served. */
const UNSERVED_BEATS = 2;

/**
 * How an engine is started: the program and its arguments; or, where there is more than one way, a function that
 * gives them one at a time. It is called for the first, and again, with the reason, each time what it gave did not
 * come to say `ready`. When it has nothing left it rejects, and that is the start's error.
 */
export type Start = readonly string[] | ((failed?: Error) => Promise<readonly string[]>);

function notStarted(program: string, cause: Error): Error {
	return new Error(
		`omp-re: SBCL was not found (tried ${JSON.stringify(program)}). omp-re's engine is Common Lisp and needs SBCL with the cl-ppcre library: install them (Debian/Ubuntu: apt install sbcl cl-ppcre; macOS: brew install sbcl, then cl-ppcre through Quicklisp; Windows: the installer from https://www.sbcl.org, and cl-ppcre unpacked under %USERPROFILE%\\common-lisp\\), or set OMPRE_SBCL_PATH to the sbcl executable itself (not a .cmd or .bat wrapper: the engine is started without a shell).`,
		{ cause },
	);
}

function otherVersion(theirs: unknown): Error {
	return new Error(
		`omp-re: the extension speaks protocol ${PROTOCOL} and its engine protocol ${JSON.stringify(theirs)}: the two halves of omp-re are of different versions. Reinstall or upgrade the omp-re plugin, then start omp again.`,
	);
}

/** omp's environment as the engine reads it. The child was started once, so it is sent, and sent again when it changed. */
function environment(): ToEngine["environment"]["params"] {
	const variables: { [name: string]: string } = {};
	for (const [name, value] of Object.entries(process.env)) {
		// Windows spells it Path; the engine reads PATH.
		if (value !== undefined && (name.startsWith(CONSTANTS.environmentPrefix) || name.toUpperCase() === "PATH")) variables[name.toUpperCase() === "PATH" ? "PATH" : name] = value;
	}
	return { variables, stateDir: getAgentDir() };
}

interface Pending {
	method: string;
	sentAt: number;
	/** How many `alive` beats in a row did not name it. */
	unserved: number;
	resolve: (result: Json) => void;
	reject: (error: Error) => void;
}

export interface EngineOptions {
	command: Start;
	handlers: HostHandlers;
	/** Where a line the engine wrote to its standard error goes, as it arrives, and what this side has to note of the wire. */
	log: (line: string) => void;
	deadlines?: Partial<Deadlines>;
}

export class Engine {
	/** The engine process; none while a way to start one is still being found. */
	#child: ChildProcessWithoutNullStreams | undefined;
	/** What ends the child now running as a start that did not come to `ready`. */
	#attemptFailed: (error: Error) => void = () => {};
	#program = "";
	#hello: JsonObject = {};
	#heardReady = false;
	#stopped = false;
	#didExit: () => void;
	#startedAs: ToEngine["hello"]["result"]["started"] | undefined;
	#pending = new Map<number, Pending>();
	#nextId = 1;
	#buffered = "";
	#logLine = "";
	#logTail = "";
	#lastHeard = Date.now();
	#watch: ReturnType<typeof setInterval> | undefined;
	#sentEnvironment = "";
	#ready: Promise<void>;
	#failed: Error | undefined;
	#started = false;
	#options: EngineOptions;
	#deadlines: Deadlines;
	readonly exited: Promise<void>;

	constructor(options: EngineOptions) {
		this.#options = options;
		this.#deadlines = { ...DEADLINES, ...options.deadlines };
		const { promise: exited, resolve: didExit } = Promise.withResolvers<void>();
		this.exited = exited;
		this.#didExit = didExit;

		const start = setTimeout(() => {
			this.#fail(
				new Error(
					`omp-re: the engine did not start within ${Math.round(this.#deadlines.startMs / 1000)} s and was ended. Check that ${JSON.stringify(this.#program || "sbcl")} --version answers, that ~/quicklisp/setup.lisp asks nothing, and that ASDF's compiled-file cache (~/.cache/common-lisp) can be written.${this.#said()}`,
				),
			);
			this.kill();
		}, this.#deadlines.startMs);
		start.unref?.();
		// The engine is ready when it has answered hello: it loaded, and speaks this protocol.
		this.#ready = this.#send("hello", { protocol: PROTOCOL, ...this.#takeEnvironment() }, undefined, (message) => {
			this.#hello = message;
		}).then(
			(answer) => {
				clearTimeout(start);
				this.#started = true;
				this.#startedAs = (answer as ToEngine["hello"]["result"]).started;
			},
			(error: Error) => {
				clearTimeout(start);
				throw error;
			},
		);
		// A failed start is reported by the request that needed the engine, not as an unhandled rejection.
		this.#ready.catch(() => {});
		void this.#launch();
	}

	/** Start the engine the next way there is, `failed` being why the last way did not start; with none left, the start has failed. */
	async #launch(failed?: Error): Promise<void> {
		const { command } = this.#options;
		let next: readonly string[] | undefined;
		try {
			if (typeof command === "function") next = await command(failed);
			else if (failed) throw failed;
			else next = command;
		} catch (error) {
			this.#fail(error instanceof Error ? error : new Error(String(error)));
		}
		// The start deadline passed, or the engine was stopped, while a way was being found.
		if (!next || this.#failed || this.#stopped) {
			this.#didExit();
			return;
		}
		const [program, ...args] = next as [string, ...string[]];
		this.#program = program;
		this.#buffered = "";
		this.#logTail = "";
		// Node reports a program it cannot run as ENOENT, and on Windows a .cmd or .bat named without a shell as EINVAL.
		const unstartable = (error: NodeJS.ErrnoException) =>
			error.code === "ENOENT" || error.code === "EINVAL" ? notStarted(program, error) : new Error(`omp-re: the engine could not be started: ${error.message}`, { cause: error });
		let child: ChildProcessWithoutNullStreams;
		try {
			// No shell: the arguments reach the program as they are on every platform.
			child = spawn(program, args, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
		} catch (error) {
			// bun throws here for a file that is no program, where Node reports it on the child.
			void this.#launch(unstartable(error as NodeJS.ErrnoException));
			return;
		}
		this.#child = child;
		let over = false;
		const ended = (error: Error) => {
			if (over) return;
			over = true;
			if (!this.#heardReady && !this.#failed && !this.#stopped) {
				this.#child = undefined;
				void this.#launch(error);
				return;
			}
			this.#fail(error);
			this.#didExit();
		};
		this.#attemptFailed = (error) => {
			if (over) return;
			ended(error);
			child.kill("SIGKILL");
		};
		child.on("error", (error: NodeJS.ErrnoException) => ended(unstartable(error)));
		child.on("exit", (code, signal) => ended(new Error(`omp-re: the engine process ended (${signal ?? `status ${code}`})${this.#said()}`)));
		// A write to a child that is already gone is reported through "exit", not thrown here.
		child.stdin.on("error", () => {});
		child.stderr.setEncoding("utf8");
		child.stderr.on("data", (chunk: string) => this.#logged(chunk));
		child.stdout.setEncoding("utf8");
		child.stdout.on("data", (chunk: string) => {
			if (this.#child === child) this.#read(chunk);
		});
		this.#write(this.#hello);
	}

	/** The engine's last words on its standard error, to end an error with. */
	#said(): string {
		const log = this.#logTail.trim();
		return log ? `: ${log}` : "";
	}

	#fail(error: Error): void {
		this.#failed ??= error;
		const waiting = [...this.#pending.values()];
		this.#pending.clear();
		this.#watching();
		for (const one of waiting) one.reject(this.#failed);
	}

	#logged(chunk: string): void {
		this.#logTail = (this.#logTail + chunk).slice(-LOG_TAIL_CHARS);
		const lines = (this.#logLine + chunk).split("\n");
		this.#logLine = lines.pop()!;
		for (const line of lines) if (line.trim() !== "") this.#options.log(line.replace(/\r$/, ""));
	}

	#read(chunk: string): void {
		this.#lastHeard = Date.now();
		this.#buffered += chunk;
		for (;;) {
			const end = this.#buffered.indexOf("\n");
			if (end === -1) break;
			const line = this.#buffered.slice(0, end).replace(/\r$/, "");
			this.#buffered = this.#buffered.slice(end + 1);
			let message: JsonObject | null = null;
			try {
				const parsed: unknown = JSON.parse(line);
				if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) message = parsed as JsonObject;
			} catch {
				// Not JSON: noted below.
			}
			if (message === null) {
				if (line.trim() !== "") this.#options.log(`skipped a line on the wire that is not a message: ${line.slice(0, 200)}`);
			} else if (message.ready !== undefined) {
				if (message.ready === PROTOCOL) this.#heardReady = true;
				else this.#attemptFailed(otherVersion(message.ready));
			} else if (typeof message.fatal === "string") this.#attemptFailed(new Error(message.fatal));
			else this.#receive(message);
		}
	}

	#write(message: JsonObject): void {
		if (this.#child?.stdin.writable) this.#child.stdin.write(`${JSON.stringify(message)}\n`);
	}

	#takeEnvironment(): ToEngine["environment"]["params"] {
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
			this.#watching();
			const error = message.error as JsonObject | undefined;
			if (error) waiting.reject(new Error(typeof error.message === "string" ? error.message : "omp-re: the engine refused the request"));
			else waiting.resolve(message.result ?? null);
			return;
		}
		const params = (message.params ?? {}) as never;
		if (method === "alive") {
			this.#beat((params as ToHost["alive"]["params"]).serving);
			return;
		}
		const answer = async (): Promise<Json> => {
			if (!Object.hasOwn(TO_HOST, method)) throw new Error(`omp-re: omp has no method ${JSON.stringify(method)}`);
			return ((await this.#options.handlers[method as keyof HostHandlers](params)) ?? {}) as Json;
		};
		const said = (error: unknown) => (error instanceof Error ? error.message : String(error));
		if (id === undefined) {
			// Nobody waits for a notification's answer: what went wrong with one is in the log.
			answer().catch((error) => this.#options.log(`${method}: ${said(error)}`));
			return;
		}
		answer().then(
			(result) => this.#write({ id, result }),
			(error) => this.#write({ id, error: { message: said(error) } }),
		);
	}

	/** Run the watch while anything waits for a started engine, and only then: an idle engine is silent by right, and one still loading has the start's own deadline. */
	#watching(): void {
		if (this.#pending.size === 0 || this.#failed || !this.#started) {
			clearInterval(this.#watch);
			this.#watch = undefined;
			return;
		}
		if (this.#watch) return;
		this.#lastHeard = Date.now();
		this.#watch = setInterval(() => {
			const silent = () => Date.now() - this.#lastHeard > SILENT_BEATS * this.#deadlines.beatMs;
			if (!silent()) return;
			// A timer can fire ahead of output that arrived while omp itself was busy; that output is read first.
			setTimeout(() => {
				if (!silent() || this.#pending.size === 0 || this.#failed) return;
				this.#fail(
					new Error(
						`omp-re: the engine has said nothing for ${Math.round((SILENT_BEATS * this.#deadlines.beatMs) / 1000)} s with ${this.#pending.size} request(s) waiting (${[...this.#pending.values()].map((one) => one.method).join(", ")}); it was ended, and the next call starts another${this.#said()}`,
					),
				);
				this.kill();
			}, 50);
		}, this.#deadlines.beatMs);
		this.#watch.unref?.();
	}

	/** The engine said which requests it is serving. One it leaves out beat after beat was never received, or its answer was lost. */
	#beat(serving: number[]): void {
		const now = Date.now();
		for (const [id, waiting] of this.#pending) {
			if (serving.includes(id) || now - waiting.sentAt < this.#deadlines.beatMs) {
				waiting.unserved = 0;
			} else if (++waiting.unserved >= UNSERVED_BEATS) {
				this.#pending.delete(id);
				waiting.reject(new Error(`omp-re: the engine is not serving the request ${waiting.method}: it was not received, or its answer was lost`));
			}
		}
		this.#watching();
	}

	/** Ask `method` and answer its result. `keep`, for `hello`, takes the message in place of the wire: it is written to each child as it is started. */
	#send(method: string, params: object, onId?: (id: number) => void, keep?: (message: JsonObject) => void): Promise<Json> {
		const id = this.#nextId++;
		onId?.(id);
		const { promise, resolve, reject } = Promise.withResolvers<Json>();
		this.#pending.set(id, { method, sentAt: Date.now(), unserved: 0, resolve, reject });
		this.#watching();
		const message = { id, method, params: params as JsonObject };
		if (keep) keep(message);
		else this.#write(message);
		return promise;
	}

	/** Tell the engine `method`: nothing is answered. */
	notify<M extends EngineNotification>(method: M, params: ToEngine[M]["params"]): void {
		this.#write({ method, params: params as JsonObject });
	}

	/** Ask the engine `method`. Aborting `signal` tells the engine the caller gave up; the answer, which then says so, is still what settles this. */
	async request<M extends EngineRequest>(method: M, params: ToEngine[M]["params"], signal?: AbortSignal, onId?: (id: number) => void): Promise<ResultOf<ToEngine, M>> {
		await this.#ready;
		if (this.#failed) throw this.#failed;
		if (JSON.stringify(environment()) !== this.#sentEnvironment) this.notify("environment", this.#takeEnvironment());
		let id = 0;
		const cancel = () => this.notify("cancel", { id });
		const answer = this.#send(method, params, (taken) => {
			id = taken;
			onId?.(taken);
		});
		if (signal?.aborted) cancel();
		else signal?.addEventListener("abort", cancel, { once: true });
		try {
			return (await answer) as ResultOf<ToEngine, M>;
		} finally {
			signal?.removeEventListener("abort", cancel);
		}
	}

	/**
	 * End the engine. It is told to leave and its input is closed, either of which makes it close its rizin
	 * processes in order and exit; it is killed only if it is still there at the end of the grace period.
	 */
	async stop(): Promise<void> {
		this.#stopped = true;
		if (!this.#child) {
			// No process yet: whatever was on its way to starting one finds the engine stopped.
			this.#fail(new Error("omp-re: the engine was stopped before it had started"));
			return;
		}
		this.notify("shutdown", {});
		this.#child.stdin.end();
		const timer = setTimeout(() => this.kill(), this.#deadlines.stopGraceMs);
		await this.exited;
		clearTimeout(timer);
	}

	kill(): void {
		this.#child?.kill("SIGKILL");
	}

	get pid(): number | undefined {
		return this.#child?.pid;
	}

	/** How the engine that answered `hello` came to be: loaded from source, or a saved image. Undefined until it has answered. */
	get startedAs(): ToEngine["hello"]["result"]["started"] | undefined {
		return this.#startedAs;
	}
}
