/**
 * NUL-framed rizin pipe protocol (`rizin -q0`) and per-session lifecycle.
 *
 * No npm dependency: direct child_process framing. In `-q0` mode rizin
 * terminates every response with a single 0x00 byte, including an empty
 * frame for a command that only wrote an error to stderr, and emits one
 * empty banner frame at startup that is consumed before `aaa` runs. Every
 * command is serialized through a promise chain because rizin answers
 * exactly one request at a time over the pipe.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { access, realpath as fsRealpath } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";

/** Allowed characters in an address/expression interpolated after `@`: hex, flag names, and
 * arithmetic (sym.main+0x10, $$). `@` itself is excluded so no value can smuggle in rizin's
 * `@@` foreach iterators, and `(`/`;`/`~`/`|`/quotes are excluded so no value can open a command
 * substitution, a separator, a grep, or a pipe. */
const ADDR_CHARS = /^[0-9a-zA-Z_.:$+-]+$/;

export function validateAddr(addr: string): string {
	if (!ADDR_CHARS.test(addr)) {
		throw new Error(`omp-re: invalid address or expression: ${JSON.stringify(addr)}`);
	}
	return addr;
}

/** Canonicalize an EA to "0x" + lowercase hex with no leading zeros (except "0x0"), or the lowercased raw value when it isn't 0x-prefixed. Used to key evidence/annotation lookups so "0x1100", "0X01100", and "0x1100 " all match. */
export function normalizeAddr(raw: string): string {
	let s = raw.trim().toLowerCase();
	if (!s.startsWith("0x")) return s;
	s = s.slice(2);
	if (s.length === 0) return "0x";
	while (s.length > 1 && s[0] === "0") s = s.slice(1);
	return `0x${s}`;
}

/** Identifiers for rename targets (function/variable names). */
const IDENT_CHARS = /^[A-Za-z_][A-Za-z0-9_.]*$/;

export function validateIdent(key: string, value: string): string {
	if (!IDENT_CHARS.test(value)) {
		throw new Error(`omp-re: invalid ${key}: ${JSON.stringify(value)}`);
	}
	return value;
}

/** Format a numeric offset as a lowercase `0x` hex string. */
export function eaFromOffset(offset: number): string {
	return `0x${offset.toString(16)}`;
}

/** rizin reports most addresses as `offset` (aflj/afij, pdfj ops) and a few as `addr` (pdfj's top level, `xrefs_to` rows). Accept either. */
export function addrOf(item: { addr?: number; offset?: number }): number | undefined {
	return item.addr ?? item.offset;
}

/**
 * Wrap a value as a single-quoted rizin argument. Inside single quotes rizin's
 * shell parser treats `;`, `@`, `~`, `|`, `>`, `` ` ``, `$(...)`, and `#` as
 * literal text; only `\'` and `\\` are escapes. Every free-text or type value
 * passes through here, so no model-supplied comment or signature can end the
 * current command and start another (including `!` shell escapes).
 */
export function rzQuote(value: string): string {
	if (value.includes("\n") || value.includes("\r") || value.includes("\0")) {
		throw new Error("omp-re: invalid argument: contains a newline or NUL");
	}
	return `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}

/**
 * Resolve a name/expression to a concrete numeric address via rizin's `%v`,
 * which (unlike `@ <expr>` addressing) never errors on an unresolvable input:
 * it prints "0x0". Failing fast here, before pdfj/pdg, gives a clear error
 * instead of treating base address 0 as real.
 */
export async function resolveNumericAddr(rz: RzSession, addr: string, signal?: AbortSignal): Promise<number> {
	const raw = (await rz.cmd(`%v ${validateAddr(addr)}`, { signal })).trim();
	const value = Number.parseInt(raw, 16);
	if (!Number.isFinite(value) || value === 0) {
		throw new Error(`omp-re: could not resolve address: ${addr}`);
	}
	return value;
}

const FORBIDDEN_TYPE_CHARS = [";", "|", "&", "`", "$", "\n", "\0"];

/** Validation for type/signature strings. The value is also rzQuote()d before it reaches rizin; rejecting characters no C type contains just turns a confusing rizin parse error into a clear one. */
export function validateTypeLike(key: string, value: string): string {
	for (const c of FORBIDDEN_TYPE_CHARS) {
		if (value.includes(c)) {
			throw new Error(`omp-re: invalid ${key}: forbidden character ${JSON.stringify(c)}`);
		}
	}
	return value;
}

/** Validation for free-text comment bodies: only line breaks and NUL are forbidden (they would end the pipe line); everything else is made literal by rzQuote(). */
export function validateText(value: string): string {
	if (value.includes("\n") || value.includes("\r") || value.includes("\0")) {
		throw new Error("omp-re: invalid text: contains forbidden character");
	}
	return value;
}

export class RzProtocolError extends Error {}

/** Thrown when the caller's AbortSignal fires. The rizin process is left alone for ordinary commands (their frames are still drained in order), so an aborted tool call never forces a respawn. */
export class RzAbortError extends Error {
	constructor(what: string) {
		super(`omp-re: ${what} aborted`);
		this.name = "AbortError";
	}
}

const COMMAND_TIMEOUT_MS = 60_000;
const STDERR_TAIL_MAX = 4096;

/** Budget for the one-time `aaa` on open: full analysis of a large or packed binary routinely runs minutes. */
export function analysisTimeoutMs(): number {
	return Number(process.env.OMPRE_ANALYSIS_TIMEOUT_MS) || 300_000;
}

/** Budget for a single debugger step/continue: a resumed process runs until it hits a breakpoint, signals, or exits. A continue that never returns (a process blocked on input) is killed at this bound. */
export function debugTimeoutMs(): number {
	return Number(process.env.OMPRE_DEBUG_TIMEOUT_MS) || 60_000;
}

/**
 * The flags every omp-re rizin process shares.
 *
 * `-q0` is the pipe protocol: `-q` (quiet, no prompt) plus `-0` (emit a NUL
 * after init and after every command), which is the frame delimiter the whole
 * RzSession protocol is built on. `scr.color`/`scr.utf8` off keep output
 * plain. `-N` skips the user's `rizinrc` and startup scripts so omp-re always
 * sees stock rizin — a global eval var or alias in a user's config can't
 * change the command output omp-re parses — while still loading plugins (that
 * needs `-NN`, which omp-re never uses), so rz-ghidra/jsdec and the catalog
 * are unaffected. `OMPRE_RIZIN_LOAD_USER_CONFIG=1` drops `-N` for anyone who
 * relies on their rizinrc (e.g. a custom `dir.plugins`).
 */
export function baseRizinFlags(): string[] {
	const flags = ["-q0", "-e", "scr.color=0", "-e", "scr.utf8=false"];
	if (!/^(1|true|yes|on)$/i.test((process.env.OMPRE_RIZIN_LOAD_USER_CONFIG ?? "").trim())) flags.push("-N");
	return flags;
}

export interface CmdOptions {
	timeoutMs?: number;
	signal?: AbortSignal;
}

export interface SpawnOptions {
	signal?: AbortSignal;
	/** Called about once a second while `aaa` runs, with the elapsed milliseconds. */
	onProgress?: (elapsedMs: number) => void;
	/** rz-run directives (`arg0=...`, `setenv=K=V`, `chdir=...`, ...) passed as `-R` flags — the debug launch's target environment. */
	runDirectives?: string[];
}

/** Settle `task` normally, or reject early with RzAbortError when `signal` fires. The task itself keeps running. */
export function raceAbort<T>(task: Promise<T>, signal: AbortSignal | undefined, what: string): Promise<T> {
	if (!signal) return task;
	if (signal.aborted) return Promise.reject(new RzAbortError(what));
	const { promise, resolve, reject } = Promise.withResolvers<T>();
	const onAbort = () => reject(new RzAbortError(what));
	signal.addEventListener("abort", onAbort, { once: true });
	task.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
	return promise;
}

/** One rizin subprocess speaking the NUL-framed pipe protocol. */
export class RzSession {
	private buf = Buffer.alloc(0);
	private queue: Promise<void> = Promise.resolve();
	private pending: { resolve: (frame: string) => void; reject: (err: Error) => void } | null = null;
	private closedFlag = false;
	private stderrTail = "";
	/** Total stderr characters seen, so a command can take exactly the stderr written while it ran. */
	private stderrSeen = 0;
	private cmdCounter = 0;

	private constructor(
		private readonly proc: ChildProcess,
		readonly binaryPath: string,
	) {
		this.proc.stdout?.on("data", (chunk: Buffer) => {
			this.buf = Buffer.concat([this.buf, chunk]);
			this.drain();
		});
		// Drain stderr unconditionally: an unread pipe fills its OS buffer and
		// blocks the child mid-write on a noisy binary, wedging every command.
		this.proc.stderr?.on("data", (chunk: Buffer) => {
			const text = chunk.toString("utf8");
			this.stderrSeen += text.length;
			this.stderrTail = (this.stderrTail + text).slice(-STDERR_TAIL_MAX);
		});
		this.proc.on("exit", () => {
			this.closedFlag = true;
			this.pending?.reject(new RzProtocolError("omp-re: rizin process exited"));
			this.pending = null;
		});
		this.proc.on("error", (err) => {
			this.closedFlag = true;
			this.pending?.reject(new RzProtocolError(`omp-re: rizin spawn failed: ${err.message}`));
			this.pending = null;
		});
	}

	/** Whether the underlying rizin process has exited or been closed. Callers should respawn rather than reuse. */
	get isClosed(): boolean {
		return this.closedFlag;
	}

	private drain(): void {
		if (!this.pending) return;
		const nul = this.buf.indexOf(0x00);
		if (nul === -1) return;
		const frame = this.buf.subarray(0, nul).toString("utf8");
		this.buf = this.buf.subarray(nul + 1);
		const { resolve } = this.pending;
		this.pending = null;
		resolve(frame);
	}

	private readFrame(): Promise<string> {
		if (this.closedFlag) {
			return Promise.reject(new RzProtocolError("omp-re: rizin process exited"));
		}
		const { promise, resolve, reject } = Promise.withResolvers<string>();
		this.pending = { resolve, reject };
		this.drain();
		return promise;
	}

	private timeoutError(command: string, timeoutMs: number): RzProtocolError {
		const detail = this.stderrTail.trim();
		return new RzProtocolError(
			`omp-re: rizin command timed out after ${timeoutMs}ms: ${command}${detail ? ` (stderr: ${detail})` : ""}`,
		);
	}

	/** Race a frame read against a hard timeout. A stuck rizin must never wedge the caller's tool call forever; on timeout the process is killed so the next command starts clean. */
	private withTimeout(framePromise: Promise<string>, command: string, timeoutMs: number): Promise<string> {
		const { promise: timeoutPromise, reject } = Promise.withResolvers<string>();
		const timer = setTimeout(() => {
			const err = this.timeoutError(command, timeoutMs);
			this.close();
			reject(err);
		}, timeoutMs);
		return Promise.race([framePromise, timeoutPromise]).finally(() => clearTimeout(timer));
	}

	/**
	 * Run a raw rizin command, returning its unparsed output.
	 *
	 * A unique `echo <marker>` is pipelined right after the real command in one
	 * write. rizin processes stdin lines strictly in order, so the marker's own
	 * frame is guaranteed to arrive; everything read before it is the real
	 * command's response. rizin itself emits exactly one frame per command, so
	 * this is one frame plus the marker in practice; the marker keeps the
	 * stream aligned even if a future rizin emits zero or several.
	 *
	 * Aborting `signal` rejects this call immediately but leaves the command
	 * queued: its frames are still drained in order, so the next command reads
	 * its own response and the process (with its analysis and annotations)
	 * survives. Only a timeout kills the process.
	 */
	cmd(command: string, options: CmdOptions = {}): Promise<string> {
		return this.run(command, options).then((result) => result.output);
	}

	/**
	 * Like cmd(), but also returns what rizin wrote to stderr while the command
	 * ran — its error messages and, for a malformed command, its own usage
	 * text. Best effort: stderr is a separate pipe, so a final fragment can
	 * trail the output by an event-loop turn, which is waited for once.
	 */
	cmdWithStderr(command: string, options: CmdOptions = {}): Promise<{ output: string; stderr: string }> {
		return this.run(command, options);
	}

	private run(command: string, options: CmdOptions): Promise<{ output: string; stderr: string }> {
		const timeoutMs = options.timeoutMs ?? COMMAND_TIMEOUT_MS;
		const task = this.queue.then(async () => {
			if (this.closedFlag) throw new RzProtocolError("omp-re: rizin process exited");
			const marker = `__OMPRE_SYNC_${(this.cmdCounter++).toString(36)}_${process.hrtime.bigint().toString(36)}__`;
			const deadline = Date.now() + timeoutMs;
			const stderrStart = this.stderrSeen;
			this.proc.stdin?.write(`${command}\necho ${marker}\n`);

			const collected: string[] = [];
			// The loop bound is a defensive ceiling against a genuinely desynced stream, not the expected path.
			for (let i = 0; i < 8; i++) {
				const remaining = deadline - Date.now();
				if (remaining <= 0) {
					const err = this.timeoutError(command, timeoutMs);
					this.close();
					throw err;
				}
				const frame = await this.withTimeout(this.readFrame(), command, remaining);
				if (frame.trim() === marker) {
					await new Promise((resolve) => setImmediate(resolve));
					const written = this.stderrSeen - stderrStart;
					const stderr = written > 0 ? this.stderrTail.slice(-Math.min(written, this.stderrTail.length)) : "";
					return { output: collected.join(""), stderr };
				}
				collected.push(frame);
			}
			const detail = this.stderrTail.trim();
			this.close();
			throw new RzProtocolError(
				`omp-re: rizin protocol desync waiting for sync marker after: ${command}${detail ? ` (stderr: ${detail})` : ""}`,
			);
		});
		this.queue = task.then(
			() => undefined,
			() => undefined,
		);
		return raceAbort(task, options.signal, `rizin command ${JSON.stringify(command)}`);
	}

	/** Run a command expecting a JSON frame. Returns null for empty output (rizin's reply to an invalid address or an unknown command) or anything that isn't JSON. */
	async cmdj<T>(command: string, options: CmdOptions = {}): Promise<T | null> {
		const raw = (await this.cmd(command, options)).trim();
		if (!raw.startsWith("{") && !raw.startsWith("[")) return null;
		try {
			return JSON.parse(raw) as T;
		} catch {
			return null;
		}
	}

	close(): void {
		if (this.closedFlag) return;
		this.closedFlag = true;
		this.proc.kill();
	}

	/**
	 * Spawn `rizin -q0 <binary>`, consume the startup banner, run `aaa`, and
	 * return a ready session. Colors and UTF-8 box drawing are turned off so
	 * plain-text output (pdg, pdf) is clean. Aborting `signal` during analysis
	 * kills the half-analyzed process; there is nothing in it worth keeping.
	 */
	static async spawn(rizinPath: string, binaryPath: string, options: SpawnOptions = {}): Promise<RzSession> {
		if (options.signal?.aborted) throw new RzAbortError("rizin analysis");
		const proc = spawn(rizinPath, [...baseRizinFlags(), binaryPath], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		const session = new RzSession(proc, binaryPath);
		const onAbort = () => session.close();
		options.signal?.addEventListener("abort", onAbort, { once: true });
		const started = Date.now();
		const ticker = options.onProgress ? setInterval(() => options.onProgress?.(Date.now() - started), 1000) : undefined;
		try {
			await session.withTimeout(session.readFrame(), "<startup banner>", COMMAND_TIMEOUT_MS);
			await session.cmd("aaa", { timeoutMs: analysisTimeoutMs() });
			return session;
		} catch (err) {
			session.close();
			if (options.signal?.aborted) throw new RzAbortError("rizin analysis");
			throw err;
		} finally {
			if (ticker) clearInterval(ticker);
			options.signal?.removeEventListener("abort", onAbort);
		}
	}

	/**
	 * Spawn a rizin DEBUG session: `rizin -q0 -d <binary>`, which LAUNCHES the
	 * target process (stopped at its entry) so it can be stepped and inspected.
	 * This is the one place omp-re executes a sample, kept entirely separate
	 * from the static {@link spawn} session that only ever reads the file.
	 * Light `aa` analysis (not full `aaa`) runs so symbols resolve in
	 * backtraces without slowing the launch.
	 */
	static async spawnDebug(rizinPath: string, binaryPath: string, options: SpawnOptions = {}): Promise<RzSession> {
		if (options.signal?.aborted) throw new RzAbortError("debug launch");
		// -R directives go before -d: each is one argv element (no shell), so
		// values with spaces need no quoting.
		const runFlags = (options.runDirectives ?? []).flatMap((d) => ["-R", d]);
		const proc = spawn(rizinPath, [...baseRizinFlags(), ...runFlags, "-d", binaryPath], {
			stdio: ["pipe", "pipe", "pipe"],
		});
		const session = new RzSession(proc, binaryPath);
		const onAbort = () => session.close();
		options.signal?.addEventListener("abort", onAbort, { once: true });
		try {
			await session.withTimeout(session.readFrame(), "<debug startup banner>", COMMAND_TIMEOUT_MS);
			await session.cmd("aa", { timeoutMs: analysisTimeoutMs() });
			return session;
		} catch (err) {
			session.close();
			if (options.signal?.aborted) throw new RzAbortError("debug launch");
			throw err;
		} finally {
			options.signal?.removeEventListener("abort", onAbort);
		}
	}
}

export function resolveRizinPath(): string {
	return process.env.OMPRE_RIZIN_PATH?.trim() || "rizin";
}

/**
 * The path to a sibling rizin CLI tool (`rz-bin`, `rz-diff`, …). rizin ships
 * these next to the `rizin` binary, so when the configured rizin is an
 * absolute path the tool is taken from the same directory (a non-default
 * install prefix keeps its own tools together); otherwise the bare name is
 * returned and resolved on PATH, exactly like `rizin` itself.
 */
export function resolveRizinTool(tool: string): string {
	const rizin = resolveRizinPath();
	const slash = rizin.lastIndexOf("/");
	return slash === -1 ? tool : `${rizin.slice(0, slash + 1)}${tool}`;
}

/** Whether `name` resolves to an executable, either as a path or via PATH. On Windows a path without an extension also tries the `.exe` form: a sibling tool resolved from OMPRE_RIZIN_PATH is "C:/dir/rz-hash", which access() cannot see but every spawn API runs fine. */
export async function isExecutable(name: string): Promise<boolean> {
	if (!name.includes("/")) return Bun.which(name) !== null || Bun.which(`${name}.exe`) !== null;
	for (const candidate of process.platform === "win32" && !/\.(exe|cmd|bat)$/i.test(name) ? [name, `${name}.exe`] : [name]) {
		try {
			await access(candidate, fsConstants.X_OK);
			return true;
		} catch {
			// try the next candidate
		}
	}
	return false;
}

export async function assertRizinAvailable(): Promise<void> {
	if (!(await isExecutable(resolveRizinPath()))) {
		throw new Error("omp-re: rizin not found on PATH — install rizin (https://rizin.re) or set OMPRE_RIZIN_PATH");
	}
}

/** `rizin -v`'s first line (e.g. "rizin 0.9.1 @ linux-x86-64"), or null when it can't be run. */
export async function rizinVersion(): Promise<string | null> {
	try {
		const proc = Bun.spawn([resolveRizinPath(), "-v"], { stdout: "pipe", stderr: "ignore" });
		const out = await new Response(proc.stdout).text();
		await proc.exited;
		return out.split("\n")[0]?.trim() || null;
	} catch {
		return null;
	}
}

/** Resolve a user-supplied binary path to an absolute, existing, readable file path. */
export async function resolveBinaryPath(inputPath: string): Promise<string> {
	let real: string;
	try {
		real = await fsRealpath(inputPath);
	} catch {
		throw new Error(`omp-re: no such binary: ${inputPath}`);
	}
	try {
		await access(real, fsConstants.R_OK);
	} catch {
		throw new Error(`omp-re: no such binary: ${inputPath}`);
	}
	return real;
}
