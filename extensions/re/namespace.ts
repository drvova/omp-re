/**
 * The `run` tool's namespace, host side: one long-lived JavaScript realm per
 * omp session, running in a worker (namespace-worker.ts).
 *
 * Each session (the main one and every task subagent, like its rizin process)
 * gets its own worker, started on first use; its global object is the
 * namespace. Cells run there one at a time, so whatever a cell defines is
 * there for the next. This side starts the worker, queues the calls, collects
 * what a cell prints, and answers the worker's requests — every `re`
 * capability (through {@link invokeCapability}, so it is validated, audited,
 * and recorded exactly as a tool call was), the session's rizin process,
 * evidence and findings, and `exec`.
 *
 * The worker is what makes a call stoppable. Cancelling the `run` call
 * terminates it, which ends even a loop that never yields; a cell that calls
 * `process.exit()` or crashes the worker ends only the worker. Either way the
 * call fails with a message saying the namespace was reset, and the next call
 * starts a fresh worker,
 * which reloads the kept definitions. The namespace hangs off the session's
 * record in runtime.ts, so it follows a branch and is disposed with it.
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { appendAuditLine } from "./audit.ts";
import { type CallScope, type CapabilityRegistry, invokeCapability } from "./capabilities.ts";
import { branchEntries, collectEvidence } from "./entries.ts";
import { liveFindings } from "./findings.ts";
import { manual } from "./describe.ts";
import { keptDir } from "./kept.ts";
import type { BinaryInfo, FromWorker, HostOp, KeptFailure, ToWorker } from "./namespace-protocol.ts";
import { ensureRizin, getState } from "./state.ts";
import { errorText } from "./values.ts";

/** What a `run` call brings to the namespace. */
export interface RunCall extends Omit<CallScope, "calls" | "evidence"> {
	strings: Record<string, string>;
}

export interface CellOutcome {
	/** Everything the cell printed, one entry per print/console call. */
	output: string[];
	/** A structured-clone copy of the last expression's value, or undefined (no value, or one that cannot be copied, like a function). */
	value: unknown;
	/** The last expression's value as the result shows it (strings verbatim, other values as JSON), or undefined when there was none. */
	shown: string | undefined;
	/** Names whose definitions this cell saved. */
	kept: string[];
	scope: CallScope;
}

/** A cell that threw or was stopped, with what it printed and recorded before it did. */
export class CellError extends Error {
	constructor(
		message: string,
		readonly output: string[],
		readonly scope: CallScope | null,
	) {
		super(message);
	}
}

const WORKER_URL = new URL("./namespace-worker.ts", import.meta.url).href;
const RESET = "the namespace was reset — kept definitions reload on the next call; other variables are gone";

interface LiveWorker {
	worker: Worker;
	ready: Promise<void>;
}

interface Running {
	runId: number;
	scope: CallScope;
	output: string[];
	resolve: (outcome: CellOutcome) => void;
	reject: (err: CellError) => void;
}

function binaryOf(ctx: ExtensionContext): BinaryInfo | null {
	const state = getState(ctx);
	return state.binaryPath ? { path: state.binaryPath, sha256: state.binarySha256 } : null;
}

export class ReNamespace {
	private live: LiveWorker | null = null;
	private current: Running | null = null;
	/** Cells run one at a time: each waits for the one before it. */
	private tail: Promise<unknown> = Promise.resolve();
	private runs = 0;
	private sideCalls = 0;
	private kept: string[] = [];
	private failures: KeptFailure[] = [];
	private disposed = false;

	private constructor(
		private readonly registry: CapabilityRegistry,
		private readonly toolName: string,
	) {}

	/** A namespace whose worker is up, with every kept definition loaded. */
	static async create(registry: CapabilityRegistry, toolName: string, ctx: ExtensionContext): Promise<ReNamespace> {
		const ns = new ReNamespace(registry, toolName);
		const live = ns.start(ctx);
		await live.ready;
		// Idle now: unreferenced, so it never keeps omp alive. A cell references it while it runs (execute).
		if (ns.live === live) live.worker.unref();
		return ns;
	}

	private start(ctx: ExtensionContext): LiveWorker {
		const worker = new Worker(WORKER_URL);
		let settle!: { resolve: () => void; reject: (err: Error) => void };
		const ready = new Promise<void>((resolve, reject) => {
			settle = { resolve, reject };
		});
		const live: LiveWorker = { worker, ready };
		this.live = live;
		worker.addEventListener("message", (event) => this.onMessage(live, event.data as FromWorker, settle.resolve));
		worker.addEventListener("error", (event) => {
			// Handled here: an error the worker could not catch ends only the worker, never omp.
			event.preventDefault();
			this.onDeath(live, `crashed (${event.message})`, settle.reject);
		});
		worker.addEventListener("close", (event) => this.onDeath(live, `exited (code ${(event as CloseEvent).code})`, settle.reject));
		const init: ToWorker = { type: "init", capabilities: this.registry.infos(), keptDir: keptDir(), toolName: this.toolName, binary: binaryOf(ctx) };
		worker.postMessage(init);
		return live;
	}

	private onMessage(live: LiveWorker, message: FromWorker, ready: () => void): void {
		if (live !== this.live) return; // a worker already replaced
		switch (message.type) {
			case "ready":
				this.kept = message.kept;
				this.failures = message.failures;
				ready();
				return;
			case "print":
				if (this.current?.runId === message.runId) this.current.output.push(message.text);
				return;
			case "call":
				void this.answer(live, message.callId, message.runId, message.op);
				return;
			case "done":
			case "failed": {
				this.kept = message.kept;
				this.failures = message.failures;
				const running = this.current;
				if (!running || running.runId !== message.runId) return;
				this.current = null;
				if (message.type === "failed") running.reject(new CellError(message.error, running.output, running.scope));
				else running.resolve({ output: [...running.output, ...message.notes], value: message.value, shown: message.shown, kept: message.saved, scope: running.scope });
				return;
			}
		}
	}

	/** The worker stopped on its own (process.exit, a crash): the running call fails, and the next one starts a fresh worker. */
	private onDeath(live: LiveWorker, how: string, notReady: (err: Error) => void): void {
		if (live !== this.live) return; // stopped deliberately by kill(), which already reported it
		this.live = null;
		notReady(new Error(`omp-re: the ${this.toolName} namespace's worker ${how} while starting`));
		const running = this.current;
		this.current = null;
		running?.reject(new CellError(`omp-re: the ${this.toolName} namespace's worker ${how}; ${RESET}`, running.output, running.scope));
	}

	/** Stop the worker now — mid-statement if need be — and fail the running call with `reason`. */
	private kill(reason: string): void {
		const live = this.live;
		this.live = null;
		void live?.worker.terminate();
		const running = this.current;
		this.current = null;
		running?.reject(new CellError(reason, running.output, running.scope));
	}

	private async answer(live: LiveWorker, callId: number, runId: number, op: HostOp): Promise<void> {
		const running = this.current;
		let reply: ToWorker;
		if (!running || running.runId !== runId) {
			reply = { type: "reply", callId, ok: false, error: { name: "Error", message: `omp-re: the ${this.toolName} call this belonged to has finished — await it inside the cell` }, binary: null };
		} else {
			try {
				const value = await this.perform(op, running.scope);
				reply = { type: "reply", callId, ok: true, value, binary: binaryOf(running.scope.ctx) };
			} catch (err) {
				const name = err && typeof err === "object" && typeof (err as { name?: unknown }).name === "string" ? (err as { name: string }).name : "Error";
				const message = err && typeof err === "object" && "message" in err ? String((err as { message: unknown }).message) : String(err);
				reply = { type: "reply", callId, ok: false, error: { name, message }, binary: binaryOf(running.scope.ctx) };
			}
		}
		if (live !== this.live) return;
		try {
			live.worker.postMessage(reply);
		} catch (err) {
			live.worker.postMessage({ type: "reply", callId, ok: false, error: { name: "DataCloneError", message: `omp-re: the result could not be passed to the namespace: ${errorText(err)}` }, binary: reply.binary });
		}
	}

	/** One audit line for a call the namespace makes outside the capability registry (raw rizin, exec). */
	private audit(scope: CallScope, tool: string, args: unknown): Promise<void> {
		return appendAuditLine(scope.ctx, { toolCallId: `${scope.toolCallId}.x${++this.sideCalls}`, tool, args }, scope.pi.logger);
	}

	private async perform(op: HostOp, scope: CallScope): Promise<unknown> {
		const { ctx, signal } = scope;
		switch (op.kind) {
			case "capability": {
				const cap = this.registry.get(op.name);
				if (!cap) throw new Error(`omp-re: re.${op.name} is not available in this session — describe(re) lists what is`);
				return invokeCapability(cap, op.params, scope);
			}
			case "rz": {
				if (op.method === "close") {
					getState(ctx).rz?.close();
					return undefined;
				}
				const rz = await ensureRizin(ctx, { signal });
				if (op.method === "open") return rz.binaryPath;
				const command = op.command ?? "";
				await this.audit(scope, `rz.${op.method}`, { command });
				if (op.method === "cmd") return rz.cmd(command, { signal });
				if (op.method === "cmdj") return rz.cmdj(command, { signal });
				return rz.cmdWithStderr(command, { signal });
			}
			case "evidence":
				return collectEvidence(branchEntries(ctx));
			case "findings":
				return liveFindings(ctx);
			case "exec":
				await this.audit(scope, "exec", { bin: op.bin, argv: op.argv });
				return scope.pi.exec(op.bin, op.argv, { signal, ...(op.timeout ? { timeout: op.timeout } : {}) });
		}
	}

	async manual(ctx: ExtensionContext): Promise<string> {
		return manual({
			toolName: this.toolName,
			binary: binaryOf(ctx),
			capabilityCount: this.registry.list().length,
			keptDir: keptDir(),
			kept: this.kept,
			keptFailures: this.failures,
		});
	}

	/** Run one cell. Calls queue behind each other: one namespace, one cell at a time. */
	run(code: string, call: RunCall): Promise<CellOutcome> {
		const turn = this.tail.then(() => this.execute(code, call));
		this.tail = turn.catch(() => undefined);
		return turn;
	}

	private async execute(code: string, call: RunCall): Promise<CellOutcome> {
		const { strings, ...rest } = call;
		const scope: CallScope = { ...rest, calls: [], evidence: [] };
		if (this.disposed) throw new CellError(`omp-re: this session's ${this.toolName} namespace was shut down`, [], scope);
		if (call.signal?.aborted) throw new CellError("cancelled before it started", [], scope);
		const live = this.live ?? this.start(call.ctx);
		// Referenced while a caller waits on it; unreferenced again when the cell ends, so an idle worker never keeps omp alive.
		live.worker.ref();
		const onAbort = () => this.kill(`omp-re: cancelled — the call was stopped where it was; ${RESET}`);
		try {
			try {
				await live.ready;
			} catch (err) {
				throw new CellError(errorText(err), [], scope);
			}
			const runId = ++this.runs;
			return await new Promise<CellOutcome>((resolve, reject) => {
				this.current = { runId, scope, output: [], resolve, reject };
				call.signal?.addEventListener("abort", onAbort, { once: true });
				const message: ToWorker = { type: "run", runId, code, strings, binary: binaryOf(call.ctx) };
				live.worker.postMessage(message);
			});
		} finally {
			call.signal?.removeEventListener("abort", onAbort);
			if (this.live === live) live.worker.unref();
		}
	}

	/** Shut the namespace down with its session: stop the worker and fail a running call. */
	dispose(): void {
		this.disposed = true;
		this.kill(`omp-re: the session ended; ${RESET}`);
	}
}

/** This session's namespace, created (worker started, kept definitions loaded) on first use. */
export function namespaceFor(ctx: ExtensionContext, registry: CapabilityRegistry, toolName: string): Promise<ReNamespace> {
	const state = getState(ctx);
	if (!state.namespace) {
		state.namespace = ReNamespace.create(registry, toolName, ctx).catch((err) => {
			state.namespace = null;
			throw err;
		});
	}
	return state.namespace;
}
