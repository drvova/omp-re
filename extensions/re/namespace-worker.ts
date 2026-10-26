/**
 * The `run` namespace's worker: where the model's code actually runs.
 *
 * One Bun Worker per omp session (namespace.ts starts it). Its global object
 * IS the namespace — a realm of its own, apart from omp's — seeded with the
 * vocabulary (`re`, `describe`, `man`, `kept`, `forget`, `strings`, `print`,
 * `exec`, `mcp`, `require`). Cells compiled by cell.ts are evaluated here one at
 * a time, so whatever a cell defines is there for the next.
 *
 * Running in a worker is what makes a call stoppable: the host terminates the
 * worker when the call is cancelled, which ends even a loop that never yields,
 * and a cell that calls `process.exit()` or crashes ends only the worker. The
 * host then starts a fresh one, which reloads the kept definitions. An
 * exception a timer throws after its cell has returned is caught here and
 * printed into the running call's output (or dropped between calls) instead of
 * ending the worker.
 *
 * Everything that needs omp is a `call` to the host (namespace-protocol.ts).
 */
import { createRequire } from "node:module";
import { parentPort } from "node:worker_threads";
import { checkUnit, compileCell } from "./cell.ts";
import { CAPABILITY, type CapabilityInfo, DESCRIBERS, describeMcpServer, describeValue, describeWorkspace, leadingDoc, manual, shorthandParam } from "./describe.ts";
import { forgetKept, isUnitName, listKept, saveDefinitions } from "./kept.ts";
import type { AdHocMcpServer, BinaryInfo, FromWorker, HostOp, KeptFailure, McpConnectionInfo, ToWorker } from "./namespace-protocol.ts";
import { errorText, show } from "./values.ts";

const port = parentPort;
if (!port) throw new Error("omp-re: namespace-worker.ts runs only as a worker");

function post(message: FromWorker): void {
	port!.postMessage(message);
}

let toolName = "run";
let dir = "";
let capabilities: CapabilityInfo[] = [];
let binary: BinaryInfo | null = null;
/** The running cell's id, or null between calls. */
let runId: number | null = null;
let cells = 0;
const loaded = new Set<string>();
let failures: KeptFailure[] = [];
/** Source of each kept unit this namespace knows (loaded, or saved by a cell), for describe() docs. */
const unitSource = new Map<string, string>();
/** The namespace's own names, which a cell may not redeclare. */
const vocabulary = new Set<string>();

let nextCall = 1;
const pending = new Map<number, { resolve: (value: unknown) => void; reject: (err: Error) => void }>();

function requireRunning(what: string): number {
	if (runId === null) throw new Error(`omp-re: ${what} can only be used while a ${toolName} call is running — await it inside the cell`);
	return runId;
}

/** Ask the host to do something for the running cell. Async, so a call outside a running cell rejects rather than throwing synchronously. */
async function host(what: string, op: HostOp): Promise<unknown> {
	const id = requireRunning(what);
	const callId = nextCall++;
	return new Promise((resolve, reject) => {
		pending.set(callId, { resolve, reject });
		post({ type: "call", callId, runId: id, op });
	});
}

function print(args: unknown[]): void {
	if (runId !== null) post({ type: "print", runId, text: args.map(show).join(" ") });
}

process.on("uncaughtException", (err) => print([`(uncaught: ${errorText(err)})`]));
process.on("unhandledRejection", (err) => print([`(unhandled rejection: ${errorText(err)})`]));

/** The proxy `re.rz()` returns: the session's rizin process, driven through the host. */
class RzSession {
	constructor(readonly binaryPath: string) {}
	async cmd(command: string): Promise<string> {
		return (await host("rz.cmd", { kind: "rz", method: "cmd", command: String(command) })) as string;
	}
	async cmdj<T = unknown>(command: string): Promise<T | null> {
		return (await host("rz.cmdj", { kind: "rz", method: "cmdj", command: String(command) })) as T | null;
	}
	async cmdWithStderr(command: string): Promise<{ output: string; stderr: string }> {
		return (await host("rz.cmdWithStderr", { kind: "rz", method: "cmdWithStderr", command: String(command) })) as { output: string; stderr: string };
	}
	async close(): Promise<void> {
		await host("rz.close", { kind: "rz", method: "close" });
	}
}

/** An operation method: async, with its metadata attached for describe(). */
function operation(owner: string, cap: CapabilityInfo, call: (params: unknown) => Promise<unknown>): (params?: unknown) => Promise<unknown> {
	const method = async (params?: unknown) => call(params);
	Object.defineProperty(method, "name", { value: cap.name });
	CAPABILITY.set(method, { cap, owner });
	return method;
}

function buildWorkspace(): Record<string, unknown> {
	const re: Record<string, unknown> = {};
	for (const cap of capabilities) {
		re[cap.name] = operation("re", cap, (params) => host(`re.${cap.name}`, { kind: "capability", name: cap.name, params }));
	}
	Object.defineProperties(re, {
		rz: { enumerable: true, value: async () => new RzSession((await host("re.rz", { kind: "rz", method: "open" })) as string) },
		binary: { enumerable: true, get: () => binary },
		evidence: { enumerable: true, value: () => host("re.evidence", { kind: "evidence" }) },
		findings: { enumerable: true, value: () => host("re.findings", { kind: "findings" }) },
	});
	DESCRIBERS.set(re, () => describeWorkspace(capabilities, binary));
	return Object.freeze(re);
}

/** A connected MCP server: one async method per tool, plus close(). Named after the server so describe() reads naturally. */
function mcpServer(info: McpConnectionInfo): Record<string, unknown> {
	const server: Record<string, unknown> = {};
	const tools: CapabilityInfo[] = info.tools.map((tool) => ({ name: tool.name, description: tool.description ?? "", tier: "exec", evidence: false, schema: tool.inputSchema ?? {} }));
	for (const tool of tools) {
		const only = shorthandParam(tool);
		server[tool.name] = operation(info.name, tool, (args) => {
			// The same shorthand as re.*: a bare value fills the tool's one required (or only) parameter.
			const params = only && args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args)) ? { [only]: args } : args;
			return host(`${info.name}.${tool.name}`, { kind: "mcp.call", connection: info.id, tool: tool.name, args: params });
		});
	}
	Object.defineProperties(server, {
		name: { enumerable: true, value: info.name },
		close: { enumerable: true, value: () => host(`${info.name}.close`, { kind: "mcp.close", connection: info.id }) },
	});
	DESCRIBERS.set(server, () => describeMcpServer(info.name, tools, info.instructions));
	return Object.freeze(server);
}

function buildMcp(): Record<string, unknown> {
	const mcp = {
		servers: () => host("mcp.servers", { kind: "mcp.servers" }),
		connect: async (target: string | AdHocMcpServer) => mcpServer((await host("mcp.connect", { kind: "mcp.connect", target })) as McpConnectionInfo),
	};
	DESCRIBERS.set(mcp, () => ["mcp — MCP servers as functions (omp's own MCP client; servers come from omp's configuration, or inline).", "  servers(): Promise<Record<string, { type, target, enabled }>> — the configured servers", "  connect(server: string | { command, args?, env?, cwd? } | { url, headers? }): Promise<McpServer> — its tools become async methods; describe() the result to list them"].join("\n"));
	return Object.freeze(mcp);
}

function docFor(name: string): string | undefined {
	const source = unitSource.get(name);
	return source === undefined ? undefined : leadingDoc(source);
}

async function keptText(name?: string): Promise<string> {
	const units = await listKept(dir);
	if (name !== undefined) {
		const unit = units.find((u) => u.name === name);
		if (!unit) throw new Error(`omp-re: nothing kept as ${JSON.stringify(name)} — kept() lists what is`);
		return unit.source;
	}
	if (units.length === 0) return `nothing kept yet (${dir}): top-level functions, classes, and static consts a successful call defines are kept automatically`;
	const failed = new Map(failures.map((f) => [f.name, f.error]));
	return [
		`${units.length} kept in ${dir}:`,
		...units.map((u) => {
			const doc = leadingDoc(u.source);
			const head = u.source.replace(/^\s*(\/\*[\s\S]*?\*\/|\/\/.*\n)\s*/g, "").split("\n")[0]!.replace(/\s*\{\s*$/, "");
			return `  ${u.name} — ${head}${doc ? ` — ${doc}` : ""}${failed.has(u.name) ? ` (NOT LOADED: ${failed.get(u.name)})` : ""}`;
		}),
	].join("\n");
}

const global = globalThis as unknown as Record<string, unknown>;

async function forget(name: string): Promise<string> {
	if (typeof name !== "string" || !isUnitName(name)) throw new TypeError("omp-re: forget(name) takes a definition name");
	const existed = await forgetKept(dir, name);
	const live = !vocabulary.has(name) && Object.hasOwn(global, name);
	if (live) delete global[name];
	loaded.delete(name);
	unitSource.delete(name);
	failures = failures.filter((f) => f.name !== name);
	if (!existed && !live) return `${name} was neither kept nor defined`;
	return `forgot ${name}${existed ? "" : " (it was defined, not kept)"}`;
}

function seed(): void {
	const re = buildWorkspace();
	const write = (...args: unknown[]) => print(args);
	const names: Record<string, unknown> = {
		re,
		describe: (x: unknown = re) => describeValue(x, docFor),
		man: () =>
			manual({ toolName, binary, capabilityCount: capabilities.length, keptDir: dir, kept: [...loaded], keptFailures: failures }),
		kept: (name?: string) => keptText(name),
		forget,
		strings: Object.freeze({}),
		print: write,
		console: Object.freeze({ log: write, info: write, warn: write, error: write, debug: write, dir: write, table: write }),
		exec: (bin: string, argv: string[] = [], options: { timeout?: number } = {}) =>
			host("exec", { kind: "exec", bin: String(bin), argv: argv.map(String), ...(options.timeout ? { timeout: options.timeout } : {}) }),
		mcp: buildMcp(),
		require: createRequire(import.meta.url),
	};
	for (const [key, value] of Object.entries(names)) {
		Object.defineProperty(global, key, { value, writable: key === "strings", enumerable: false, configurable: true });
		vocabulary.add(key);
	}
}

const importModule = (specifier: string) => import(specifier);

/** Compile and evaluate a cell in this realm: indirect eval runs it in the global scope, the compiled wrapper does the rest. */
async function evaluate(code: string): Promise<{ value: unknown; definitions: Awaited<ReturnType<typeof compileCell>>["definitions"] }> {
	const cell = await compileCell(code, vocabulary);
	const geval = globalThis.eval as (source: string) => unknown;
	const fn = geval(`${cell.source}\n//# sourceURL=${toolName}-${++cells}.ts`) as (g: unknown, imp: unknown) => Promise<unknown>;
	return { value: await fn(globalThis, importModule), definitions: cell.definitions };
}

async function loadKept(): Promise<void> {
	let todo = await listKept(dir);
	const errors = new Map<string, string>();
	while (todo.length > 0) {
		const retry = [];
		for (const unit of todo) {
			try {
				await checkUnit(unit.name, unit.source);
				await evaluate(unit.source);
				loaded.add(unit.name);
				unitSource.set(unit.name, unit.source);
				errors.delete(unit.name);
			} catch (err) {
				errors.set(unit.name, errorText(err));
				retry.push(unit);
			}
		}
		if (retry.length === todo.length) break;
		todo = retry;
	}
	failures = [...errors].map(([name, error]) => ({ name, error }));
}

/** A copy of the value the host can receive, or undefined when it cannot be cloned (functions, class instances with private state, …); `shown` always carries the text. */
function cloneable(value: unknown): unknown {
	try {
		return structuredClone(value);
	} catch {
		return undefined;
	}
}

async function run(id: number, code: string, strings: Record<string, string>): Promise<void> {
	runId = id;
	global.strings = Object.freeze({ ...strings });
	try {
		let result: Awaited<ReturnType<typeof evaluate>>;
		try {
			result = await evaluate(code);
		} catch (err) {
			post({ type: "failed", runId: id, error: errorText(err), kept: [...loaded], failures });
			return;
		}
		const notes: string[] = [];
		let saved: string[] = [];
		try {
			saved = await saveDefinitions(dir, result.definitions);
			for (const def of result.definitions) {
				loaded.add(def.name);
				unitSource.set(def.name, def.source);
				failures = failures.filter((f) => f.name !== def.name);
			}
		} catch (err) {
			notes.push(`(omp-re: could not keep this call's definitions: ${errorText(err)})`);
		}
		const value = result.value;
		post({ type: "done", runId: id, value: cloneable(value), shown: value === undefined ? undefined : show(value), saved, kept: [...loaded], failures, notes });
	} finally {
		runId = null;
	}
}

port.on("message", (raw: unknown) => {
	const message = raw as ToWorker;
	switch (message.type) {
		case "init":
			toolName = message.toolName;
			dir = message.keptDir;
			capabilities = message.capabilities;
			binary = message.binary;
			seed();
			void loadKept().then(() => post({ type: "ready", kept: [...loaded], failures }));
			return;
		case "run":
			binary = message.binary;
			void run(message.runId, message.code, message.strings);
			return;
		case "reply": {
			binary = message.binary;
			const waiter = pending.get(message.callId);
			if (!waiter) return;
			pending.delete(message.callId);
			if (message.ok) waiter.resolve(message.value);
			else {
				// Rebuilt in this realm, keeping the host error's name (TypeError, RzAbortError, …) so the cell can tell them apart.
				const err = new Error(message.error.message);
				err.name = message.error.name;
				waiter.reject(err);
			}
			return;
		}
	}
});
