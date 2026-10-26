/**
 * The `run` tool's namespace: one long-lived JavaScript realm per omp session.
 *
 * Each session (the main one and every task subagent, like its rizin process)
 * gets a `node:vm` context seeded with the namespace vocabulary — `re`,
 * `describe`, `man`, `kept`, `forget`, `strings`, `print`, `exec`, and the
 * usual Node conveniences. Cells compiled by cell.ts run in it one at a time,
 * so whatever a cell defines is there for the next. The context hangs off the
 * session's record in runtime.ts, so it follows a branch and is dropped on
 * shutdown with the rizin process.
 *
 * When a namespace is created, every kept unit (kept.ts) is loaded into it,
 * each checked to be a single definition and evaluated on its own; a unit
 * that throws is retried after the rest (it may name one loaded later), and
 * one that still fails is reported in the manual instead of stopping the
 * others. After a successful cell its definitions are saved.
 */
import { createRequire } from "node:module";
import vm from "node:vm";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { type CallScope, type CapabilityRegistry, invokeCapability } from "./capabilities.ts";
import { checkUnit, compileCell } from "./cell.ts";
import { CAPABILITY, describeValue, describeWorkspace, leadingDoc, manual } from "./describe.ts";
import { branchEntries, collectEvidence } from "./entries.ts";
import { liveFindings } from "./findings.ts";
import { formatJson } from "./format.ts";
import { forgetKept, isUnitName, keptDir, listKept, saveDefinitions } from "./kept.ts";
import { raceAbort } from "./rizin.ts";
import { ensureRizin, getState } from "./state.ts";

/** What a `run` call brings to the namespace. */
export interface RunCall extends Omit<CallScope, "calls" | "evidence"> {
	strings: Record<string, string>;
}

export interface CellOutcome {
	/** Everything the cell printed, one entry per print/console call. */
	output: string[];
	/** The last expression's value, or undefined. */
	value: unknown;
	/** Names whose definitions this cell saved. */
	kept: string[];
	scope: CallScope;
}

/** A cell that threw, with what it printed and recorded before it did. */
export class CellError extends Error {
	constructor(
		message: string,
		readonly output: string[],
		readonly scope: CallScope | null,
	) {
		super(message);
	}
}

const requireFromHere = createRequire(import.meta.url);
const importModule = (specifier: string) => import(specifier);

/** `Name: message` for anything thrown, including errors from the cell's realm (where `instanceof Error` is false). */
export function errorText(err: unknown): string {
	if (err && typeof err === "object" && "message" in err) {
		const name = (err as { name?: unknown }).name;
		const message = String((err as { message: unknown }).message);
		return typeof name === "string" && name !== "Error" && !message.startsWith(`${name}:`) ? `${name}: ${message}` : message;
	}
	return String(err);
}

/** A value as plain JSON-able data: Map/Set/bigint/functions/cycles made printable. Works on the cell realm's objects. */
function toPlain(value: unknown, seen: WeakSet<object>): unknown {
	if (typeof value === "bigint") return `${value}n`;
	if (typeof value === "function") return `[function ${value.name || "anonymous"}]`;
	if (typeof value === "symbol") return value.toString();
	if (value === undefined) return null;
	if (value === null || typeof value !== "object") return value;
	if (seen.has(value)) return "[circular]";
	seen.add(value);
	try {
		if (typeof (value as { then?: unknown }).then === "function") return "[Promise — await it]";
		const tag = Object.prototype.toString.call(value);
		if (tag === "[object Map]") return Object.fromEntries([...(value as Map<unknown, unknown>)].map(([k, v]) => [String(k), toPlain(v, seen)]));
		if (tag === "[object Set]") return [...(value as Set<unknown>)].map((v) => toPlain(v, seen));
		if (tag === "[object Error]") return errorText(value);
		if (Array.isArray(value)) return value.map((v) => toPlain(v, seen));
		if (ArrayBuffer.isView(value)) return Array.from(value as unknown as ArrayLike<number>);
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value)) out[key] = toPlain((value as Record<string, unknown>)[key], seen);
		return out;
	} finally {
		seen.delete(value);
	}
}

/** How a printed argument or the call's value reads in the result: strings verbatim, everything else as JSON (arrays one row per line). */
export function show(value: unknown): string {
	if (typeof value === "string") return value;
	if (value === undefined) return "undefined";
	const plain = toPlain(value, new WeakSet());
	return typeof plain === "string" ? plain : formatJson(plain);
}

export class ReNamespace {
	private readonly global: Record<string, unknown>;
	private readonly context: vm.Context;
	/** The running cell, read by `re.*` and `print` while it runs; null between calls. */
	private current: { scope: CallScope; output: string[] } | null = null;
	/** Cells run one at a time: each waits for the one before it. */
	private tail: Promise<unknown> = Promise.resolve();
	private cells = 0;
	private loaded = new Set<string>();
	private failures: { name: string; error: string }[] = [];
	/** Source of each kept unit this namespace knows (loaded, or saved by one of its cells), for describe() docs. */
	private readonly unitSource = new Map<string, string>();
	/** The namespace's own names (`re`, `describe`, …), which a cell may not redeclare. `strings` is replaced per call. */
	private readonly vocabulary = new Set<string>();

	private constructor(
		private readonly registry: CapabilityRegistry,
		private readonly toolName: string,
	) {
		this.global = {};
		this.context = vm.createContext(this.global, { name: "omp-re run" });
		this.seed();
	}

	/** A namespace with every kept definition loaded. */
	static async create(registry: CapabilityRegistry, toolName: string): Promise<ReNamespace> {
		const ns = new ReNamespace(registry, toolName);
		await ns.loadKept();
		return ns;
	}

	private scope(what: string): CallScope {
		if (!this.current) throw new Error(`omp-re: ${what} can only be used while a ${this.toolName} call is running — await it inside the cell`);
		return this.current.scope;
	}

	private print(args: unknown[]): void {
		this.current?.output.push(args.map(show).join(" "));
	}

	private seed(): void {
		const re: Record<string, unknown> = {};
		for (const cap of this.registry.list()) {
			// async, so a call outside a running cell rejects instead of throwing synchronously (inside a timer that would be an uncaught exception in omp's process).
			const method = async (params?: unknown) => invokeCapability(cap, params, this.scope(`re.${cap.name}`));
			Object.defineProperty(method, "name", { value: cap.name });
			CAPABILITY.set(method, cap);
			re[cap.name] = method;
		}
		Object.defineProperties(re, {
			rz: {
				enumerable: true,
				value: async () => {
					const s = this.scope("re.rz");
					return ensureRizin(s.ctx, { signal: s.signal });
				},
			},
			binary: { enumerable: true, get: () => this.binary(this.scope("re.binary").ctx) },
			evidence: { enumerable: true, value: () => collectEvidence(branchEntries(this.scope("re.evidence").ctx)) },
			findings: { enumerable: true, value: () => liveFindings(this.scope("re.findings").ctx) },
		});
		Object.freeze(re);

		const write = (...args: unknown[]) => this.print(args);
		const vocabulary: Record<string, unknown> = {
			re,
			describe: (x: unknown = re) => (x === re ? describeWorkspace(this.registry.list(), this.binary(this.scope("describe").ctx)) : describeValue(x, (name) => this.docFor(name))),
			man: () => this.manual(this.scope("man").ctx),
			kept: (name?: string) => this.keptText(name),
			forget: (name: string) => this.forget(name),
			strings: Object.freeze({}),
			print: write,
			console: Object.freeze({ log: write, info: write, warn: write, error: write, debug: write, dir: write, table: write }),
			exec: async (bin: string, argv: string[] = [], options: { timeout?: number } = {}) => {
				const s = this.scope("exec");
				return s.pi.exec(bin, argv, { signal: s.signal, ...options });
			},
			require: requireFromHere,
			setTimeout: (fn: (...a: unknown[]) => unknown, ms?: number, ...args: unknown[]) => setTimeout(this.guarded(fn), ms, ...args),
			clearTimeout,
			setInterval: (fn: (...a: unknown[]) => unknown, ms?: number, ...args: unknown[]) => setInterval(this.guarded(fn), ms, ...args),
			clearInterval,
			queueMicrotask,
			structuredClone,
			Buffer,
			TextEncoder,
			TextDecoder,
			URL,
			URLSearchParams,
			fetch,
			AbortController,
		};
		for (const [key, value] of Object.entries(vocabulary)) {
			Object.defineProperty(this.global, key, { value, writable: key === "strings", enumerable: false, configurable: true });
			this.vocabulary.add(key);
		}
	}

	/** A timer callback that cannot throw into omp's event loop: what it throws is printed into the running call's output, or dropped between calls. */
	private guarded(fn: (...args: unknown[]) => unknown): (...args: unknown[]) => void {
		return (...args) => {
			try {
				fn(...args);
			} catch (err) {
				this.print([`(timer callback threw: ${errorText(err)})`]);
			}
		};
	}

	private binary(ctx: ExtensionContext): { path: string; sha256: string | null } | null {
		const state = getState(ctx);
		return state.binaryPath ? { path: state.binaryPath, sha256: state.binarySha256 } : null;
	}

	private docFor(name: string): string | undefined {
		const source = this.unitSource.get(name);
		return source === undefined ? undefined : leadingDoc(source);
	}

	async manual(ctx: ExtensionContext): Promise<string> {
		return manual({
			toolName: this.toolName,
			binary: this.binary(ctx),
			capabilityCount: this.registry.list().length,
			keptDir: keptDir(),
			kept: [...this.loaded],
			keptFailures: this.failures,
		});
	}

	private async keptText(name?: string): Promise<string> {
		const units = await listKept();
		if (name !== undefined) {
			const unit = units.find((u) => u.name === name);
			if (!unit) throw new Error(`omp-re: nothing kept as ${JSON.stringify(name)} — kept() lists what is`);
			return unit.source;
		}
		if (units.length === 0) return `nothing kept yet (${keptDir()}): top-level functions, classes, and static consts a successful call defines are kept automatically`;
		const failed = new Map(this.failures.map((f) => [f.name, f.error]));
		return [
			`${units.length} kept in ${keptDir()}:`,
			...units.map((u) => {
				const doc = leadingDoc(u.source);
				const head = u.source.replace(/^\s*(\/\*[\s\S]*?\*\/|\/\/.*\n)\s*/g, "").split("\n")[0]!.replace(/\s*\{\s*$/, "");
				return `  ${u.name} — ${head}${doc ? ` — ${doc}` : ""}${failed.has(u.name) ? ` (NOT LOADED: ${failed.get(u.name)})` : ""}`;
			}),
		].join("\n");
	}

	private async forget(name: string): Promise<string> {
		if (typeof name !== "string" || !isUnitName(name)) throw new TypeError("omp-re: forget(name) takes a definition name");
		const existed = await forgetKept(name);
		const live = Object.hasOwn(this.global, name) && Object.getOwnPropertyDescriptor(this.global, name)?.enumerable !== false;
		if (live) delete this.global[name];
		this.loaded.delete(name);
		this.unitSource.delete(name);
		this.failures = this.failures.filter((f) => f.name !== name);
		if (!existed && !live) return `${name} was neither kept nor defined`;
		return `forgot ${name}${existed ? "" : " (it was defined, not kept)"}`;
	}

	/** Compile and evaluate a cell in this realm, returning its value and definitions. */
	private async evaluate(code: string, signal?: AbortSignal): Promise<{ value: unknown; definitions: Awaited<ReturnType<typeof compileCell>>["definitions"] }> {
		const cell = await compileCell(code, this.vocabulary);
		const fn = vm.runInContext(cell.source, this.context, { filename: `${this.toolName}-${++this.cells}.ts` }) as (g: unknown, imp: unknown) => Promise<unknown>;
		const value = await raceAbort(Promise.resolve(fn(this.global, importModule)), signal, `${this.toolName} cell`);
		return { value, definitions: cell.definitions };
	}

	private async loadKept(): Promise<void> {
		let pending = await listKept();
		const errors = new Map<string, string>();
		while (pending.length > 0) {
			const retry = [];
			for (const unit of pending) {
				try {
					await checkUnit(unit.name, unit.source);
					await this.evaluate(unit.source);
					this.loaded.add(unit.name);
					this.unitSource.set(unit.name, unit.source);
					errors.delete(unit.name);
				} catch (err) {
					errors.set(unit.name, errorText(err));
					retry.push(unit);
				}
			}
			if (retry.length === pending.length) break;
			pending = retry;
		}
		this.failures = [...errors].map(([name, error]) => ({ name, error }));
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
		const output: string[] = [];
		this.current = { scope, output };
		this.global.strings = Object.freeze({ ...strings });
		try {
			let result: Awaited<ReturnType<ReNamespace["evaluate"]>>;
			try {
				result = await this.evaluate(code, call.signal);
			} catch (err) {
				throw new CellError(errorText(err), output, scope);
			}
			let kept: string[] = [];
			try {
				kept = await saveDefinitions(result.definitions);
				for (const def of result.definitions) {
					this.loaded.add(def.name);
					this.unitSource.set(def.name, def.source);
				}
			} catch (err) {
				output.push(`(omp-re: could not keep this call's definitions: ${errorText(err)})`);
			}
			return { output, value: result.value, kept, scope };
		} finally {
			this.current = null;
		}
	}
}

/** This session's namespace, created (and its kept definitions loaded) on first use. */
export function namespaceFor(ctx: ExtensionContext, registry: CapabilityRegistry, toolName: string): Promise<ReNamespace> {
	const state = getState(ctx);
	if (!state.namespace) {
		state.namespace = ReNamespace.create(registry, toolName).catch((err) => {
			state.namespace = null;
			throw err;
		});
	}
	return state.namespace;
}
