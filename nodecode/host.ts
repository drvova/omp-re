/**
 * A headless host for the omp-re engine.
 *
 * `extensions/re` is written against omp's ExtensionAPI: it registers tools,
 * a `/re` command and event listeners with the host it is handed. This module
 * is a second, minimal host — the part of that API omp-re actually uses — so
 * the same engine (the rizin process lifecycle, the evidence store, the audit
 * log, the report gate) runs outside omp with no fork of its logic. The
 * nodecode cell drives it through `bridge.ts`; nothing here knows nodecode.
 *
 * What a host owes the engine, and how this one pays it:
 *  - a session branch of custom entries (`appendEntry` / `getBranch`): an
 *    append-only JSONL file per session, so a restart restores the open
 *    binary, the annotations and the evidence index exactly as an omp resume
 *    does;
 *  - the `tool_call` → execute → `tool_result` pipeline, with the same
 *    blocking and result-rewriting semantics, so the audit log and the
 *    evidence store record a call made here exactly like one made in omp;
 *  - an artifact store for outputs too large for a tool result;
 *  - argv exec with a timeout and an abort signal.
 * There is no UI: `hasUI` is false, so the engine takes its own headless
 * branches, and what it would have printed is captured as the command's text.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolDefinition } from "@oh-my-pi/pi-coding-agent";
// The schema builder omp injects as `pi.zod` (see pi-coding-agent extensions/loader.ts).
import * as zod from "@oh-my-pi/omptype/zod";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import registerExtension from "../extensions/re/index.ts";

/** What one request collects from the engine's headless output paths. */
interface Sink {
	out: string[];
	err: string[];
	failed: boolean;
}

const sinks = new AsyncLocalStorage<Sink>();

let consoleCaptured = false;

/**
 * Route the engine's headless `console.log`/`console.error` into the request
 * that caused them. The engine prints its `/re` answers when there is no UI,
 * and stdout belongs to the bridge's protocol: an uncaptured line would
 * corrupt a frame. Output with no request behind it (a background reopen at
 * session start) goes to stderr, which the cell keeps as a log.
 */
export function captureConsole(): void {
	if (consoleCaptured) return;
	consoleCaptured = true;
	const render = (args: unknown[]) => args.map((a) => (typeof a === "string" ? a : Bun.inspect(a))).join(" ");
	const toOut = (...args: unknown[]) => {
		const sink = sinks.getStore();
		if (sink) sink.out.push(render(args));
		else process.stderr.write(`${render(args)}\n`);
	};
	const toErr = (...args: unknown[]) => {
		const sink = sinks.getStore();
		if (sink) sink.err.push(render(args));
		else process.stderr.write(`${render(args)}\n`);
	};
	console.log = toOut;
	console.info = toOut;
	console.debug = toErr;
	console.warn = toErr;
	console.error = toErr;
}

interface Entry {
	type: "custom";
	id: string;
	customType: string;
	data: unknown;
}

type Handler = (event: any, ctx: ExtensionContext) => unknown;

interface CommandDefinition {
	description?: string;
	handler: (args: string, ctx: any) => Promise<void> | void;
}

export interface ToolInfo {
	name: string;
	label?: string;
	description: string;
	/** omp's approval tier: "read" tools only observe, anything else changes state or runs code. */
	approval: string;
	parameters: Record<string, unknown>;
}

export interface CallResult {
	text: string;
	isError: boolean;
}

export interface HeadlessOptions {
	/** Where session branches and artifacts are kept. Defaults to `<agent dir>/re/headless`. */
	stateDir?: string;
}

/** Session ids become file names: keep the safe characters, replace the rest. */
function fileSafe(id: string): string {
	return id.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128) || "session";
}

function textOf(content: unknown): string {
	if (!Array.isArray(content)) return "";
	return content
		.filter((block): block is { type: "text"; text: string } => block?.type === "text" && typeof block.text === "string")
		.map((block) => block.text)
		.join("");
}

function messageOf(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

/** One engine instance bound to one session — omp runs the extension factory once per session, and so does this. */
export class HeadlessSession {
	readonly sessionId: string;
	readonly #dir: string;
	readonly #entriesPath: string;
	readonly #entries: Entry[] = [];
	readonly #tools = new Map<string, ToolDefinition<any, any>>();
	readonly #commands = new Map<string, CommandDefinition>();
	readonly #handlers = new Map<string, Handler[]>();
	#entryWrites: Promise<void> = Promise.resolve();
	#artifacts = 0;
	#calls = 0;
	#sessionName: string | undefined;
	#closed = false;
	readonly pi: ExtensionAPI;
	readonly ctx: ExtensionContext;

	private constructor(sessionId: string, stateDir: string) {
		this.sessionId = sessionId;
		this.#dir = join(stateDir, "sessions", fileSafe(sessionId));
		this.#entriesPath = join(this.#dir, "branch.jsonl");
		this.pi = this.#makeApi();
		this.ctx = this.#makeContext();
	}

	static async open(sessionId: string, options: HeadlessOptions = {}): Promise<HeadlessSession> {
		captureConsole();
		const stateDir = options.stateDir ?? join(getAgentDir(), "re", "headless");
		const session = new HeadlessSession(sessionId, stateDir);
		await mkdir(join(session.#dir, "artifacts"), { recursive: true });
		await session.#loadEntries();
		await registerExtension(session.pi);
		await session.#emit("session_start", {});
		return session;
	}

	async #loadEntries(): Promise<void> {
		if (!existsSync(this.#entriesPath)) return;
		const text = await readFile(this.#entriesPath, "utf8");
		for (const line of text.split("\n")) {
			if (!line.trim()) continue;
			try {
				const entry = JSON.parse(line) as Entry;
				if (entry?.type === "custom" && typeof entry.customType === "string") this.#entries.push(entry);
			} catch {
				// A torn last line (the process died mid-append) loses that one entry, never the branch.
			}
		}
	}

	#makeApi(): ExtensionAPI {
		const noop = () => {};
		const log = (level: string) => (message: unknown) => process.stderr.write(`omp-re ${level}: ${String(message)}\n`);
		const api = {
			zod,
			logger: { debug: noop, info: noop, warn: log("warn"), error: log("error") },
			registerTool: (def: ToolDefinition<any, any>) => {
				this.#tools.set(def.name, def);
			},
			getAllTools: () => [...this.#tools.values()].map((def) => ({ name: def.name, description: def.description, parameters: def.parameters })),
			registerCommand: (name: string, def: CommandDefinition) => {
				this.#commands.set(name, def);
			},
			// Presentation the headless host has no surface for.
			registerMessageRenderer: noop,
			registerShortcut: noop,
			registerFlag: noop,
			getFlag: () => undefined,
			on: (event: string, handler: Handler) => {
				const list = this.#handlers.get(event) ?? [];
				list.push(handler);
				this.#handlers.set(event, list);
			},
			appendEntry: (customType: string, data?: unknown) => {
				const entry: Entry = { type: "custom", id: `${Date.now().toString(36)}-${this.#entries.length}`, customType, data };
				this.#entries.push(entry);
				// Appends are chained so two entries written in one tick land in branch order.
				this.#entryWrites = this.#entryWrites
					.then(() => appendFile(this.#entriesPath, `${JSON.stringify(entry)}\n`))
					.catch((err) => {
						process.stderr.write(`omp-re error: could not persist a session entry: ${messageOf(err)}\n`);
					});
			},
			// A display message in omp; here it is part of what the running command says.
			sendMessage: (message: { content?: unknown; display?: boolean }) => {
				const sink = sinks.getStore();
				if (sink && message.display !== false && typeof message.content === "string") sink.out.push(message.content);
			},
			getSessionName: () => this.#sessionName,
			setSessionName: async (name: string) => {
				this.#sessionName = name;
			},
			exec: async (bin: string, argv: string[], opts?: { timeout?: number; signal?: AbortSignal; cwd?: string }) => {
				const signals = [opts?.signal, opts?.timeout ? AbortSignal.timeout(opts.timeout) : undefined].filter((s): s is AbortSignal => s !== undefined);
				const proc = Bun.spawn([bin, ...argv], {
					stdin: "ignore",
					stdout: "pipe",
					stderr: "pipe",
					...(opts?.cwd ? { cwd: opts.cwd } : {}),
					...(signals.length > 0 ? { signal: AbortSignal.any(signals) } : {}),
				});
				const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
				const code = await proc.exited;
				return { code, stdout, stderr, killed: proc.signalCode !== null };
			},
		};
		return api as unknown as ExtensionAPI;
	}

	#makeContext(): ExtensionContext {
		const noop = () => {};
		const say = (message: string, type?: string) => {
			const sink = sinks.getStore();
			if (!sink) {
				process.stderr.write(`${message}\n`);
				return;
			}
			if (type === "error") {
				sink.err.push(message);
				sink.failed = true;
			} else if (type === "warning") sink.err.push(message);
			else sink.out.push(message);
		};
		const ctx = {
			hasUI: false,
			ui: {
				notify: say,
				setStatus: noop,
				setWidget: noop,
				setWorkingMessage: noop,
				// omp prefills the input box (`/re cite`); with no input box the draft is the answer.
				setEditorText: (text: string) => say(text.trimEnd()),
				getEditorText: () => "",
				custom: async () => undefined,
			},
			sessionManager: {
				getSessionId: () => this.sessionId,
				getBranch: () => this.#entries,
				getEntries: () => this.#entries,
				saveArtifact: async (content: string, label?: string) => {
					// Evidence records keep artifact ids, and the branch outlives this process: an id must never be reused after a restart.
					const id = `${Date.now().toString(36)}-${this.#artifacts++}-${fileSafe(label ?? "omp-re")}`;
					await writeFile(this.#artifactPath(id), content);
					return id;
				},
				getArtifactPath: async (id: string) => {
					const path = this.#artifactPath(id);
					return existsSync(path) ? path : null;
				},
			},
		};
		return ctx as unknown as ExtensionContext;
	}

	#artifactPath(id: string): string {
		return join(this.#dir, "artifacts", `${fileSafe(id)}.txt`);
	}

	/**
	 * The engine names a spilled output `artifact://<id>`, an address only omp
	 * resolves. Here the artifact is a file, so the note the model reads names
	 * that file. Applied to the returned text only — the evidence hashes are
	 * taken over the tool's own content, before this.
	 */
	#resolveArtifacts(text: string): string {
		if (!text.includes("artifact://")) return text;
		return text.replace(/artifact:\/\/([A-Za-z0-9._-]+)/g, (whole, id: string) => {
			const path = this.#artifactPath(id);
			return existsSync(path) ? path : whole;
		});
	}

	/** Run every listener of `event` in registration order; the listeners' own results are handed back in that order. */
	async #emit(event: string, payload: Record<string, unknown>): Promise<unknown[]> {
		const results: unknown[] = [];
		for (const handler of this.#handlers.get(event) ?? []) results.push(await handler({ type: event, ...payload }, this.ctx));
		return results;
	}

	tools(): ToolInfo[] {
		return [...this.#tools.values()].map((def) => ({
			name: def.name,
			...(typeof def.label === "string" ? { label: def.label } : {}),
			description: def.description,
			approval: typeof def.approval === "string" ? def.approval : "exec",
			parameters: (def.parameters as { toJsonSchema(): Record<string, unknown> }).toJsonSchema(),
		}));
	}

	/**
	 * One tool call, through the same three steps omp's tool wrapper takes:
	 * `tool_call` (a listener may block it), execute, `tool_result` (a listener
	 * may rewrite the content — the evidence store appends its id this way).
	 * A failure is a result, never a rejection: the caller reads `isError`.
	 */
	async callTool(name: string, args: unknown, signal?: AbortSignal): Promise<CallResult> {
		const def = this.#tools.get(name);
		if (!def) return { text: `omp-re: no tool named ${JSON.stringify(name)} — list them with the tools request`, isError: true };
		const parsed = (def.parameters as { safeParse(data: unknown): { success: boolean; data?: unknown; error?: { message?: string } } }).safeParse(args ?? {});
		if (!parsed.success) return { text: `omp-re: ${name} was called with arguments that do not fit its schema: ${parsed.error?.message ?? "invalid arguments"}`, isError: true };
		const input = parsed.data;
		const toolCallId = `${fileSafe(this.sessionId)}-${++this.#calls}`;
		return await sinks.run({ out: [], err: [], failed: false }, async () => {
			try {
				for (const verdict of await this.#emit("tool_call", { toolName: name, toolCallId, input })) {
					const v = verdict as { block?: boolean; reason?: string } | undefined;
					if (v?.block) return { text: v.reason ?? `omp-re: ${name} was blocked`, isError: true };
				}
			} catch (err) {
				return { text: messageOf(err), isError: true };
			}
			let content: unknown[];
			let details: unknown;
			let isError = false;
			try {
				const result = (await def.execute(toolCallId, input, signal, undefined, this.ctx as any)) as { content?: unknown[]; details?: unknown; isError?: boolean };
				content = Array.isArray(result?.content) ? result.content : [];
				details = result?.details;
				isError = result?.isError === true;
			} catch (err) {
				content = [{ type: "text", text: messageOf(err) }];
				isError = true;
			}
			try {
				for (const handler of this.#handlers.get("tool_result") ?? []) {
					const rewritten = (await handler({ type: "tool_result", toolName: name, toolCallId, input, content, details, isError }, this.ctx)) as { content?: unknown[] } | undefined;
					if (Array.isArray(rewritten?.content)) content = rewritten.content;
				}
			} catch (err) {
				process.stderr.write(`omp-re error: a tool_result listener failed: ${messageOf(err)}\n`);
			}
			return { text: this.#resolveArtifacts(textOf(content)), isError };
		});
	}

	commands(): { name: string; description: string }[] {
		return [...this.#commands.entries()].map(([name, def]) => ({ name, description: def.description ?? "" }));
	}

	/**
	 * One slash command (`re`, with its subcommand line). The engine answers
	 * through notifications, display messages and — headless — the console;
	 * all three are collected into the text. Its headless failure signal is
	 * `process.exitCode`, which is read back into `isError` and cleared, so a
	 * withheld report fails this one command and not the bridge.
	 */
	async runCommand(name: string, args: string): Promise<CallResult> {
		const def = this.#commands.get(name);
		if (!def) return { text: `omp-re: no command named /${name}`, isError: true };
		const sink: Sink = { out: [], err: [], failed: false };
		const before = process.exitCode;
		process.exitCode = 0;
		try {
			await sinks.run(sink, async () => {
				await def.handler(args, this.ctx);
			});
		} catch (err) {
			sink.err.push(messageOf(err));
			sink.failed = true;
		}
		if (process.exitCode !== undefined && process.exitCode !== 0) sink.failed = true;
		process.exitCode = before ?? 0;
		const text = [...sink.out, ...sink.err].join("\n");
		return { text: text.length > 0 ? text : "(done)", isError: sink.failed };
	}

	/** Close this session's rizin and debug processes; its branch stays on disk for the next open. */
	async close(): Promise<void> {
		if (this.#closed) return;
		this.#closed = true;
		try {
			await this.#emit("session_shutdown", {});
		} catch (err) {
			process.stderr.write(`omp-re error: session shutdown: ${messageOf(err)}\n`);
		}
		await this.#entryWrites;
	}
}
