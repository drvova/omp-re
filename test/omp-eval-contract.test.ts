/**
 * The part of omp's `eval` this plugin stands on, pinned claim by claim.
 *
 * docs/omp-eval.md describes what omp's eval does — cells and what persists,
 * `tool.<name>()`, `%load`, the `skill://`, `artifact://` and `xd://` URLs —
 * from omp's source, because omp.sh does not. This file holds that description
 * to the installed omp: each test is named for one claim of the doc, so an omp
 * release that changes one fails here in the claim's own words.
 *
 * Everything goes through omp's real SDK and real `eval` tool, as
 * test/extension-sdk.test.ts and test/recipes-eval.test.ts do. No model is
 * called and no rizin is needed: the host's behaviour is shown with a probe
 * extension registered inline (a handful of tools that answer, throw, sleep or
 * overflow on demand, and two event handlers that write down what they see),
 * not with the RE tools. What those tools and the recipes do on top of this is
 * the other two files' business.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AgentSession, ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { rmDirSafe } from "./helpers.ts";

const ROOT = resolve(import.meta.dir, "..");
const SKILLS = join(ROOT, "skills");
const RECIPES = join(SKILLS, "re-triage", "recipes.js");
const RECIPES_PY = join(SKILLS, "re-triage", "recipes.py");

/**
 * Whether omp can start its Python kernel here, by omp's own probe (eval/py/kernel.ts): a project
 * or active virtualenv, then its managed environment, then `python` or `python3` on PATH — the
 * first that runs. Forced, because under `bun test` omp answers "available" without looking.
 */
const python = await (async () => {
	const { checkPythonKernelAvailability } = await import("@oh-my-pi/pi-coding-agent/eval/py/kernel");
	const home = getAgentDir();
	const scratchHome = await mkdtemp(join(tmpdir(), "omp-re-contract-python-probe-"));
	setAgentDir(scratchHome);
	try {
		return await checkPythonKernelAvailability(tmpdir(), undefined, { forceProbe: true });
	} finally {
		setAgentDir(home);
		rmDirSafe(scratchHome);
	}
})();
if (!python.ok) console.log(`omp-re: SKIPPING the Python-kernel contract tests — omp reports its Python backend unavailable here: ${python.reason ?? "no reason given"}`);

/** omp's own bound on a tool result's text: `tools.artifactSpillThreshold`, 50 KB by default. */
const SPILL_THRESHOLD_BYTES = 50 * 1024;

// --- the probe extension -------------------------------------------------------------------

interface SeenEvent {
	kind: "call" | "result";
	tool: string;
	id: string;
	input: unknown;
	isError?: boolean;
	text?: string;
}
/** Every tool_call and tool_result the probe's handlers were handed, in order. */
const seen: SeenEvent[] = [];
/** How each c_sleep call ended: "finished", or the name of the reason its signal was aborted with. */
const sleeps: string[] = [];
/** Names on the ExtensionAPI object an extension is handed, own and inherited. */
const apiNames = new Set<string>();

const row = (i: number) => `row ${String(i).padStart(6, "0")} ${"x".repeat(40)}`;
/** `count` lines of 51 bytes each, newline included. */
const rows = (count: number) => Array.from({ length: count }, (_, i) => row(i)).join("\n");

function probe(pi: ExtensionAPI): void {
	for (let o: object | null = pi; o !== null && o !== Object.prototype; o = Object.getPrototypeOf(o)) for (const name of Object.getOwnPropertyNames(o)) apiNames.add(name);
	const z = pi.zod;
	const text = (value: string) => ({ type: "text" as const, text: value });
	const none = z.object({});
	const tool = (name: string, extra: Record<string, unknown>, execute: (id: string, params: never, signal: AbortSignal | undefined, ctx: never) => Promise<unknown>) =>
		pi.registerTool({ name, label: name, description: `contract probe: ${name}`, approval: "read", parameters: none, ...extra, execute: ((id: string, params: never, signal: AbortSignal | undefined, _update: unknown, ctx: never) => execute(id, params, signal, ctx)) as never });

	tool("c_plain", { parameters: z.object({ say: z.string().optional() }) }, async (_id, params: { say?: string }) => ({ content: [text(`plain:${params.say ?? ""}`)], details: undefined }));
	tool("c_details", {}, async () => ({ content: [text("one"), text("two")], details: { k: 1 } }));
	tool("c_required", { parameters: z.object({ must: z.string() }) }, async () => ({ content: [text("ran")], details: {} }));
	tool("c_throw", {}, async () => {
		throw new Error("c_throw: refused in the tool's own words");
	});
	tool("c_throw_rewritten", {}, async () => {
		throw new Error("the tool's message");
	});
	tool("c_iserror", {}, async () => ({ content: [text("soft failure")], details: { why: "marked" }, isError: true }));
	tool("c_blocked", {}, async () => ({ content: [text("must never run")], details: {} }));
	tool("c_inactive", { defaultInactive: true }, async () => ({ content: [text("must never run")], details: {} }));
	tool("c_essential", { loadMode: "essential" }, async () => ({ content: [text("essential ran")], details: {} }));
	tool("c_write", { approval: "write" }, async () => ({ content: [text("wrote")], details: {} }));
	tool("c_exec", { approval: undefined }, async () => ({ content: [text("ran")], details: {} }));
	tool("c_sleep", { parameters: z.object({ ms: z.number() }) }, async (_id, params: { ms: number }, signal) => {
		await new Promise<void>((done) => {
			const timer = setTimeout(() => {
				sleeps.push("finished");
				done();
			}, params.ms);
			signal?.addEventListener("abort", () => {
				clearTimeout(timer);
				sleeps.push(`aborted:${(signal.reason as Error | undefined)?.name}`);
				done();
			});
		});
		return { content: [text("slept")], details: {} };
	});
	// A result of exactly `bytes` bytes of text, with details of its own.
	tool("c_bytes", { parameters: z.object({ bytes: z.number() }) }, async (_id, params: { bytes: number }) => ({ content: [text(rows(Math.ceil(params.bytes / 51)).slice(0, params.bytes))], details: { mine: true } }));
	// What extensions/re/format.ts does past its own cap: keep the whole output as a session artifact, answer the cut text and the id.
	tool("c_spill", { parameters: z.object({ lines: z.number() }) }, async (_id, params: { lines: number }, _signal, ctx: { sessionManager: { saveArtifact(content: string, toolType: string): Promise<string | undefined> } }) => {
		const full = `header\n${rows(params.lines)}`;
		const artifactId = await ctx.sessionManager.saveArtifact(full, "c_spill");
		return { content: [text(`header\n\n[Output truncated. Full output: artifact://${artifactId}]`)], details: { truncated: true, artifactId } };
	});

	pi.on("tool_call", async (event) => {
		seen.push({ kind: "call", tool: event.toolName, id: event.toolCallId, input: event.input });
		return event.toolName === "c_blocked" ? { block: true, reason: "blocked by the probe's tool_call handler" } : undefined;
	});
	pi.on("tool_result", async (event) => {
		const body = event.content.map((part) => (part.type === "text" ? part.text : "")).join("");
		seen.push({ kind: "result", tool: event.toolName, id: event.toolCallId, input: event.input, isError: event.isError, text: body });
		// As extensions/re/evidence.ts tags a read: one more text block after the tool's own.
		if (event.toolName === "c_throw_rewritten") return { content: [{ type: "text" as const, text: "the handler's replacement" }] };
		return event.toolName === "c_details" ? { content: [...event.content, { type: "text" as const, text: "\n[tagged by tool_result]" }] } : undefined;
	});
}

// --- the harness ----------------------------------------------------------------------------

interface Cell {
	text: string;
	isError: boolean;
	/** The tool threw instead of answering: a refusal before any code ran (schema, `%load`, approval). The agent loop shows the model either as an error result. */
	thrown: boolean;
	details: Record<string, unknown> | undefined;
}

let agentDir: string;
let originalAgentDir: string;
/** The sessions' working directory: where a relative `%load` path is looked up. */
let work: string;

async function boot(sessionManager: unknown, settings?: Record<string, unknown>, skills?: unknown[]): Promise<AgentSession> {
	const sdk = await import("@oh-my-pi/pi-coding-agent");
	const { initializeExtensions } = await import("@oh-my-pi/pi-coding-agent/modes/runtime-init");
	const loaded = skills ?? (await sdk.loadSkillsFromDir({ dir: SKILLS, source: "omp-re:user" })).skills;
	const { session, extensionsResult } = await sdk.createAgentSession({
		cwd: work,
		disableExtensionDiscovery: true,
		extensions: [probe],
		sessionManager: sessionManager as never,
		skills: loaded as never,
		...(settings ? { settings: (sdk as unknown as { Settings: { isolated(overrides: Record<string, unknown>): never } }).Settings.isolated(settings) } : {}),
	});
	expect(extensionsResult.errors).toEqual([]);
	await initializeExtensions(session, { reportSendError: () => {}, reportRuntimeError: () => {} });
	return session;
}

/** Run one cell through omp's own `eval` tool, as the model does. */
async function cell(session: AgentSession, code: string, more: Record<string, unknown> = {}, signal?: AbortSignal): Promise<Cell> {
	try {
		const result = await session.getToolByName("eval")!.execute(`t-eval-${Math.random().toString(36).slice(2)}`, { language: "js", code, ...more } as never, signal);
		const text = result.content.map((part) => (part.type === "text" ? part.text : "")).join("\n");
		return { text, isError: (result as { isError?: boolean }).isError === true, thrown: false, details: result.details as Record<string, unknown> | undefined };
	} catch (error) {
		return { text: error instanceof Error ? error.message : String(error), isError: true, thrown: true, details: undefined };
	}
}
const out = async (session: AgentSession, code: string): Promise<string> => {
	const result = await cell(session, code);
	expect({ code, isError: result.isError }).toEqual({ code, isError: false });
	return result.text;
};
/** A cell that answers the message of whatever `body` throws, or "ok". */
const caught = (body: string) => `let m = "ok"; try { ${body} } catch (e) { m = e.message }; m`;
/** A cell's value as JSON, written to a file: what a cell returns is cut for a model's eyes (see the output tests), and these are compared whole. */
async function value<T>(session: AgentSession, expression: string): Promise<T> {
	const file = join(work, `value-${Math.random().toString(36).slice(2)}.json`);
	expect(await out(session, `await Bun.write(${JSON.stringify(file)}, JSON.stringify(await (async () => (${expression}))())); "written"`)).toBe("written");
	return JSON.parse(await readFile(file, "utf8")) as T;
}
const eventsOf = (name: string): SeenEvent[] => seen.filter((event) => event.tool === name);

/** The session most claims are shown on: on disk, so it has an artifact store; with the probe and this plugin's skills. */
let h: AgentSession;

beforeAll(async () => {
	originalAgentDir = getAgentDir();
	agentDir = await mkdtemp(join(tmpdir(), "omp-re-contract-"));
	work = await mkdtemp(join(tmpdir(), "omp-re-contract-cwd-"));
	setAgentDir(agentDir);
	const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
	h = await boot(SessionManager.create(work, join(agentDir, "sessions")));
	await h.sessionManager.ensureOnDisk();
});

afterAll(async () => {
	await h.dispose();
	setAgentDir(originalAgentDir);
	rmDirSafe(agentDir);
	rmDirSafe(work);
});

// --- cells ----------------------------------------------------------------------------------

describe("a cell", () => {
	test("the documented omp version is the installed one", async () => {
		const pkg = JSON.parse(await readFile(join(ROOT, "node_modules", "@oh-my-pi", "pi-coding-agent", "package.json"), "utf8")) as { version: string };
		const doc = await readFile(join(ROOT, "docs", "omp-eval.md"), "utf8");
		// When this fails, omp was upgraded: re-read docs/omp-eval.md against the new source, then change the version it names.
		expect(doc).toContain(`\`@oh-my-pi/pi-coding-agent\` **${pkg.version}**`);
	});

	test("the language is named by a required field, py or js, and nothing else is accepted", async () => {
		const ruby = await cell(h, "1", { language: "rb" });
		expect(ruby.thrown).toBe(true);
		expect(ruby.text).toStartWith('Validation failed for tool "eval": language must be "py"');
		const missing = await cell(h, "1", { language: undefined });
		expect(missing.thrown).toBe(true);
		expect(missing.text).toStartWith('Validation failed for tool "eval": language must be');
	});

	test("the value of the last expression is the cell's output; a cell with none answers (no output)", async () => {
		expect(await out(h, "1 + 1")).toBe("2");
		expect(await out(h, '"a string"')).toBe("a string");
		expect(await out(h, "void 0")).toBe("(no output)");
		// An object is shown as JSON under a display label, after anything printed.
		expect(await out(h, 'print("printed"); ({ x: 1 })')).toBe('printed\n\ndisplay[1]:\n{\n  "x": 1\n}');
	});

	test("top-level await and return work", async () => {
		expect(await out(h, "await Promise.resolve(8)")).toBe("8");
		expect(await out(h, "return 7")).toBe("7");
	});

	test("top-level const, let, var, function, class and globalThis assignments persist to later cells, and a const may be declared again", async () => {
		expect(await out(h, 'const a = 1; let b = 2; var c = 3; function f() { return 4 } class K {} globalThis.g = 5; const [d, { e }] = [6, { e: 7 }]; "set"')).toBe("set");
		expect(await out(h, '[a, b, c, f(), typeof K, g, d, e].join(" ")')).toBe("1 2 3 4 function 5 6 7");
		expect(await out(h, "const a = 10; a")).toBe("10");
	});

	test("an uncaught error is the cell's output, marked isError, with exit code 1 — and the kernel and its state survive it", async () => {
		const failed = await cell(h, 'throw new Error("boom")');
		expect(failed.thrown).toBe(false);
		expect(failed.isError).toBe(true);
		expect(failed.text).toStartWith("Error: boom\n");
		expect(failed.text).toEndWith("\n\nCommand exited with code 1");
		expect(await out(h, "g")).toBe("5");
	});

	test("the helpers are globals of the realm: print, display, log, phase, read, write, env, output, wait, tool, budget, agent, workpool, judge, judgeBatch, completion — beside Bun's own", async () => {
		const kinds = await value<Record<string, string>>(
			h,
			'Object.fromEntries(["print","display","log","phase","read","write","env","output","wait","tool","agent","workpool","judge","judgeBatch","completion","budget","Bun","fetch","require","process","console"].map((n) => [n, typeof globalThis[n]]))',
		);
		for (const name of ["print", "display", "log", "phase", "read", "write", "env", "output", "wait", "tool", "agent", "workpool", "judge", "judgeBatch", "completion", "fetch", "require"]) {
			expect({ name, kind: kinds[name] }).toEqual({ name, kind: "function" });
		}
		for (const name of ["budget", "Bun", "process", "console"]) expect({ name, kind: kinds[name] }).toEqual({ name, kind: "object" });
	});

	test("the name `re` is not taken by the host: no helper, and no prelude enabled by default, defines it", async () => {
		expect(await out(h, "typeof re")).toBe("undefined");
	});
});

// --- tool.<name>() --------------------------------------------------------------------------

describe("tool.<name>(args)", () => {
	test("reaches a discoverable tool that is mounted as an xd:// device and absent from the top-level list", async () => {
		expect(h.getMountedXdevToolNames()).toContain("c_plain");
		expect(h.getActiveToolNames()).not.toContain("c_plain");
		expect(await out(h, 'await tool.c_plain({ say: "hi" })')).toBe("plain:hi");
		// An essential tool stays top-level and is reached the same way.
		expect(h.getActiveToolNames()).toContain("c_essential");
		expect(await out(h, "(await tool.c_essential({})).text")).toBe("essential ran");
	});

	test("a result with no details comes back as a bare string", async () => {
		expect(await value<unknown>(h, 'tool.c_plain({ say: "hi" })')).toBe("plain:hi");
	});

	test("a result with details comes back as { text, details }: the text blocks joined with nothing between, the details as the tool gave them", async () => {
		expect(await value<unknown>(h, "tool.c_bytes({ bytes: 5 })")).toEqual({ text: "row 0", details: { mine: true } });
		// Two blocks from the tool, and a third appended by a tool_result handler.
		expect(await value<unknown>(h, "tool.c_details({})")).toEqual({ text: "onetwo\n[tagged by tool_result]", details: { k: 1 } });
	});

	test("a tool that throws rejects in the cell as a plain Error carrying the tool's own message", async () => {
		expect(await out(h, caught("await tool.c_throw({})"))).toBe("c_throw: refused in the tool's own words");
		expect(await out(h, 'let k; try { await tool.c_throw({}) } catch (e) { k = [e instanceof Error, e.name].join(" ") }; k')).toBe("true Error");
	});

	test("a result the tool marked isError does not throw: it comes back as { text, details, hasError: true }", async () => {
		expect(await value<unknown>(h, "tool.c_iserror({})")).toEqual({ text: "soft failure", details: { why: "marked" }, hasError: true });
	});

	test("a thrown tool whose result a tool_result handler replaced does not throw either: the replacement comes back with hasError: true", async () => {
		expect(await value<unknown>(h, "tool.c_throw_rewritten({})")).toEqual({ text: "the handler's replacement", hasError: true });
	});

	test("tool_call and tool_result fire for a call made from a cell, under the id js-<name>-<uuid>, with the arguments the tool ran with", async () => {
		seen.length = 0;
		await out(h, 'await tool.c_plain({ say: "audited" })');
		const [call, result] = eventsOf("c_plain");
		expect(eventsOf("c_plain").map((event) => event.kind)).toEqual(["call", "result"]);
		expect(call!.id).toMatch(/^js-c_plain-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
		expect(result!.id).toBe(call!.id);
		expect(call!.input).toEqual({ say: "audited" });
		expect(result).toMatchObject({ isError: false, text: "plain:audited" });
		// The cell itself is a tool call too, around the one it made.
		expect(seen.map((event) => `${event.kind} ${event.tool}`)).toEqual(["call eval", "call c_plain", "result c_plain", "result eval"]);
	});

	test("a thrown tool reaches tool_result handlers as isError with the message as its content", async () => {
		seen.length = 0;
		await out(h, caught("await tool.c_throw({})"));
		expect(eventsOf("c_throw").at(-1)).toMatchObject({ kind: "result", isError: true, text: "c_throw: refused in the tool's own words" });
	});

	test("a tool_call handler that blocks makes the call throw its reason in the cell, and the tool does not run", async () => {
		seen.length = 0;
		expect(await out(h, caught("await tool.c_blocked({})"))).toBe("blocked by the probe's tool_call handler");
		expect(eventsOf("c_blocked").map((event) => event.kind)).toEqual(["call"]);
	});

	test("a name that is not a tool, and a registered tool that is not enabled, both throw Unknown tool from js runtime", async () => {
		expect(await out(h, caught("await tool.no_such_tool({})"))).toBe("Unknown tool from js runtime: no_such_tool");
		expect(h.getToolByName("c_inactive")).toBeDefined();
		expect(await out(h, caught("await tool.c_inactive({})"))).toBe("Unknown tool from js runtime: c_inactive");
	});

	test("arguments are checked against the tool's schema before it runs; omitted arguments are {}", async () => {
		seen.length = 0;
		expect(await out(h, caught("await tool.c_required({})"))).toStartWith('Validation failed for tool "c_required":');
		expect(eventsOf("c_required")).toEqual([]); // refused before tool_call
		expect(await out(h, "await tool.c_plain()")).toBe("plain:");
	});

	test("checkpoint and rewind are refused through the bridge", async () => {
		expect(await out(h, caught("await tool.checkpoint({})"))).toBe("`checkpoint` cannot run through the eval bridge; call the direct `checkpoint` tool.");
	});

	test("calls started together run concurrently, and a call that was not awaited is still finished before the cell returns", async () => {
		const elapsed = await value<number>(h, "(async () => { const t = Date.now(); await Promise.all([tool.c_sleep({ ms: 300 }), tool.c_sleep({ ms: 300 }), tool.c_sleep({ ms: 300 })]); return Date.now() - t })()");
		expect(elapsed).toBeLessThan(800);
		sleeps.length = 0;
		expect(await out(h, 'tool.c_sleep({ ms: 200 }); "returned without awaiting"')).toBe("returned without awaiting");
		expect(sleeps).toEqual(["finished"]);
	});

	test("a result whose text is at most tools.artifactSpillThreshold (50 KB) is passed through whole", async () => {
		const result = await value<{ text: string; details: Record<string, unknown> }>(h, `tool.c_bytes({ bytes: ${SPILL_THRESHOLD_BYTES} })`);
		expect(Buffer.byteLength(result.text)).toBe(SPILL_THRESHOLD_BYTES);
		expect(result.details).toEqual({ mine: true });
	});

	test("one byte more and omp cuts the middle out, says so on a last line naming an artifact, and adds details.meta.truncation beside the tool's own details", async () => {
		seen.length = 0;
		const result = await value<{ text: string; details: { mine?: boolean; meta?: { truncation?: { direction: string; totalBytes: number; artifactId: string } } } }>(h, `tool.c_bytes({ bytes: ${SPILL_THRESHOLD_BYTES + 1} })`);
		const truncation = result.details.meta?.truncation;
		expect(result.details.mine).toBe(true);
		expect(truncation).toMatchObject({ direction: "middle", totalBytes: SPILL_THRESHOLD_BYTES + 1 });
		expect(truncation!.artifactId).toMatch(/^\d+$/);
		expect(Buffer.byteLength(result.text)).toBeLessThan(SPILL_THRESHOLD_BYTES);
		expect(result.text.split("\n").at(-1)).toMatch(new RegExp(`^\\[Showing lines 1-\\d+ and \\d+-\\d+ of \\d+; [\\d,]+ middle lines \\(.+\\) elided\\. Read artifact://${truncation!.artifactId} for full output\\]$`));
		// It is done before tool_result fires: a handler is handed the cut text, note and all.
		expect(eventsOf("c_bytes").at(-1)!.text).toBe(result.text);
		// The artifact is the whole text, and eval's read() returns it raw.
		const whole = await value<string>(h, `read("artifact://${truncation!.artifactId}")`);
		expect(Buffer.byteLength(whole)).toBe(SPILL_THRESHOLD_BYTES + 1);
	});
});

// --- approval -------------------------------------------------------------------------------

describe("approval of a call made from a cell", () => {
	test("eval itself is an exec-tier tool: under tools.approvalMode always-ask with no UI it is refused, naming tools.approval.eval", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const session = await boot(SessionManager.inMemory(join(work, "ask-1")), { "tools.approvalMode": "always-ask" });
		try {
			const refused = await cell(session, "1 + 1");
			expect(refused.thrown).toBe(true);
			expect(refused.text).toStartWith('Tool "eval" requires approval but no interactive UI available.');
			expect(refused.text).toContain("Add tools.approval.eval: allow to config");
		} finally {
			await session.dispose();
		}
	});

	test("each tool.<name>() call is approved on its own tier and policy: read runs, write is refused, and tools.approval.<name>: deny blocks before tool_call fires", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const session = await boot(SessionManager.inMemory(join(work, "ask-2")), { "tools.approvalMode": "always-ask", "tools.approval": { eval: "allow", c_exec: "deny" } });
		try {
			seen.length = 0;
			expect(await out(session, "await tool.c_plain({})")).toBe("plain:");
			expect(await out(session, caught("await tool.c_write({})"))).toStartWith('Tool "c_write" requires approval but no interactive UI available.');
			expect(await out(session, caught("await tool.c_exec({})"))).toBe('Tool "c_exec" is blocked by user policy.\nTo allow: remove "tools.approval.c_exec: deny" from config.');
			// A call awaiting approval has already been announced to tool_call handlers; a denied one never is. Neither ran.
			expect(eventsOf("c_write").map((event) => event.kind)).toEqual(["call"]);
			expect(eventsOf("c_exec")).toEqual([]);
		} finally {
			await session.dispose();
		}
	});

	test("under the default mode (yolo) every tier runs unprompted", async () => {
		expect(await out(h, "(await tool.c_write({})).text + (await tool.c_exec({})).text")).toBe("wroteran");
	});
});

// --- %load ----------------------------------------------------------------------------------

describe("%load <path>", () => {
	let lib: string;

	beforeAll(async () => {
		lib = join(work, "lib.js");
		await writeFile(lib, 'globalThis.lib = { n: 1 };\nconst libConst = "kept";\nfunction libFn() { return "fn" }\nprint("printed by the script");\n"its last expression"\n');
		await mkdir(join(work, "sp ace"), { recursive: true });
		await writeFile(join(work, "sp ace", "l.js"), "globalThis.spaced = true;\n");
	});

	test("runs the file in the kernel without echoing its source: the output is what the script printed and its last expression", async () => {
		const loaded = await cell(h, "%load lib.js");
		expect(loaded).toMatchObject({ isError: false, text: "printed by the script\nits last expression" });
		// The transcript keeps the command, not the script.
		expect((loaded.details as { cells: { code: string }[] }).cells[0]!.code).toBe("%load lib.js");
	});

	test("what the script defines at top level persists like a cell's own definitions", async () => {
		expect(await out(h, '[lib.n, libConst, libFn()].join(" ")')).toBe("1 kept fn");
	});

	test("a relative path is relative to the session's working directory; ./, an absolute path, file:// and a quoted path name the same kind of file", async () => {
		for (const form of ["lib.js", "./lib.js", lib, `file://${lib}`, '"lib.js"', `'${lib}'`]) {
			expect({ form, text: (await cell(h, `%load ${form}`)).text }).toEqual({ form, text: "printed by the script\nits last expression" });
		}
		expect((await cell(h, '%load "sp ace/l.js"')).isError).toBe(false);
		expect(await out(h, "spaced")).toBe("true");
		// Blank space around the command is not code.
		expect((await cell(h, "  %load lib.js\n")).isError).toBe(false);
	});

	test("an edited file needs another %load, and loading again runs it again", async () => {
		await writeFile(lib, "globalThis.lib = { n: 2 };\n");
		expect(await out(h, "lib.n")).toBe("1");
		expect((await cell(h, "%load lib.js")).isError).toBe(false);
		expect(await out(h, "lib.n")).toBe("2");
	});

	test("it must be the whole cell, with exactly one path", async () => {
		const withCode = await cell(h, "%load lib.js\n1 + 1");
		expect(withCode).toMatchObject({ thrown: true, text: "Use %load, %pip, %bun, and %environment as standalone cells; run subsequent code in another eval call." });
		for (const bad of ["%load", "%load sp ace/l.js"]) expect((await cell(h, bad)).text).toBe("Usage: %load <script path>. Quote paths containing spaces.");
	});

	test("a missing file is refused with the path as written and the system's reason", async () => {
		expect((await cell(h, "%load nope.js")).text).toBe(`Cannot load eval script nope.js: ENOENT: no such file or directory, open '${join(work, "nope.js")}'`);
	});

	test("a remote script is refused", async () => {
		expect((await cell(h, "%load https://example.com/x.js")).text).toBe("Eval scripts must be local. Download and inspect remote scripts before executing them.");
	});

	test("skill://<name>/<path> loads the file beside that skill's SKILL.md — how this plugin's recipes are loaded", async () => {
		const loaded = await cell(h, "%load skill://re-triage/recipes.js");
		expect(loaded.isError).toBe(false);
		expect(loaded.text).toStartWith("omp-re recipes loaded: ");
		expect(await out(h, "typeof re.triage")).toBe("function");
	});

	test("an unknown skill is refused with the names that are loaded; a file the skill does not have, with the path it resolved to", async () => {
		expect((await cell(h, "%load skill://no-such-skill/x.js")).text).toBe("Unknown skill: no-such-skill\nAvailable: re-triage");
		expect((await cell(h, "%load skill://re-triage/nope.js")).text).toBe(`Cannot load skill://re-triage/nope.js: File not found: ${join(SKILLS, "re-triage", "nope.js")}`);
	});

	test("a skill:// path cannot climb out of the skill's directory", async () => {
		// `..` is folded while the URL is parsed, so the path stays under the skill: this names skills/re-triage/README.md, which does not exist.
		expect((await cell(h, "%load skill://re-triage/../../README.md")).text).toBe(`Cannot load skill://re-triage/../../README.md: File not found: ${join(SKILLS, "re-triage", "README.md")}`);
	});

	test("local:// works: a script written with write() is loaded from the session's scratch root", async () => {
		expect(await out(h, 'await write("local://contract.js", "globalThis.viaLocal = 41 + 1;"); "written"')).toBe("written");
		expect((await cell(h, "%load local://contract.js")).isError).toBe(false);
		expect(await out(h, "viaLocal")).toBe("42");
	});

	test("a URL with no file behind it cannot be loaded", async () => {
		expect((await cell(h, "%load xd://eval")).text).toBe("Cannot load xd:// URL: no local file backs xd://eval");
	});
});

// --- internal URLs --------------------------------------------------------------------------

describe("internal URLs, read from a cell", () => {
	test('read("skill://<name>/<path>") is the file\'s text under a first line naming the file it resolved to; a bare skill://<name> is its SKILL.md', async () => {
		// A skill made for this test: its file is far under the size omp cuts a read at, whatever becomes of the plugin's own.
		const sdk = await import("@oh-my-pi/pi-coding-agent");
		const fixture = join(work, "read-fixture", "skills");
		const note = join(fixture, "contract-notes", "note.js");
		await mkdir(join(fixture, "contract-notes"), { recursive: true });
		await writeFile(join(fixture, "contract-notes", "SKILL.md"), "---\nname: contract-notes\ndescription: a skill with one small file\n---\n");
		await writeFile(note, "// line one\nglobalThis.note = 1;\n");
		const { skills } = await sdk.loadSkillsFromDir({ dir: fixture, source: "omp-re:user" });
		const session = await boot(sdk.SessionManager.inMemory(join(work, "read-fixture")), undefined, skills);
		try {
			expect(await value<string>(session, 'read("skill://contract-notes/note.js")')).toBe(`[Skill file: ${note}]\n// line one\nglobalThis.note = 1;`);
		} finally {
			await session.dispose();
		}
		expect((await value<string>(h, 'read("skill://re-triage")')).split("\n").slice(0, 3)).toEqual([`[Skill file: ${join(SKILLS, "re-triage", "SKILL.md")}]`, "---", "name: re-triage"]);
		expect(await out(h, caught('await read("skill://no-such-skill/x")'))).toBe("Unknown skill: no-such-skill\nAvailable: re-triage");
	});

	test("a skill whose name was taken is addressed by its namespace: skill://<namespace>/<name>/<path>, while the bare name stays with the holder", async () => {
		const sdk = await import("@oh-my-pi/pi-coding-agent");
		const { skills } = await sdk.loadSkillsFromDir({ dir: SKILLS, source: "omp-re:user" });
		const holder = skills.find((skill) => skill.name === "re-triage")!;
		// What omp's skill loader makes of a second, different `re-triage`: the same skill under `<namespace>/re-triage` (extensibility/skills.ts resolveCollision).
		const elsewhere = join(work, "other-plugin", "skills", "re-triage");
		await mkdir(elsewhere, { recursive: true });
		await writeFile(join(elsewhere, "SKILL.md"), "---\nname: re-triage\ndescription: another plugin's skill of the same name\n---\n");
		await writeFile(join(elsewhere, "recipes.js"), 'globalThis.fromOther = "the other plugin\'s file";\n');
		const session = await boot(sdk.SessionManager.inMemory(join(work, "collision")), undefined, [holder, { ...holder, name: "other-plugin/re-triage", baseDir: elsewhere, filePath: join(elsewhere, "SKILL.md") }]);
		try {
			expect((await value<string>(session, 'read("skill://re-triage/recipes.js")')).split("\n")[0]).toBe(`[Skill file: ${RECIPES}]`);
			expect((await cell(session, "%load skill://other-plugin/re-triage/recipes.js")).isError).toBe(false);
			expect(await out(session, "fromOther")).toBe("the other plugin's file");
		} finally {
			await session.dispose();
		}
	});

	test('read("artifact://<id>") returns, raw and whole, what an extension saved with sessionManager.saveArtifact; offset and limit select lines', async () => {
		const spilled = await value<{ text: string; details: { truncated: boolean; artifactId: string } }>(h, "tool.c_spill({ lines: 5000 })");
		const id = spilled.details.artifactId;
		expect(spilled.details.truncated).toBe(true);
		expect(id).toMatch(/^\d+$/);
		expect(await h.sessionManager.getArtifactPath(id)).toMatch(new RegExp(`/${id}\\.c_spill\\.log$`));
		const whole = await value<string>(h, `read("artifact://${id}")`);
		expect(whole).toBe(`header\n${rows(5000)}`); // past omp's own 50 KB bound on a tool result, and not cut
		expect(await value<string>(h, `read("artifact://${id}", { offset: 2, limit: 2 })`)).toBe(`${row(0)}\n${row(1)}`);
		expect(await out(h, caught('await read("artifact://999999")'))).toMatch(/^Artifact 999999 not found\. Available: /);
	});

	test("a session that is not on disk still hands out artifact ids, and none of them can be read back: No session - artifacts unavailable", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const session = await boot(SessionManager.inMemory(join(work, "memory")));
		try {
			expect(session.sessionManager.getArtifactsDir()).toBeNull();
			const spilled = await value<{ details: { artifactId: string } }>(session, "tool.c_spill({ lines: 10 })");
			expect(spilled.details.artifactId).toBe("0");
			expect(await session.sessionManager.getArtifactPath("0")).toBeNull();
			expect(await out(session, caught('await read("artifact://0")'))).toBe("No session - artifacts unavailable");
		} finally {
			await session.dispose();
		}
	});

	test('read("xd://") lists the mounted devices, read("xd://<tool>") is one tool\'s documentation, and xd://eval/helpers is where omp documents %load', async () => {
		const listing = await value<string>(h, 'read("xd://")');
		expect(listing.split("\n")[0]).toMatch(/^xd:\/\/ \d+ mounted tool devices\.$/);
		expect(listing).toMatch(/^xd:\/\/c_plain +contract probe: c_plain$/m);
		expect(await value<string>(h, 'read("xd://c_plain")')).toStartWith("# c_plain");
		const helpers = await value<string>(h, 'read("xd://eval/helpers")');
		expect(helpers).toContain("run `%load <path>` in a standalone `code` cell. Quoted paths and `local://` work; source is not echoed. Definitions persist; edited files require another `%load`.");
	});

	test('read("omp://tools/eval.md") is omp\'s own reference for eval, shipped inside the package', async () => {
		const reference = await value<string>(h, 'read("omp://tools/eval.md")');
		expect(reference).toStartWith("# eval\n");
		expect(reference).toContain("`tool.<name>(args)` for a normal session tool call");
	});
});

// --- tools.xdev -----------------------------------------------------------------------------

describe("tools.xdev", () => {
	test("off, the same tools are listed top-level, tool.<name>() is unchanged, and xd:// is not mounted", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const session = await boot(SessionManager.inMemory(join(work, "flat")), { "tools.xdev": false });
		try {
			expect(session.getMountedXdevToolNames()).toEqual([]);
			expect(session.getActiveToolNames()).toContain("c_plain");
			expect(await out(session, 'await tool.c_plain({ say: "flat" })')).toBe("plain:flat");
			expect(await out(session, caught('await read("xd://")'))).toBe("xd:// is not mounted in this session.");
		} finally {
			await session.dispose();
		}
	});
});

// --- preludes -------------------------------------------------------------------------------

describe("eval preludes", () => {
	test("are built in — browser, computer, ratchet, archive — and an extension is given no way to register one", async () => {
		const enabled = (h as unknown as { getEvalPreludes(): { name: string; exports: string[] }[] }).getEvalPreludes();
		for (const prelude of enabled) expect(["browser", "computer", "ratchet", "archive"]).toContain(prelude.name);
		// With default settings: browser and archive, each a global of its own name.
		expect(enabled.map((prelude) => prelude.name).sort()).toEqual(["archive", "browser"]);
		expect(await out(h, '[typeof browser, typeof archive].join(" ")')).not.toContain("undefined");
		expect(apiNames.has("registerTool")).toBe(true);
		expect([...apiNames].filter((name) => /prelude/i.test(name))).toEqual([]);
	});
});

// --- output ---------------------------------------------------------------------------------

describe("what a cell prints or returns is cut for the model", () => {
	test("a line wider than tools.outputMaxColumns (768 bytes) is cut, with a note naming the artifact that has it whole", async () => {
		const wide = await cell(h, '"w".repeat(3000)');
		expect(wide.isError).toBe(false);
		const note = /\n\n\[Some lines truncated to 768 bytes\. Use artifact:\/\/(\d+):raw:1-1 to read line 1 whole\]$/.exec(wide.text);
		expect(note).not.toBeNull();
		expect(wide.text.split("\n")[0]).toMatch(/^w{700,768}…$/);
		expect((await value<string>(h, `read("artifact://${note![1]}")`)).trimEnd()).toBe("w".repeat(3000));
	});

	test("past 50 KB the middle of the output is left out — a marker line stands where it was — with a note naming the artifact that has all of it", async () => {
		const long = await cell(h, 'print(Array.from({ length: 5000 }, (_, i) => "line " + i + " " + "x".repeat(40)).join("\\n"))');
		expect(long.isError).toBe(false);
		const lines = long.text.split("\n");
		const note = /^\[Showing lines \d+-5000 of 5000 \(50\.0KB limit\)\. Read artifact:\/\/(\d+) for full output\]$/.exec(lines.at(-1)!);
		expect(note).not.toBeNull();
		expect(lines[0]).toBe(`line 0 ${"x".repeat(40)}`);
		expect(lines.at(-3)).toBe(`line 4999 ${"x".repeat(40)}`);
		expect(lines.filter((line) => /^\[…\d+ln elided…\]$/.test(line)).length).toBe(1);
		expect(lines.length).toBeLessThan(2000);
		expect((await value<string>(h, `read("artifact://${note![1]}")`)).trimEnd().split("\n").length).toBe(5000);
	});
});

// --- the Python kernel ------------------------------------------------------------------------

describe.skipIf(!python.ok)("the Python kernel", () => {
	const py = (session: AgentSession, code: string, more: Record<string, unknown> = {}) => cell(session, code, { language: "py", ...more });
	const pyOut = async (session: AgentSession, code: string): Promise<string> => {
		const result = await py(session, code);
		expect({ code, isError: result.isError, text: result.isError ? result.text : "" }).toEqual({ code, isError: false, text: "" });
		return result.text;
	};
	/** A cell that prints the kind and message of whatever `statement` raises, or "ok". */
	const caughtPy = (statement: string) => `try:\n    ${statement}\n    print("ok")\nexcept Exception as error:\n    print(type(error).__name__ + ": " + str(error))`;
	/** What recipes.py does to wait for a tool call from a plain function, with and without the cell's context. */
	const SETTLE = [
		"def settle(awaitable, keep_context=True):",
		"    import threading",
		"    context = contextvars.copy_context()",
		"    outcome = {}",
		"    async def wait():",
		"        return await awaitable",
		"    def work():",
		"        try:",
		'            outcome["value"] = context.run(asyncio.run, wait()) if keep_context else asyncio.run(wait())',
		"        except BaseException as error:",
		'            outcome["error"] = error',
		"    worker = threading.Thread(target=work)",
		"    worker.start()",
		"    worker.join()",
		'    if "error" in outcome:',
		'        raise outcome["error"]',
		'    return outcome["value"]',
	].join("\n");

	test("the name re is taken in a Python cell: omp's prelude runs in the cell namespace and leaves the standard library's regex module, json, os, math and Path there", async () => {
		expect(await pyOut(h, 'print(" ".join(name + ":" + type(globals().get(name)).__name__ for name in ["re", "json", "os", "math", "asyncio", "inspect", "contextvars", "Path"]))')).toBe(
			"re:module json:module os:module math:module asyncio:module inspect:module contextvars:module Path:type",
		);
		expect(await pyOut(h, 'print(re.__name__, re.sub("a", "b", "aaa"))')).toBe("re bbb");
		// The helpers a script may count on, by the names the tool description gives.
		expect(await pyOut(h, 'print(" ".join(str(callable(globals().get(name))) for name in ["read", "write", "display", "env", "output", "log", "phase", "wait", "tool"]))')).toBe(Array(9).fill("True").join(" "));
	});

	test("tool.<name>(args) answers a coroutine; awaited, it gives what a JavaScript cell gets — a bare string, or a dict of text and details — for arguments passed as a dict, as keywords, or not at all", async () => {
		expect(await pyOut(h, 'call = tool.c_plain({"say": "hi"})\nprint(type(call).__name__, inspect.isawaitable(call))\nprint(repr(await call))')).toBe("coroutine True\n'plain:hi'");
		expect(await pyOut(h, 'print(await tool.c_plain(say="hi"), await tool.c_plain({"say": "no"}, say="yes"), repr(await tool.c_plain()))')).toBe("plain:hi plain:yes 'plain:'");
		expect(await pyOut(h, "print(json.dumps(await tool.c_details(), sort_keys=True))")).toBe('{"details": {"k": 1}, "text": "onetwo\\n[tagged by tool_result]"}');
		expect(await pyOut(h, caughtPy('await tool.c_plain("hi")'))).toBe("TypeError: tool.c_plain(...) expects a dict of arguments (got str)");
	});

	test("a tool that throws raises RuntimeError with the tool's own message; a result marked isError comes back as a dict with hasError True; a name that is no tool raises too", async () => {
		expect(await pyOut(h, caughtPy("await tool.c_throw()"))).toBe("RuntimeError: c_throw: refused in the tool's own words");
		expect(await pyOut(h, "print(json.dumps(await tool.c_iserror(), sort_keys=True))")).toBe('{"details": {"why": "marked"}, "hasError": true, "text": "soft failure"}');
		expect(await pyOut(h, caughtPy("await tool.no_such_tool()"))).toBe("RuntimeError: Unknown tool from js runtime: no_such_tool");
		expect(await pyOut(h, caughtPy("await tool.c_required()"))).toStartWith('RuntimeError: Validation failed for tool "c_required"');
	});

	test("a cell runs inside a running event loop: top-level await works and asyncio.run() is refused, so a plain function cannot wait for a tool call there", async () => {
		expect(await pyOut(h, "print(asyncio.get_running_loop().is_running())")).toBe("True");
		expect(await pyOut(h, "pending = asyncio.sleep(0)\ntry:\n    asyncio.run(pending)\nexcept RuntimeError as error:\n    print(error)\nawait pending")).toBe("asyncio.run() cannot be called from a running event loop");
	});

	test("a tool call can be settled from a plain function on another thread under a copy of the cell's context; without the copy the bridge refuses it: Missing session/run/name", async () => {
		const before = eventsOf("c_plain").length;
		expect(await pyOut(h, `${SETTLE}\nprint(settle(tool.c_plain(say="from a thread")))`)).toBe("plain:from a thread");
		// It is the same call as any other: announced to tool_call handlers, with the arguments given.
		expect(eventsOf("c_plain").slice(before).map((event) => [event.kind, event.input])).toEqual([
			["call", { say: "from a thread" }],
			["result", { say: "from a thread" }],
		]);
		expect(await pyOut(h, caughtPy('settle(tool.c_plain(say="no context"), keep_context=False)'))).toBe("RuntimeError: Missing session/run/name");
		expect(await pyOut(h, caughtPy("settle(tool.c_throw())"))).toBe("RuntimeError: c_throw: refused in the tool's own words");
	});

	test("a Python cell past its deadline is interrupted, not killed: a plain function waiting on a tool call is stopped, the call's signal is aborted, and the namespace is still there", async () => {
		expect(await pyOut(h, 'marker = "before"\nprint(marker)')).toBe("before");
		sleeps.length = 0;
		const started = Date.now();
		const late = await py(h, 'settle(tool.c_sleep({"ms": 10000}))\nprint("finished")', { timeout: 1 });
		expect(late.isError).toBe(true);
		expect(late.text).toStartWith("[eval cell timed out after 1s; kernel interrupted but remains running.");
		expect(late.text).not.toContain("finished");
		expect(Date.now() - started).toBeLessThan(8000);
		expect(sleeps).toEqual(["aborted:TimeoutError"]);
		expect(await pyOut(h, "print(marker, callable(settle))")).toBe("before True");
	}, 20_000);

	test("%load skill://<name>/<path> runs a Python file in the cell namespace: the output is what it printed, and omp sets __file__ and puts the script's directory on sys.path", async () => {
		expect(await pyOut(h, 'print("__file__" in globals(), "omp_re" in globals())')).toBe("False False");
		const loaded = await py(h, "%load skill://re-triage/recipes.py");
		expect(loaded.isError).toBe(false);
		// The source is not echoed; a script says what it did by printing.
		expect(loaded.text).toStartWith("omp-re recipes loaded: omp_re.triage, ");
		expect(loaded.text.split("\n").length).toBe(1);
		expect((loaded.details as { cells: { code: string }[] }).cells[0]!.code).toBe("%load skill://re-triage/recipes.py");
		expect(await pyOut(h, `import sys\nprint(__file__, ${JSON.stringify(join(SKILLS, "re-triage"))} in sys.path, "omp_re" in globals())`)).toBe(`${RECIPES_PY} True True`);
		// The refusals are %load's own, the same for either language.
		expect((await py(h, '%load skill://re-triage/recipes.py\nprint("more")')).text).toBe("Use %load, %pip, %bun, and %environment as standalone cells; run subsequent code in another eval call.");
		expect((await py(h, "%load skill://no-such-skill/x.py")).text).toBe("Unknown skill: no-such-skill\nAvailable: re-triage");
	});

	test('read("artifact://<id>") is synchronous in Python and returns the artifact whole; offset and limit select lines; read("skill://…") goes through the read tool', async () => {
		expect(await pyOut(h, 'spilled = await tool.c_spill({"lines": 2000})\nprint(spilled["text"].split("\\n")[0], spilled["details"]["truncated"], type(spilled["details"]["artifactId"]).__name__)')).toBe("header True str");
		expect(await pyOut(h, 'whole = read("artifact://" + spilled["details"]["artifactId"])\nprint(type(whole).__name__, len(whole.encode()), whole.count("\\n"), whole[:6], whole[-10:] == "x" * 10)')).toBe(
			`str ${"header\n".length + 2000 * (row(0).length + 1) - 1} 2000 header True`,
		);
		expect(await pyOut(h, 'print(repr(read("artifact://" + spilled["details"]["artifactId"], offset=2, limit=1)))')).toBe(`'${row(0)}\\n'`);
		expect(await pyOut(h, 'print(read("skill://re-triage/recipes.py").split("\\n")[0])')).toBe(`[Skill file: ${RECIPES_PY}]`);
	});

	test("in a session that is not on disk, read of an artifact id raises RuntimeError: No session - artifacts unavailable", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		// The directory has to exist: the Python kernel is a subprocess started in the session's working directory.
		await mkdir(join(work, "memory-py"), { recursive: true });
		const session = await boot(SessionManager.inMemory(join(work, "memory-py")));
		try {
			expect(await pyOut(session, 'spilled = await tool.c_spill({"lines": 10})\nprint(spilled["details"]["artifactId"])')).toBe("0");
			expect(await pyOut(session, caughtPy('read("artifact://0")'))).toBe("RuntimeError: No session - artifacts unavailable");
		} finally {
			await session.dispose();
		}
	});

	test("a string left as a cell's last expression is shown as its repr — one quoted line — while print() shows the text; any value is shown by its __repr__", async () => {
		expect(await pyOut(h, '"two\\nlines"')).toBe("'two\\nlines'");
		expect(await pyOut(h, 'print("two\\nlines")')).toBe("two\nlines");
		expect(await pyOut(h, 'class Shown(str):\n    def __repr__(self):\n        return str(self)\nShown("two\\nlines")')).toBe("two\nlines");
	});

	test("a line that begins with % is rewritten as a magic even inside brackets, so a script cannot start a line with a string format's %", async () => {
		const broken = await py(h, 'text = ("%d items"\n    % (5,))\nprint(text)');
		expect(broken.isError).toBe(true);
		expect(broken.text).toContain("SyntaxError");
		expect(await pyOut(h, 'text = "%d items" % (\n    5,\n)\nprint(text)')).toBe("5 items");
	});
});

// --- the kernel -----------------------------------------------------------------------------

describe("the kernel", () => {
	test("is keyed by the session's file and working directory; sessions with no file share one per directory", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		expect(h.getEvalSessionId()).toBe(`session:${h.sessionManager.getSessionFile()}:cwd:${work}`);
		const shared = join(work, "shared");
		const first = await boot(SessionManager.inMemory(shared));
		const second = await boot(SessionManager.inMemory(shared));
		try {
			expect(first.getEvalSessionId()).toBe(`cwd:${shared}`);
			expect(second.getEvalSessionId()).toBe(`cwd:${shared}`);
			expect(await out(first, 'globalThis.fromFirst = "seen"; "set"')).toBe("set");
			expect(await out(second, "fromFirst")).toBe("seen");
			expect(await out(h, "typeof fromFirst")).toBe("undefined");
		} finally {
			await first.dispose();
			await second.dispose();
		}
	});

	// The tests below each end the kernel; they come last and say what is left.

	test("reset: true starts a fresh kernel for that language before the cell runs", async () => {
		expect(await out(h, 'globalThis.marker = "before"; marker')).toBe("before");
		expect((await cell(h, "typeof marker", { reset: true })).text).toBe("undefined");
	});

	test("a cell past its deadline is killed and the kernel with it: the output says so, and every earlier definition — a %load included — is gone", async () => {
		expect((await cell(h, "%load skill://re-triage/recipes.js")).isError).toBe(false);
		expect(await out(h, 'globalThis.marker = "before"; typeof re')).toBe("object");
		const late = await cell(h, 'await new Promise((done) => setTimeout(done, 10_000)); "finished"', { timeout: 1 });
		expect(late).toMatchObject({ thrown: false, isError: true, text: "Command timed out after 1 seconds. The JS worker was force-killed and its VM state was reset; variables from earlier cells are gone." });
		expect(await out(h, '[typeof marker, typeof re].join(" ")')).toBe("undefined undefined");
	}, 15_000);

	test("time spent inside tool.<name>() counts toward the deadline, and the tool's signal is aborted with a TimeoutError when it passes", async () => {
		sleeps.length = 0;
		const started = Date.now();
		const late = await cell(h, 'await tool.c_sleep({ ms: 10_000 }); "finished"', { timeout: 1 });
		expect(late.text).toStartWith("Command timed out after 1 seconds.");
		expect(Date.now() - started).toBeLessThan(5000);
		expect(sleeps).toEqual(["aborted:TimeoutError"]);
	}, 15_000);

	test("aborting a cell kills the kernel too, and aborts the tool call it was waiting on", async () => {
		expect(await out(h, 'globalThis.marker = "before"; marker')).toBe("before");
		sleeps.length = 0;
		const stop = new AbortController();
		setTimeout(() => stop.abort(), 300);
		const stopped = await cell(h, 'await tool.c_sleep({ ms: 10_000 }); "finished"', {}, stop.signal);
		expect(stopped).toMatchObject({ thrown: false, isError: true, text: "Command aborted" });
		expect(sleeps).toEqual(["aborted:AbortError"]);
		expect(await out(h, "typeof marker")).toBe("undefined");
	}, 15_000);
});
