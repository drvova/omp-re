/**
 * Loads extensions/re through omp's real SDK and extension runner — the same
 * loader, tool wrappers (approval, tool_call/tool_result events), and command
 * dispatch an interactive session uses — instead of a stub ExtensionAPI.
 * Nothing here calls a model: slash commands are handled locally and tools
 * are executed straight from the session's tool registry.
 *
 * This is the suite that catches host API drift (e.g. omp 18 changing
 * getAllTools() from names to ToolInfo objects broke `/re on` while every
 * stub-based test stayed green). The rizin-free half runs in CI.
 *
 * omp-re advertises exactly one tool, `run`; every RE operation is a method
 * on `re` inside it, so these tests drive the operations through code the
 * way a model does.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { RE_ALL_TOOL_NAMES, RE_ANALYZE_TOOL_NAMES, RE_EMULATE_TOOL_NAMES, RE_FINDING_TOOL_NAMES, RE_MUTATE_TOOL_NAMES, RE_READ_TOOL_NAMES, RE_RIZIN_TOOL_NAMES, RE_SESSION_TOOL_NAMES, RE_SIGNATURE_TOOL_NAMES } from "../extensions/re/audit.ts";
import { REQUIRED_COMMANDS } from "../extensions/re/catalog.ts";
import { canRunRizin, logSkip, rmDirSafe, TEST_BINARY } from "./helpers.ts";

logSkip("extension-sdk rizin tests");

const EXTENSION = resolve(import.meta.dir, "../extensions/re");
/** The capabilities present in every session (methods on `re`). Triage, rizin_cli, and debug are conditional (binary on PATH / env opt-in), so they are excluded here. */
const ALWAYS_PRESENT = [
	...Object.keys(RE_READ_TOOL_NAMES),
	...Object.keys(RE_MUTATE_TOOL_NAMES),
	...Object.keys(RE_RIZIN_TOOL_NAMES),
	...Object.keys(RE_EMULATE_TOOL_NAMES),
	...Object.keys(RE_SIGNATURE_TOOL_NAMES),
	...Object.keys(RE_ANALYZE_TOOL_NAMES),
	...Object.keys(RE_SESSION_TOOL_NAMES),
	...Object.keys(RE_FINDING_TOOL_NAMES),
];

interface Harness {
	session: AgentSession;
	notes: string[];
	editor: () => string;
	shutdown: () => Promise<void>;
}

/** A minimal ExtensionUIContext: records what the extension tells the user, renders nothing. */
function makeUi(notes: string[], editor: { text: string }) {
	const noop = () => {};
	return {
		notify: (message: string, type?: string) => notes.push(`[${type ?? "info"}] ${message}`),
		setStatus: noop,
		setWidget: noop,
		setWorkingMessage: noop,
		setEditorText: (text: string) => {
			editor.text = text;
		},
		getEditorText: () => editor.text,
		custom: async () => undefined,
		select: async () => undefined,
		confirm: async () => true,
		input: async () => undefined,
		onTerminalInput: () => noop,
		setFooter: noop,
		setHeader: noop,
		setTitle: noop,
		pasteToEditor: noop,
		editor: async () => undefined,
		addAutocompleteProvider: noop,
		setEditorComponent: noop,
		getAllThemes: async () => [],
		getTheme: async () => undefined,
		setTheme: async () => ({ success: true }),
		getToolsExpanded: () => false,
		setToolsExpanded: noop,
	};
}

async function boot(sessionManager: unknown): Promise<Harness> {
	const sdk = await import("@oh-my-pi/pi-coding-agent");
	const { initializeExtensions } = await import("@oh-my-pi/pi-coding-agent/modes/runtime-init");
	const notes: string[] = [];
	const editor = { text: "" };
	const ui = makeUi(notes, editor);
	const { session, extensionsResult, setToolUIContext } = await sdk.createAgentSession({
		cwd: tmpdir(),
		additionalExtensionPaths: [EXTENSION],
		disableExtensionDiscovery: true,
		sessionManager: sessionManager as never,
	});
	expect(extensionsResult.errors).toEqual([]);
	setToolUIContext(ui as never, false);
	await initializeExtensions(session, {
		reportSendError: () => {},
		reportRuntimeError: (error: { error: string }) => notes.push(`[runtime] ${error.error}`),
		uiContext: ui as never,
	});
	return {
		session,
		notes,
		editor: () => editor.text,
		shutdown: () => session.dispose(),
	};
}

const activeRe = (session: AgentSession) => session.getActiveToolNames().filter((name) => RE_ALL_TOOL_NAMES[name]);

/** Run one cell through the `run` tool, as a model's tool call would. Returns the result text; a failing cell rejects. */
async function run(session: AgentSession, code: string, strings?: Record<string, string>): Promise<string> {
	const result = await session.getToolByName("run")!.execute(`t-run-${Math.random().toString(36).slice(2)}`, strings ? { code, strings } : { code });
	const block = result.content[0];
	return block?.type === "text" ? block.text : "";
}

let agentDir: string;
let originalAgentDir: string;
const originalKeptDir = process.env.OMPRE_KEPT_DIR;

beforeAll(async () => {
	originalAgentDir = getAgentDir();
	agentDir = await mkdtemp(join(tmpdir(), "omp-re-sdk-test-"));
	setAgentDir(agentDir);
	// Kept definitions go to a throwaway directory, never a real user's.
	process.env.OMPRE_KEPT_DIR = join(agentDir, "kept");
});

afterAll(async () => {
	setAgentDir(originalAgentDir);
	if (originalKeptDir === undefined) delete process.env.OMPRE_KEPT_DIR;
	else process.env.OMPRE_KEPT_DIR = originalKeptDir;
	rmDirSafe(agentDir);
});

describe("loaded by omp's SDK (no rizin needed)", () => {
	let h: Harness;

	beforeAll(async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		h = await boot(SessionManager.inMemory());
	});

	afterAll(async () => {
		await h.shutdown();
	});

	test("advertises exactly one tool, run, and it is active", () => {
		// Filtered to this extension: omp's own built-in extensions register tools through the same runner.
		const registered = h.session.extensionRunner!
			.getAllRegisteredTools()
			.filter((tool) => resolve(tool.extensionPath).startsWith(EXTENSION))
			.map((tool) => tool.definition.name);
		expect(registered).toEqual(["run"]);
		expect(activeRe(h.session)).toEqual(["run"]);
		for (const name of ALWAYS_PRESENT) expect(h.session.getToolByName(name)).toBeUndefined();
	});

	test("empty code returns the manual: the namespace vocabulary, the security note, and what the project offers", async () => {
		const text = await run(h.session, "");
		for (const word of ["re ", "describe(x)", "man()", "kept(name?)", "forget(name)", "strings", "SECURITY", "sandbox", "open_binary"]) expect(text).toContain(word);
		expect(text).toMatch(/capabilities: \d+ live/);
	});

	test("describe(re) lists every always-present capability with a signature", async () => {
		const text = await run(h.session, "describe(re)");
		for (const name of ALWAYS_PRESENT) expect(text).toContain(`  ${name}(`);
		expect(text).toContain("decompile_function({ addr: string })");
		expect(await run(h.session, "describe(re.rename_function)")).toContain("new: string");
	});

	test("a helper defined in one call is reusable in the next without being redefined", async () => {
		expect(await run(h.session, "function sdkTwice(x: number): number { return x * 2 }\nconst sdkBase = 20")).toContain("kept sdkTwice, sdkBase");
		expect(await run(h.session, "sdkTwice(sdkBase) + 2")).toContain("42");
		const rule = 'rule x { strings: $a = "\\x41`${}" condition: $a }';
		expect(await run(h.session, "strings.rule", { rule })).toBe(`ran\n${rule}`);
	});

	test("/re off deactivates the run tool and /re on brings it back", async () => {
		await h.session.prompt("/re off");
		expect(activeRe(h.session)).toEqual([]);
		await h.session.prompt("/re on");
		expect(activeRe(h.session)).toEqual(["run"]);
		expect(h.notes.at(-1)).toBe("[info] omp-re: RE tools enabled for this session");
	});

	test("/re completes subcommands", () => {
		const command = h.session.extensionRunner!.getCommand("re")!;
		expect(command.getArgumentCompletions!("st")).toEqual([
			expect.objectContaining({ value: "strings ", label: "strings" }),
			expect.objectContaining({ value: "status ", label: "status" }),
		]);
	});

	test("bare /re shows help, an unknown subcommand is an error, and undo with nothing open says so", async () => {
		await h.session.prompt("/re");
		expect(h.notes.at(-1)).toContain("/re open <path>      open a binary");
		await h.session.prompt("/re bogus");
		expect(h.notes.at(-1)).toBe('[error] omp-re: unknown /re subcommand "bogus" — try /re help');
		await h.session.prompt("/re undo");
		expect(h.notes.at(-1)).toBe("[error] omp-re: no annotation left to undo");
	});

	test("a capability called with no binary open fails with omp-re's guidance, and the code can catch it", async () => {
		await expect(run(h.session, "await re.list_functions()")).rejects.toThrow("omp-re: no binary open");
		expect(await run(h.session, "try { await re.list_functions() } catch (e) { print('caught:', e.message) }")).toContain("caught: omp-re: no binary open");
	});
});

describe.skipIf(!canRunRizin)("loaded by omp's SDK, against rizin", () => {
	// Opens the binary (full `aaa`) once, then replays into a freshly reopened
	// session (another `aaa`); on a cold CI/container host each analysis is a
	// few seconds, so the default 5s budget is too tight.
	test("open, annotate, and resume: the reopened session replays the annotation into a fresh rizin", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const sessionDir = join(agentDir, "sessions");
		const first = await boot(SessionManager.create(tmpdir(), sessionDir));
		await first.session.sessionManager.ensureOnDisk();
		await run(first.session, `await re.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
		await run(first.session, 'await re.rename_function({ addr: "main", new: "omp_re_sdk_main" })');
		const file = first.session.sessionManager.getSessionFile()!;
		await first.shutdown();

		const second = await boot(await SessionManager.open(file));
		try {
			const result = await run(second.session, 'await re.get_function("omp_re_sdk_main")');
			expect(result).toMatch(/^ran · 1 re call · 1 evidence\nomp_re_sdk_main at 0x/);
			expect(second.notes.filter((n) => n.startsWith("[runtime]"))).toEqual([]);
		} finally {
			await second.shutdown();
		}
	}, 30_000);

	test("/re status reports the rizin compatibility check, and rizin_command runs through the host", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const h = await boot(SessionManager.inMemory());
		try {
			await run(h.session, `await re.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
			await h.session.prompt("/re status");
			// The count is REQUIRED_COMMANDS.length, which grows as tool families
			// are added; assert the shape, not a frozen number.
			expect(h.notes.at(-1)).toContain(`rizin commands: all ${REQUIRED_COMMANDS.length} omp-re sends are present`);
			const result = await run(h.session, 'await re.rizin_command({ command: "pdsf", addr: "main" })');
			expect(result).toContain("\nrizin> pdsf @ main\n");
			expect(result).toMatch(/evidence recorded \(cite in re\.record_finding\): [0-9a-f]{8} rizin_command/);
			// rizin_cli registers through the real runner when the rz-* tools are present (they ship with rizin).
			expect(await run(h.session, "typeof re.rizin_cli")).toContain("function");
		} finally {
			await h.shutdown();
		}
	});

	test("the debugger registers through the real runner only when opted in, and its enum schema loads", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const off = await boot(SessionManager.inMemory());
		try {
			expect(await run(off.session, "typeof re.rizin_debug")).toContain("undefined");
		} finally {
			await off.shutdown();
		}

		const prev = process.env.OMPRE_ENABLE_DEBUGGER;
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		const on = await boot(SessionManager.inMemory());
		try {
			expect(await run(on.session, "describe(re.rizin_debug)")).toContain("action:");
			await run(on.session, `await re.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
			expect(await run(on.session, 'await re.rizin_debug({ action: "start" })')).toContain("RUNNING under a debugger");
			await run(on.session, 'await re.rizin_debug({ action: "stop" })');
		} finally {
			await on.shutdown();
			if (prev === undefined) delete process.env.OMPRE_ENABLE_DEBUGGER;
			else process.env.OMPRE_ENABLE_DEBUGGER = prev;
		}
	}, 30_000); // two full SDK boots plus a real launch; the default 5s is too tight
});
