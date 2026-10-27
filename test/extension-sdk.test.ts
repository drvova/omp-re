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
 * Every RE tool is `discoverable` (render.ts `RE_LOAD_MODE`), so omp mounts it
 * as an `xd://` device rather than listing it top-level, and the model drives
 * it from omp's own `eval` tool as `await tool.<name>({ ... })`. These tests go
 * through that same path.
 */
import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { RE_ALL_TOOL_NAMES, RE_ANALYZE_TOOL_NAMES, RE_EMULATE_TOOL_NAMES, RE_MUTATE_TOOL_NAMES, RE_READ_TOOL_NAMES, RE_RIZIN_TOOL_NAMES, RE_SESSION_TOOL_NAMES, RE_SIGNATURE_TOOL_NAMES } from "../extensions/re/audit.ts";
import { REQUIRED_COMMANDS } from "../extensions/re/catalog.ts";
import { canRunRizin, logSkip, rmDirSafe, TEST_BINARY } from "./helpers.ts";

logSkip("extension-sdk rizin tests");

const EXTENSION = resolve(import.meta.dir, "../extensions/re");
/** The tools registered unconditionally in every session. Triage, rizin_cli, and debug are conditional (binary on PATH / env opt-in), so they are excluded here. */
const ALWAYS_REGISTERED = [
	...Object.keys(RE_READ_TOOL_NAMES),
	...Object.keys(RE_MUTATE_TOOL_NAMES),
	...Object.keys(RE_RIZIN_TOOL_NAMES),
	...Object.keys(RE_EMULATE_TOOL_NAMES),
	...Object.keys(RE_SIGNATURE_TOOL_NAMES),
	...Object.keys(RE_ANALYZE_TOOL_NAMES),
	...Object.keys(RE_SESSION_TOOL_NAMES),
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

/**
 * Boot a session with the extension loaded. `headless` boots without a UI, as `omp -p` runs; `flags` sets
 * extension flags (like `--binary`) before session_start fires.
 */
async function boot(sessionManager: unknown, options: { headless?: boolean; flags?: Record<string, string> } = {}): Promise<Harness> {
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
	for (const [name, value] of Object.entries(options.flags ?? {})) session.extensionRunner!.setFlagValue(name, value);
	if (!options.headless) setToolUIContext(ui as never, false);
	await initializeExtensions(session, {
		reportSendError: () => {},
		reportRuntimeError: (error: { error: string }) => notes.push(`[runtime] ${error.error}`),
		...(options.headless ? {} : { uiContext: ui as never }),
	});
	return {
		session,
		notes,
		editor: () => editor.text,
		shutdown: () => session.dispose(),
	};
}

const activeRe = (session: AgentSession) => session.getActiveToolNames().filter((name) => RE_ALL_TOOL_NAMES[name]);
const mountedRe = (session: AgentSession) => session.getMountedXdevToolNames().filter((name) => RE_ALL_TOOL_NAMES[name]);

/** Run one JavaScript cell through omp's own `eval` tool, as the model does. Returns its text output (an error the cell threw comes back as its output, with isError). */
async function evalJs(session: AgentSession, code: string): Promise<{ text: string; isError: boolean }> {
	const result = await session.getToolByName("eval")!.execute(`t-eval-${Math.random().toString(36).slice(2)}`, { language: "js", code } as never);
	const text = result.content.map((part) => (part.type === "text" ? part.text : "")).join("\n");
	return { text, isError: (result as { isError?: boolean }).isError === true };
}

/** A cell that returns the message of whatever `body` throws, or "ok". */
const caught = (body: string) => `let m = "ok"; try { ${body} } catch (e) { m = e.message }; m`;

let agentDir: string;
let originalAgentDir: string;

beforeAll(async () => {
	originalAgentDir = getAgentDir();
	agentDir = await mkdtemp(join(tmpdir(), "omp-re-sdk-test-"));
	setAgentDir(agentDir);
});

afterAll(async () => {
	setAgentDir(originalAgentDir);
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

	test("registers every non-triage RE tool as an xd:// device — none in the top-level tool list", () => {
		for (const name of ALWAYS_REGISTERED) expect(h.session.getToolByName(name)).toBeDefined();
		expect(activeRe(h.session)).toEqual([]);
		expect(mountedRe(h.session).sort()).toEqual(expect.arrayContaining(ALWAYS_REGISTERED.sort()));
	});

	test("omp's eval reaches an RE tool as tool.<name>(), and its error is catchable in the cell", async () => {
		expect((await evalJs(h.session, caught("await tool.list_functions({})"))).text).toBe("omp-re: no binary open — use /re open <path>, open_binary, or --binary <path> first");
	});

	test("/re off refuses RE tool calls from eval while the devices stay mounted, and /re on lifts it", async () => {
		await h.session.prompt("/re off");
		expect((await evalJs(h.session, caught("await tool.hash_binary({})"))).text).toBe("omp-re: RE tools are off for this session — the user can re-enable them with /re on");
		expect(mountedRe(h.session).sort()).toEqual(expect.arrayContaining(ALWAYS_REGISTERED.sort()));
		await h.session.prompt("/re on");
		expect(h.notes.at(-1)).toBe("[info] omp-re: RE tools enabled for this session");
		expect((await evalJs(h.session, caught("await tool.hash_binary({})"))).text).toContain("omp-re: no binary open");
		expect(activeRe(h.session)).toEqual([]);
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

	test("headless (omp -p), a /re error goes to stderr with a non-zero exit code instead of vanishing", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const headless = await boot(SessionManager.inMemory(), { headless: true });
		const errors: string[] = [];
		const logs: string[] = [];
		const error = spyOn(console, "error").mockImplementation((...args: unknown[]) => void errors.push(args.join(" ")));
		const log = spyOn(console, "log").mockImplementation((...args: unknown[]) => void logs.push(args.join(" ")));
		const exitCode = process.exitCode;
		try {
			await headless.session.prompt("/re bogus");
			expect(errors).toContain('omp-re: unknown /re subcommand "bogus" — try /re help');
			expect(process.exitCode).toBe(1);
			await headless.session.prompt("/re on");
			expect(logs).toContain("omp-re: RE tools enabled for this session");
		} finally {
			error.mockRestore();
			log.mockRestore();
			process.exitCode = exitCode; // this test's deliberate failure must not fail the test run
			await headless.shutdown();
		}
	});

	test("a tool called with no binary open fails with omp-re's guidance", async () => {
		await expect(h.session.getToolByName("list_functions")!.execute("t-nobin", {})).rejects.toThrow("omp-re: no binary open");
	});
});

describe.skipIf(!canRunRizin)("loaded by omp's SDK, against rizin", () => {
	// Opens the binary (full `aaa`) once, then replays into a freshly reopened
	// session (another `aaa`); on a cold CI/container host each analysis is a
	// few seconds, so the default 5s budget is too tight.
	test("open, annotate, and resume through eval: the reopened session replays the annotation into a fresh rizin", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const sessionDir = join(agentDir, "sessions");
		const first = await boot(SessionManager.create(tmpdir(), sessionDir));
		await first.session.sessionManager.ensureOnDisk();

		const opened = await evalJs(first.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })\nawait tool.rename_function({ addr: "main", new: "omp_re_sdk_main" })`);
		expect(opened.isError).toBe(false);
		const file = first.session.sessionManager.getSessionFile()!;
		await first.shutdown();

		const second = await boot(await SessionManager.open(file));
		try {
			// A call made from eval goes through omp's tool wrapper, so the evidence hook records it and tags what the cell gets
			// back. A tool with details comes back to the cell as { text, details }.
			const result = await evalJs(second.session, '(await tool.get_function({ target: "omp_re_sdk_main" })).text');
			expect(result.text).toMatch(/^omp_re_sdk_main at 0x/);
			const tag = result.text.match(/\[evidence ([0-9a-f]{8}) — cite it in record_finding\]/);
			expect(tag).not.toBeNull();
			const recorded = second.session.sessionManager
				.getEntries()
				.filter((e) => e.type === "custom" && (e as { customType?: string }).customType === "re.evidence")
				.map((e) => (e as { data?: { id: string; tool: string } }).data!);
			expect(recorded).toContainEqual(expect.objectContaining({ tool: "get_function", id: expect.stringMatching(new RegExp(`^${tag![1]}`)) }));
			// The tag sits on its own last line (eval joins text blocks with no separator), so a list tool's body parses.
			const rows = await evalJs(second.session, 'const t = (await tool.list_functions({ limit: 2 })).text; JSON.parse(t.split("\\n").slice(1, -1).join("\\n")).length');
			expect(rows.text).toBe("2");
			expect(second.notes.filter((n) => n.startsWith("[runtime]"))).toEqual([]);
		} finally {
			await second.shutdown();
		}
	}, 30_000);

	test("a tool call made while --binary is still analyzing waits for that open instead of failing", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		// session_start opens the binary in the background; the call below is made before that open can have finished.
		const h = await boot(SessionManager.inMemory(), { flags: { binary: TEST_BINARY } });
		try {
			const result = await evalJs(h.session, "(await tool.hash_binary({})).text");
			expect(result.text).toMatch(/^sha256=[0-9a-f]{64}$/m);
		} finally {
			await h.shutdown();
		}
	}, 30_000);

	test("/re status reports the rizin compatibility check, and rizin_command runs through the host", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const h = await boot(SessionManager.inMemory());
		try {
			await evalJs(h.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
			await h.session.prompt("/re status");
			// The count is REQUIRED_COMMANDS.length, which grows as tool families
			// are added; assert the shape, not a frozen number.
			expect(h.notes.at(-1)).toContain(`rizin commands: all ${REQUIRED_COMMANDS.length} omp-re sends are present`);
			const result = await evalJs(h.session, '(await tool.rizin_command({ command: "pdsf", addr: "main" })).text');
			expect(result.text.startsWith("rizin> pdsf @ main\n")).toBe(true);
			// rizin_cli registers through the real runner when the rz-* tools are present (they ship with rizin).
			expect(h.session.getToolByName("rizin_cli")).toBeDefined();
		} finally {
			await h.shutdown();
		}
	});

	test("the debugger registers through the real runner only when opted in, and its enum schema loads", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const off = await boot(SessionManager.inMemory());
		try {
			expect(off.session.getToolByName("rizin_debug")).toBeUndefined();
		} finally {
			await off.shutdown();
		}

		const prev = process.env.OMPRE_ENABLE_DEBUGGER;
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		const on = await boot(SessionManager.inMemory());
		try {
			expect(on.session.getToolByName("rizin_debug")).toBeDefined();
			await evalJs(on.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`);
			expect((await evalJs(on.session, '(await tool.rizin_debug({ action: "start" })).text')).text).toContain("RUNNING under a debugger");
			await evalJs(on.session, 'await tool.rizin_debug({ action: "stop" })');
		} finally {
			await on.shutdown();
			if (prev === undefined) delete process.env.OMPRE_ENABLE_DEBUGGER;
			else process.env.OMPRE_ENABLE_DEBUGGER = prev;
		}
	}, 30_000); // two full SDK boots plus a real launch; the default 5s is too tight
});
