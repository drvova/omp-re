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
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { RE_ALL_TOOL_NAMES } from "../extensions/re/audit.ts";
import { canRunRizin, logSkip, TEST_BINARY } from "./helpers.ts";

logSkip("extension-sdk rizin tests");

const EXTENSION = resolve(import.meta.dir, "../extensions/re");
const ALWAYS_REGISTERED = Object.keys(RE_ALL_TOOL_NAMES).filter((name) => !name.startsWith("triage_"));

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

let agentDir: string;
let originalAgentDir: string;

beforeAll(async () => {
	originalAgentDir = getAgentDir();
	agentDir = await mkdtemp(join(tmpdir(), "omp-re-sdk-test-"));
	setAgentDir(agentDir);
});

afterAll(async () => {
	setAgentDir(originalAgentDir);
	await rm(agentDir, { recursive: true, force: true });
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

	test("registers every non-triage RE tool, all active", () => {
		for (const name of ALWAYS_REGISTERED) expect(h.session.getToolByName(name)).toBeDefined();
		expect(activeRe(h.session).sort()).toEqual(expect.arrayContaining(ALWAYS_REGISTERED.sort()));
	});

	test("/re off deactivates every RE tool and /re on brings them all back", async () => {
		await h.session.prompt("/re off");
		expect(activeRe(h.session)).toEqual([]);
		await h.session.prompt("/re on");
		expect(activeRe(h.session).sort()).toEqual(expect.arrayContaining(ALWAYS_REGISTERED.sort()));
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

	test("a tool called with no binary open fails with omp-re's guidance", async () => {
		await expect(h.session.getToolByName("list_functions")!.execute("t-nobin", {})).rejects.toThrow("omp-re: no binary open");
	});
});

describe.skipIf(!canRunRizin)("loaded by omp's SDK, against rizin", () => {
	test("open, annotate, and resume: the reopened session replays the annotation into a fresh rizin", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const sessionDir = join(agentDir, "sessions");
		const first = await boot(SessionManager.create(tmpdir(), sessionDir));
		await first.session.sessionManager.ensureOnDisk();
		const run = (h: Harness, name: string, params: Record<string, unknown>) => h.session.getToolByName(name)!.execute(`t-${name}`, params);

		await run(first, "open_binary", { path: TEST_BINARY });
		await run(first, "rename_function", { addr: "main", new: "omp_re_sdk_main" });
		const file = first.session.sessionManager.getSessionFile()!;
		await first.shutdown();

		const second = await boot(await SessionManager.open(file));
		try {
			const result = await run(second, "get_function", { target: "omp_re_sdk_main" });
			expect(result.content[0]?.type === "text" && result.content[0].text.startsWith("omp_re_sdk_main at 0x")).toBe(true);
			expect(second.notes.filter((n) => n.startsWith("[runtime]"))).toEqual([]);
		} finally {
			await second.shutdown();
		}
	});
});
