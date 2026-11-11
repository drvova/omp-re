/**
 * What the bun suites share: whether rizin and the test binary are here, the
 * names of the engine's tools, and omp's real SDK booted with the extension
 * loaded — the engine behind it is a real SBCL child, as in a session.
 */
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent";

/** Any readable binary works; /bin/ls exists on every Linux host and macOS. Override with OMPRE_TEST_BINARY. */
export const TEST_BINARY = process.env.OMPRE_TEST_BINARY ?? "/bin/ls";
/** The rizin the engine will run, as the suites can tell: OMPRE_RIZIN_PATH, or `rizin` on PATH. */
export const rizinPath = process.env.OMPRE_RIZIN_PATH?.trim() || "rizin";
export const rizinAvailable = /[\\/]/.test(rizinPath) ? existsSync(rizinPath) : Bun.which(rizinPath) !== null;
export const binaryAvailable = existsSync(TEST_BINARY);
export const canRunRizin = rizinAvailable && binaryAvailable;

/** The annotation tools: write-tier, each recorded and replayed. */
const ANNOTATE_TOOLS = [
	"rename_function",
	"rename_variable",
	"set_comment",
	"set_prototype",
	"set_variable_type",
	"define_variable",
	"define_global",
	"define_function",
	"set_calling_convention",
	"set_flag",
	"set_arch_hint",
	"set_hint",
	"set_data",
	"set_string",
	"set_format",
];

/** The tools the engine offers in every session. rizin_cli, the triage tools and rizin_debug depend on what is installed and switched on. */
export const ALWAYS_REGISTERED = [
	...ANNOTATE_TOOLS,
	"open_binary",
	"map_file",
	"export_project",
	"analyze",
	"apply_signatures",
	"create_signature",
	"record_finding",
	"adopt_finding",
	"retract_finding",
	"rizin_help",
	"rizin_command",
	"rizin_emulate",
];

const RE_TOOLS = new Set([...ALWAYS_REGISTERED, "rizin_cli", "rizin_debug", "triage_capa", "triage_floss", "triage_die", "triage_yara"]);

/** Whether `name` is one of the engine's tools, as opposed to omp's own. */
export const isReTool = (name: string): boolean => RE_TOOLS.has(name);

export function logSkip(suite: string): void {
	if (canRunRizin) return;
	const reasons = [
		...(rizinAvailable ? [] : [`rizin ("${rizinPath}") not on PATH`]),
		...(binaryAvailable ? [] : [`test binary not found at ${TEST_BINARY} (set OMPRE_TEST_BINARY)`]),
	];
	console.log(`omp-re: skipping ${suite} — ${reasons.join("; ")}`);
}

/**
 * Remove a temp dir recursively, tolerating the Windows lag between killing a
 * rizin child that held a file open and the OS releasing the handle — until
 * then `rm` throws EBUSY. Node's own maxRetries/retryDelay back-off covers it;
 * on POSIX there is nothing to retry. It is only teardown, so a residual
 * failure is swallowed rather than failing an otherwise-green test.
 */
export function rmDirSafe(dir: string): void {
	try {
		rmSync(dir, { recursive: true, force: true, maxRetries: 15, retryDelay: 100 });
	} catch {
		// A temp dir the OS will reclaim; never worth failing a green run over.
	}
}

// --- omp's SDK, with the extension loaded --------------------------------------------------

const EXTENSION = resolve(import.meta.dir, "../extensions/re");

export interface SdkHarness {
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
export async function boot(sessionManager: unknown, options: { headless?: boolean; flags?: Record<string, string> } = {}): Promise<SdkHarness> {
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
	if (extensionsResult.errors.length > 0) throw new Error(extensionsResult.errors.map((failure) => failure.error).join("\n"));
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

export const activeRe = (session: AgentSession) => session.getActiveToolNames().filter(isReTool);
export const mountedRe = (session: AgentSession) => session.getMountedXdevToolNames().filter(isReTool);

/** Run one JavaScript cell through omp's own `eval` tool, as the model does. Returns its text output (an error the cell threw comes back as its output, with isError). */
export async function evalJs(session: AgentSession, code: string): Promise<{ text: string; isError: boolean }> {
	const result = await session.getToolByName("eval")!.execute(`t-eval-${Math.random().toString(36).slice(2)}`, { language: "js", code } as never);
	const text = result.content.map((part) => (part.type === "text" ? part.text : "")).join("\n");
	return { text, isError: (result as { isError?: boolean }).isError === true };
}

/** A cell that returns the message of whatever `body` throws, or "ok". */
export const caught = (body: string) => `let m = "ok"; try { ${body} } catch (e) { m = e.message }; m`;
