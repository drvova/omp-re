/**
 * What the bun suites share: whether rizin and the test binary are here, and
 * the one harness — omp's real SDK booted into a session, with this plugin's
 * extension loaded (the engine behind it a real SBCL child, as in a session)
 * or another in its place, a scratch agent directory, a screen that records
 * what is drawn on it, and cells run through omp's own `eval`.
 *
 * It reaches into omp past its extension API (`modes/runtime-init`,
 * `eval/py/kernel`, the extension runner): a test that exists to catch omp
 * moving has to stand where omp's own modes stand. All of that reaching is in
 * this file.
 */
import { afterAll, beforeAll } from "bun:test";
import { existsSync, rmSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AgentSession, ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import type { Component } from "@oh-my-pi/pi-tui";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";

export const ROOT = resolve(import.meta.dir, "..");
const EXTENSION = join(ROOT, "extensions", "re");
export const SKILLS = join(ROOT, "skills");

/** Any readable binary works; /bin/ls exists on every Linux host and macOS. Override with OMPRE_TEST_BINARY. */
export const TEST_BINARY = process.env.OMPRE_TEST_BINARY ?? "/bin/ls";
/** The rizin the engine will run, as the suites can tell: OMPRE_RIZIN_PATH, or `rizin` on PATH. */
const rizinPath = process.env.OMPRE_RIZIN_PATH?.trim() || "rizin";
const rizinAvailable = /[\\/]/.test(rizinPath) ? existsSync(rizinPath) : Bun.which(rizinPath) !== null;
const binaryAvailable = existsSync(TEST_BINARY);
export const canRunRizin = rizinAvailable && binaryAvailable;

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

/** Give the file's tests an agent directory of their own, and omp its own back after. Answers where it is, once the tests run. */
export function scratchAgentDir(name: string): () => string {
	let dir = "";
	let original = "";
	beforeAll(async () => {
		original = getAgentDir();
		dir = await mkdtemp(join(tmpdir(), `omp-re-${name}-`));
		setAgentDir(dir);
	});
	afterAll(() => {
		setAgentDir(original);
		rmDirSafe(dir);
	});
	return () => dir;
}

/**
 * Whether omp can start its Python kernel here, asked of omp: the probe `eval` itself makes
 * before a Python cell (a project or active virtualenv, then omp's managed environment, then
 * `python` or `python3` on PATH — the first that runs `import sys`). Under `bun test` omp skips
 * that probe and reports the backend available regardless, so it is forced. The agent directory
 * is a scratch one for the question.
 */
export async function pythonKernel(): Promise<{ ok: boolean; reason?: string }> {
	const { checkPythonKernelAvailability } = await import("@oh-my-pi/pi-coding-agent/eval/py/kernel");
	const home = getAgentDir();
	const scratchHome = await mkdtemp(join(tmpdir(), "omp-re-python-probe-"));
	setAgentDir(scratchHome);
	try {
		return await checkPythonKernelAvailability(tmpdir(), undefined, { forceProbe: true });
	} finally {
		setAgentDir(home);
		rmDirSafe(scratchHome);
	}
}

/** A theme that colours nothing, so what a component draws is compared as the text it is. */
export const plainTheme = new Proxy(
	{ fg: (_colour: string, text: string) => text, bg: (_colour: string, text: string) => text, bold: (text: string) => text, styledSymbol: (name: string) => `<${name}>`, spinnerFrames: [] as string[] },
	{ get: (target, name) => (name in target ? target[name as keyof typeof target] : (text: unknown) => text) },
);

export interface SdkHarness {
	session: AgentSession;
	/** What the extension told the user, each as `[level] text`; a runtime error as `[runtime] …`. */
	notes: string[];
	editor: () => string;
	/** The widget mounted under `key`, drawn at `width` with no colours; undefined when none is. */
	widget: (key: string, width?: number) => string[] | undefined;
	/** The overlays open now, oldest first: drawn with `render`, driven with `handleInput`. */
	overlays: Component[];
	shutdown: () => Promise<void>;
}

/** A screen that draws nothing and remembers everything: notifications, the editor's text, widgets, and overlays, which stay open until their component says it is done. */
function makeUi(notes: string[], editor: { text: string }, widgets: Map<string, unknown>, overlays: Component[]) {
	const noop = () => {};
	return {
		notify: (message: string, type?: string) => notes.push(`[${type ?? "info"}] ${message}`),
		setStatus: noop,
		setWidget: (key: string, widget: unknown) => void widgets.set(key, widget),
		setWorkingMessage: noop,
		setEditorText: (text: string) => {
			editor.text = text;
		},
		getEditorText: () => editor.text,
		custom: async (factory: (tui: unknown, theme: unknown, keybindings: unknown, done: (result: unknown) => void) => Component) => {
			const { promise, resolve } = Promise.withResolvers<unknown>();
			// Only the up/down/page keys are asked of the keybindings; the suites drive overlays with the keys the extension reads itself.
			const component = factory({}, plainTheme, { matches: () => false }, resolve);
			overlays.push(component);
			const result = await promise;
			overlays.splice(overlays.indexOf(component), 1);
			return result;
		},
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

export interface BootOptions {
	/** Without a UI, as `omp -p` runs. */
	headless?: boolean;
	/** Extension flags (like `--binary`), set before session_start fires. */
	flags?: Record<string, string>;
	/** Load the plugin's skills, as an installed plugin has them; or these. */
	skills?: true | unknown[];
	/** Extensions to load in place of this plugin's. */
	extensions?: ((pi: ExtensionAPI) => void)[];
	/** omp settings, isolated from the user's. */
	settings?: Record<string, unknown>;
	cwd?: string;
}

/** Boot a session through omp's SDK and extension runner, as a mode does. An extension that fails to load rejects with its error. */
export async function boot(sessionManager: unknown, options: BootOptions = {}): Promise<SdkHarness> {
	const sdk = await import("@oh-my-pi/pi-coding-agent");
	const { initializeExtensions } = await import("@oh-my-pi/pi-coding-agent/modes/runtime-init");
	const notes: string[] = [];
	const editor = { text: "" };
	const widgets = new Map<string, unknown>();
	const overlays: Component[] = [];
	const ui = makeUi(notes, editor, widgets, overlays);
	const skills = options.skills === true ? (await sdk.loadSkillsFromDir({ dir: SKILLS, source: "omp-re:user" })).skills : options.skills;
	const { session, extensionsResult, setToolUIContext } = await sdk.createAgentSession({
		cwd: options.cwd ?? tmpdir(),
		disableExtensionDiscovery: true,
		...(options.extensions ? { extensions: options.extensions } : { additionalExtensionPaths: [EXTENSION] }),
		sessionManager: sessionManager as never,
		...(skills ? { skills: skills as never } : {}),
		...(options.settings ? { settings: (sdk as unknown as { Settings: { isolated(overrides: Record<string, unknown>): never } }).Settings.isolated(options.settings) } : {}),
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
		widget: (key, width = 200) => {
			const mount = widgets.get(key) as ((tui: unknown, theme: unknown) => Component) | undefined;
			const lines = mount?.({}, plainTheme).render(width);
			return lines && [...lines];
		},
		overlays,
		shutdown: () => session.dispose(),
	};
}

/** The tools this plugin's extension registered in `session`, as opposed to omp's own and other extensions'. */
export const reTools = (session: AgentSession) => session.extensionRunner!.getAllRegisteredTools().filter((tool) => tool.extensionPath.includes(join("extensions", "re")));
const reToolNames = (session: AgentSession) => new Set(reTools(session).map((tool) => tool.definition.name));
/** Those of them in the model's top-level tool list. */
export const activeRe = (session: AgentSession) => session.getActiveToolNames().filter((name) => reToolNames(session).has(name));
/** Those of them mounted as `xd://` devices. */
export const mountedRe = (session: AgentSession) => session.getMountedXdevToolNames().filter((name) => reToolNames(session).has(name));

export interface Cell {
	text: string;
	isError: boolean;
	/** The tool threw instead of answering: a refusal before any code ran (schema, `%load`, approval). The agent loop shows the model either as an error result. */
	thrown: boolean;
	details: Record<string, unknown> | undefined;
}

/** Run one cell through omp's own `eval` tool, as the model does. An error the cell threw comes back as its output, with isError. */
export async function runCell(session: AgentSession, language: "js" | "py", code: string, more: Record<string, unknown> = {}, signal?: AbortSignal): Promise<Cell> {
	try {
		const result = await session.getToolByName("eval")!.execute(`t-eval-${Math.random().toString(36).slice(2)}`, { language, code, ...more } as never, signal);
		const text = result.content.map((part) => (part.type === "text" ? part.text : "")).join("\n");
		return { text, isError: (result as { isError?: boolean }).isError === true, thrown: false, details: result.details as Record<string, unknown> | undefined };
	} catch (error) {
		return { text: error instanceof Error ? error.message : String(error), isError: true, thrown: true, details: undefined };
	}
}
export const evalJs = (session: AgentSession, code: string) => runCell(session, "js", code);
export const evalPy = (session: AgentSession, code: string) => runCell(session, "py", code);

/** A JavaScript cell that returns the message of whatever `body` throws, or "ok". */
export const caught = (body: string) => `let m = "ok"; try { ${body} } catch (e) { m = e.message }; m`;

export async function until(holds: () => boolean, ms: number): Promise<boolean> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (holds()) return true;
		await Bun.sleep(20);
	}
	return holds();
}
