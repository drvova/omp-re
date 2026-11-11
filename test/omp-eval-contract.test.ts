/**
 * The part of omp's `eval` this plugin stands on, pinned claim by claim.
 *
 * docs/omp-eval.md describes what omp's eval does — cells and what persists,
 * what a kernel is and what it knows of its session, `%load`, the `skill://`,
 * `artifact://` and `xd://` URLs — from omp's source, because omp.sh does
 * not. This file holds that description to the installed omp: each test is
 * named for one claim of the doc, so an omp release that changes one fails
 * here in the claim's own words.
 *
 * Everything goes through omp's real SDK and real `eval` tool, as
 * test/extension-sdk.test.ts and test/recipes-eval.test.ts do. No model is
 * called and no rizin is needed: the host's behaviour is shown with a probe
 * extension registered inline — two tools, a loopback listener of its own,
 * and event handlers that write down what they see — not with the plugin's
 * extension. What the plugin does on top of this is the other files'
 * business.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentSession, ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { boot as bootSession, type Cell, caught, pythonKernel, rmDirSafe, ROOT, runCell, scratchAgentDir, SKILLS, until } from "./helpers.ts";

const RECIPES = join(SKILLS, "re-triage", "recipes.js");
const RECIPES_PY = join(SKILLS, "re-triage", "recipes.py");

const python = await pythonKernel();
if (!python.ok) console.log(`omp-re: SKIPPING the Python-kernel contract tests — omp reports its Python backend unavailable here: ${python.reason ?? "no reason given"}`);

// --- the probe extension -------------------------------------------------------------------

interface SeenEvent {
	kind: "call" | "result";
	tool: string;
	id: string;
	input: unknown;
	/** The file of the session the handler's context is for. */
	sessionFile?: string;
	isError?: boolean;
	text?: string;
}
/** Every tool_call and tool_result the probe's handlers were handed, in order. */
const seen: SeenEvent[] = [];
/** Names on the ExtensionAPI object an extension is handed, own and inherited. */
const apiNames = new Set<string>();

/**
 * A loopback listener in omp's process, as the plugin's is (extensions/re/bridge.ts): it wants a token, answers
 * `/quick` at once and `/slow` never, and writes down every request it took and every one whose asker hung up.
 */
const listener = { url: "", token: `probe-${crypto.randomUUID()}`, took: [] as string[], hungUp: [] as string[], stop: () => {} };
function listen(): void {
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		idleTimeout: 0,
		async fetch(request) {
			if (request.headers.get("authorization") !== `Bearer ${listener.token}`) return new Response("no token", { status: 401 });
			const { pathname, searchParams } = new URL(request.url);
			const who = searchParams.get("who") ?? "?";
			listener.took.push(`${request.method} ${pathname} ${who} ${await request.text()}`);
			if (pathname === "/slow") {
				request.signal.addEventListener("abort", () => listener.hungUp.push(who));
				await new Promise(() => {});
			}
			return Response.json({ ok: true });
		},
	});
	listener.url = `http://127.0.0.1:${server.port}`;
	listener.stop = () => void server.stop(true);
}
/** A JavaScript expression that asks the listener with node:http, as the plugin's library does, and answers the reply's text. */
const jsAsk = (path: string) =>
	`await new Promise((done, failed) => { const request = require("node:http").request(${JSON.stringify("URL")} + ${JSON.stringify(path)}, { method: "POST", agent: false, headers: { authorization: ${JSON.stringify("TOKEN")} } }, (response) => { let text = ""; response.on("data", (chunk) => (text += chunk)); response.on("end", () => done(text)); }); request.on("error", failed); request.end("{}"); })`
		.replace('"URL"', JSON.stringify(listener.url))
		.replace('"TOKEN"', JSON.stringify(`Bearer ${listener.token}`));
/** Python statements that ask the listener with http.client, as the plugin's library does, leaving the reply's text in `reply`. */
const pyAsk = (path: string) =>
	[
		"import http.client, urllib.parse",
		`address = urllib.parse.urlsplit(${JSON.stringify(listener.url)})`,
		"connection = http.client.HTTPConnection(address.hostname, address.port)",
		"try:",
		`    connection.request("POST", ${JSON.stringify(path)}, body=b"{}", headers={"Authorization": ${JSON.stringify(`Bearer ${listener.token}`)}})`,
		"    reply = connection.getresponse().read().decode()",
		"finally:",
		"    connection.close()",
	].join("\n");

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
	// What the engine does past its own cap, through the extension: keep the whole output as a session artifact, answer the cut text and the id.
	tool("c_spill", { parameters: z.object({ lines: z.number() }) }, async (_id, params: { lines: number }, _signal, ctx: { sessionManager: { saveArtifact(content: string, toolType: string): Promise<string | undefined> } }) => {
		const full = `header\n${rows(params.lines)}`;
		const artifactId = await ctx.sessionManager.saveArtifact(full, "c_spill");
		return { content: [text(`header\n\n[Output truncated. Full output: artifact://${artifactId}]`)], details: { truncated: true, artifactId } };
	});

	// An environment variable set while the extension loads, under each kind of name: the plugin's own prefix, and omp's.
	process.env.OMPRE_CONTRACT_PROBE = "set by the probe";
	process.env.PI_CONTRACT_PROBE = "set by the probe";

	pi.on("tool_call", async (event, ctx) => {
		seen.push({ kind: "call", tool: event.toolName, id: event.toolCallId, input: event.input, sessionFile: ctx.sessionManager.getSessionFile() });
	});
	pi.on("tool_result", async (event, ctx) => {
		const body = event.content.map((part) => (part.type === "text" ? part.text : "")).join("");
		seen.push({ kind: "result", tool: event.toolName, id: event.toolCallId, input: event.input, sessionFile: ctx.sessionManager.getSessionFile(), isError: event.isError, text: body });
		// A handler adding one more text block after the cell's own output.
		return event.toolName === "eval" && body.includes("TAG ME") ? { content: [...event.content, { type: "text" as const, text: "[tagged by tool_result]" }] } : undefined;
	});
}

// --- the harness ----------------------------------------------------------------------------

const agentDir = scratchAgentDir("contract");
/** The sessions' working directory: where a relative `%load` path is looked up. */
let work: string;

/** A headless session with the probe extension in place of this plugin's, and the plugin's skills (or `skills`). */
const boot = async (sessionManager: unknown, settings?: Record<string, unknown>, skills?: unknown[]): Promise<AgentSession> =>
	(await bootSession(sessionManager, { headless: true, extensions: [probe], skills: skills ?? true, settings, cwd: work })).session;

const cell = (session: AgentSession, code: string, more: Record<string, unknown> = {}, signal?: AbortSignal): Promise<Cell> => runCell(session, "js", code, more, signal);
const out = async (session: AgentSession, code: string): Promise<string> => {
	const result = await cell(session, code);
	expect({ code, isError: result.isError }).toEqual({ code, isError: false });
	return result.text;
};
/** A cell's value as JSON, written to a file: what a cell returns is cut for a model's eyes (see the output tests), and these are compared whole. */
async function value<T>(session: AgentSession, expression: string): Promise<T> {
	const file = join(work, `value-${Math.random().toString(36).slice(2)}.json`);
	expect(await out(session, `await Bun.write(${JSON.stringify(file)}, JSON.stringify(await (async () => (${expression}))())); "written"`)).toBe("written");
	return JSON.parse(await readFile(file, "utf8")) as T;
}

/** The session most claims are shown on: on disk, so it has an artifact store; with the probe and this plugin's skills. */
let h: AgentSession;

beforeAll(async () => {
	listen();
	work = await mkdtemp(join(tmpdir(), "omp-re-contract-cwd-"));
	const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
	h = await boot(SessionManager.create(work, join(agentDir(), "sessions")));
	await h.sessionManager.ensureOnDisk();
});

afterAll(async () => {
	await h.dispose();
	listener.stop();
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
	test("reaches a tool an extension registered, and nothing else: a name that is no registered tool throws Unknown tool from js runtime — so a plugin that registers none has no way in through it", async () => {
		expect(await out(h, 'await tool.c_plain({ say: "hi" })')).toBe("plain:hi");
		expect(await out(h, caught("await tool.re_open({})"))).toBe("Unknown tool from js runtime: re_open");
		expect(await out(h, caught('await tool.rizin_command({ command: "aflj" })'))).toBe("Unknown tool from js runtime: rizin_command");
	});
});

describe("approval of a cell", () => {
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

	test("that is the one gate: once a cell is allowed, what it does over a socket is asked of nobody; and under the default mode (yolo) a cell runs unprompted", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const session = await boot(SessionManager.inMemory(join(work, "ask-2")), { "tools.approvalMode": "always-ask", "tools.approval": { eval: "allow" } });
		try {
			expect(await out(session, jsAsk("/quick?who=allowed"))).toBe('{"ok":true}');
		} finally {
			await session.dispose();
		}
		expect(await out(h, "1 + 1")).toBe("2");
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

	test("skill://<name>/<path> loads the file beside that skill's SKILL.md — how this plugin's library is loaded", async () => {
		const loaded = await cell(h, "%load skill://re-triage/recipes.js");
		expect(loaded.isError).toBe(false);
		expect(loaded.text).toStartWith("omp-re loaded: ");
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
		// A device is a registered tool: there is no entry an extension can add without registering one.
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
	test("the name re is taken in a Python cell: omp's prelude runs in the cell namespace and leaves the standard library's regex module, json, os, math and Path there", async () => {
		expect(await pyOut(h, 'print(" ".join(name + ":" + type(globals().get(name)).__name__ for name in ["re", "json", "os", "math", "asyncio", "inspect", "contextvars", "Path"]))')).toBe(
			"re:module json:module os:module math:module asyncio:module inspect:module contextvars:module Path:type",
		);
		expect(await pyOut(h, 'print(re.__name__, re.sub("a", "b", "aaa"))')).toBe("re bbb");
		// The helpers a script may count on, by the names the tool description gives.
		expect(await pyOut(h, 'print(" ".join(str(callable(globals().get(name))) for name in ["read", "write", "display", "env", "output", "log", "phase", "wait", "tool"]))')).toBe(Array(9).fill("True").join(" "));
	});

	test("a cell runs inside a running event loop, and a plain blocking call there is how omp's own helpers work: read() answers a value, not a coroutine", async () => {
		expect(await pyOut(h, "print(asyncio.get_running_loop().is_running())")).toBe("True");
		expect(await pyOut(h, 'print(type(read("skill://re-triage/recipes.py")).__name__, inspect.iscoroutinefunction(read))')).toBe("str False");
	});

	test("%load skill://<name>/<path> runs a Python file in the cell namespace: the output is what it printed, and omp sets __file__ and puts the script's directory on sys.path", async () => {
		expect(await pyOut(h, 'print("__file__" in globals(), "omp_re" in globals())')).toBe("False False");
		const loaded = await py(h, "%load skill://re-triage/recipes.py");
		expect(loaded.isError).toBe(false);
		// The source is not echoed; a script says what it did by printing.
		expect(loaded.text).toStartWith("omp-re loaded: omp_re.open, ");
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

	test("time a cell spends waiting on a socket counts toward its deadline; when the kernel is killed its open request is hung up, which the listener sees", async () => {
		listener.hungUp.length = 0;
		const started = Date.now();
		const late = await cell(h, `${jsAsk("/slow?who=js-timeout")}; "finished"`, { timeout: 1 });
		expect(late.text).toStartWith("Command timed out after 1 seconds.");
		expect(Date.now() - started).toBeLessThan(5000);
		expect(await until(() => listener.hungUp.includes("js-timeout"), 3000)).toBe(true);
	}, 15_000);

	test("aborting a cell kills the kernel too, and hangs up the request it was waiting on", async () => {
		expect(await out(h, 'globalThis.marker = "before"; marker')).toBe("before");
		listener.hungUp.length = 0;
		const stop = new AbortController();
		setTimeout(() => stop.abort(), 300);
		const stopped = await cell(h, `${jsAsk("/slow?who=js-abort")}; "finished"`, {}, stop.signal);
		expect(stopped).toMatchObject({ thrown: false, isError: true, text: "Command aborted" });
		expect(await until(() => listener.hungUp.includes("js-abort"), 3000)).toBe(true);
		expect(await out(h, "typeof marker")).toBe("undefined");
	}, 15_000);
});

// --- what the plugin's way to the engine stands on -------------------------------------------

describe("a kernel is a process of its own, a child of omp's, and may open a socket", () => {
	test("the JavaScript kernel is a child process of omp: its parent's id is omp's, and nothing of omp's realm is in it", async () => {
		(globalThis as Record<symbol, unknown>)[Symbol.for("omp-re.contract")] = "omp's realm";
		const kernel = await value<{ pid: number; ppid: number; shared: string }>(h, '({ pid: process.pid, ppid: process.ppid, shared: typeof globalThis[Symbol.for("omp-re.contract")] })');
		expect(kernel.ppid).toBe(process.pid);
		expect(kernel.pid).not.toBe(process.pid);
		expect(kernel.shared).toBe("undefined");
	});

	test("a JavaScript cell is told its session as __omp_session__: { cwd, sessionId }, the id being js:session:<session file>:cwd:<cwd>, or js:cwd:<cwd> for a session with no file", async () => {
		expect(await value<unknown>(h, "globalThis.__omp_session__")).toEqual({ cwd: work, sessionId: `js:session:${h.sessionManager.getSessionFile()}:cwd:${work}` });
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const fileless = join(work, "fileless-js");
		const session = await boot(SessionManager.inMemory(fileless));
		try {
			expect(await value<unknown>(session, "globalThis.__omp_session__")).toMatchObject({ sessionId: `js:cwd:${fileless}` });
		} finally {
			await session.dispose();
		}
	});

	test("a JavaScript cell can ask a loopback listener in omp's process with node:http, token and all, and is refused without the token", async () => {
		expect(await out(h, jsAsk("/quick?who=js"))).toBe('{"ok":true}');
		expect(listener.took.at(-1)).toBe("POST /quick js {}");
		expect(await out(h, `await new Promise((done) => require("node:http").get(${JSON.stringify(`${listener.url}/quick`)}, (response) => done(response.statusCode)))`)).toBe("401");
	});

	test("the kernel's temporary directory and user are omp's own: where a file left for it is looked for", async () => {
		const { tmpdir: ompTmp } = await import("node:os");
		expect(await value<unknown>(h, '({ tmp: require("node:os").tmpdir(), uid: process.getuid?.() ?? null, runtime: process.env.XDG_RUNTIME_DIR ?? null })')).toEqual({
			tmp: ompTmp(),
			uid: process.getuid?.() ?? null,
			runtime: process.env.XDG_RUNTIME_DIR ?? null,
		});
	});

	test("tool_call and tool_result fire for a cell, with its code and language and a context that names the session's file; what tool_result adds to the content reaches the cell's result, an error's too", async () => {
		seen.length = 0;
		const id = `contract-${crypto.randomUUID()}`;
		const tagged = await runCell(h, "js", '"TAG ME"', {}, undefined, id);
		expect(tagged.text).toBe("TAG ME\n[tagged by tool_result]");
		expect(seen.map((event) => [event.kind, event.tool, event.id, event.sessionFile])).toEqual([
			["call", "eval", id, h.sessionManager.getSessionFile()],
			["result", "eval", id, h.sessionManager.getSessionFile()],
		]);
		expect(seen[0]!.input).toMatchObject({ language: "js", code: '"TAG ME"' });
		expect(seen[1]).toMatchObject({ isError: false, input: { language: "js", code: '"TAG ME"' } });
		// A cell that threw is a result too, marked as an error, and what a handler adds is shown under it.
		const failed = await cell(h, 'throw new Error("TAG ME")');
		expect(failed.isError).toBe(true);
		expect(failed.text).toEndWith("[tagged by tool_result]");
		expect(seen.at(-1)).toMatchObject({ kind: "result", isError: true });
		// A name that is not defined is said in these words: what the plugin's reload hint looks for.
		expect((await cell(h, "notDefinedAnywhere.status()")).text).toContain("notDefinedAnywhere is not defined");
	});

	describe.skipIf(!python.ok)("the Python kernel", () => {
		const py = (session: AgentSession, code: string, more: Record<string, unknown> = {}, signal?: AbortSignal) => cell(session, code, { language: "py", ...more }, signal);
		const pyOut = async (session: AgentSession, code: string): Promise<string> => {
			const result = await py(session, code);
			expect({ code, isError: result.isError, text: result.isError ? result.text : "" }).toEqual({ code, isError: false, text: "" });
			return result.text;
		};

		test("is a child process of omp too, started in the session's directory, and told the session's file as PI_SESSION_FILE — which a session with no file does not have", async () => {
			const kernel = JSON.parse(await pyOut(h, 'print(json.dumps({"ppid": os.getppid(), "cwd": os.getcwd(), "file": os.environ.get("PI_SESSION_FILE")}))')) as { ppid: number; cwd: string; file: string };
			expect(kernel).toEqual({ ppid: process.pid, cwd: work, file: h.sessionManager.getSessionFile()! });
			const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
			const fileless = join(work, "fileless-py");
			await mkdir(fileless, { recursive: true });
			const session = await boot(SessionManager.inMemory(fileless));
			try {
				expect(await pyOut(session, 'print(os.getcwd(), os.environ.get("PI_SESSION_FILE"))')).toBe(`${fileless} None`);
			} finally {
				await session.dispose();
			}
		});

		test("its environment is filtered: a variable under the plugin's own prefix does not reach it, one under PI_ does — so the listener cannot be named to it by a variable of the plugin's", async () => {
			expect(await pyOut(h, 'print(os.environ.get("OMPRE_CONTRACT_PROBE"), os.environ.get("PI_CONTRACT_PROBE"))')).toBe("None set by the probe");
			// The JavaScript kernel is handed omp's environment as it is.
			expect(await out(h, "process.env.OMPRE_CONTRACT_PROBE")).toBe("set by the probe");
		});

		test("its temporary directory, user and runtime directory are omp's own: where a file left for it is looked for", async () => {
			const { tmpdir: ompTmp } = await import("node:os");
			const kernel = JSON.parse(await pyOut(h, 'import tempfile\nprint(json.dumps({"tmp": tempfile.gettempdir(), "uid": os.getuid() if hasattr(os, "getuid") else None, "runtime": os.environ.get("XDG_RUNTIME_DIR")}))'));
			expect(kernel).toEqual({ tmp: ompTmp(), uid: process.getuid?.() ?? null, runtime: process.env.XDG_RUNTIME_DIR ?? null });
		});

		test("a Python cell can ask a loopback listener in omp's process with http.client, token and all", async () => {
			expect(await pyOut(h, `${pyAsk("/quick?who=py")}\nprint(reply)`)).toBe('{"ok":true}');
			expect(listener.took.at(-1)).toBe("POST /quick py {}");
		});

		test("a Python cell past its deadline is interrupted, not killed: the call it was blocked in is stopped by KeyboardInterrupt, its request is hung up, and the namespace is still there", async () => {
			expect(await pyOut(h, 'marker = "before"\nprint(marker)')).toBe("before");
			listener.hungUp.length = 0;
			const started = Date.now();
			const late = await py(h, `${pyAsk("/slow?who=py-timeout")}\nprint("finished")`, { timeout: 1 });
			expect(late.isError).toBe(true);
			expect(late.text).toStartWith("[eval cell timed out after 1s; kernel interrupted but remains running.");
			expect(late.text).not.toContain("finished");
			expect(Date.now() - started).toBeLessThan(8000);
			expect(await until(() => listener.hungUp.includes("py-timeout"), 3000)).toBe(true);
			expect(await pyOut(h, "print(marker, os.getpid() > 0)")).toBe("before True");
		}, 20_000);

		test("aborting a Python cell interrupts it the same way: KeyboardInterrupt in the cell, the request hung up, the kernel and its names kept", async () => {
			const pid = await pyOut(h, 'kept = "kept"\nprint(os.getpid())');
			listener.hungUp.length = 0;
			const stop = new AbortController();
			setTimeout(() => stop.abort(), 300);
			const stopped = await py(h, `${pyAsk("/slow?who=py-abort")}\nprint("finished")`, {}, stop.signal);
			expect(stopped.isError).toBe(true);
			expect(stopped.text).toContain("KeyboardInterrupt");
			expect(await until(() => listener.hungUp.includes("py-abort"), 3000)).toBe(true);
			expect(await pyOut(h, "print(kept, os.getpid())")).toBe(`kept ${pid}`);
		}, 20_000);

		test("a name that is not defined is NameError in these words: what the plugin's reload hint looks for", async () => {
			expect((await py(h, "not_defined_anywhere.status()")).text).toContain("NameError: name 'not_defined_anywhere' is not defined");
		});
	});
});
