/**
 * extensions/re as omp's side of the engine: the child process it starts and
 * ends, the wire to it, how long it waits, and what it does with the engine's
 * answers — loaded through omp's real SDK, like extension-sdk.test.ts.
 *
 * The first half needs neither SBCL nor rizin: test/stand-in-engine.ts is
 * started where the engine would be. It speaks stdio/protocol.json and holds
 * everything omp's side says to it, so each method, event and member of the
 * wire is sent once here and checked by the protocol's own description. The
 * second half runs the real engine and, where rizin is there, a real binary.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Engine, type HostHandlers } from "../extensions/re/engine.ts";
import { askSideModel, engine, outside } from "../extensions/re/host.ts";
import { CONSTANTS, KEYS, PROTOCOL } from "../extensions/re/protocol.ts";
import { boot, canRunRizin, caught, evalJs, logSkip, plainTheme, reTools, ROOT, type SdkHarness, scratchAgentDir, TEST_BINARY, until } from "./helpers.ts";

logSkip("shim rizin tests");

const agentDir = scratchAgentDir("shim-test");

const sessions = async () => (await import("@oh-my-pi/pi-coding-agent")).SessionManager;
const inMemory = async () => (await sessions()).inMemory();
const onDisk = async () => {
	const manager = (await sessions()).create(tmpdir(), join(agentDir(), "sessions"));
	await manager.ensureOnDisk();
	return manager;
};

/** Whether the process `pid` is still running. A child that exited stays in the process table until its parent collects it, so where the system says a process's state, that is read. */
function alive(pid: number): boolean {
	if (existsSync("/proc/self/stat")) {
		try {
			const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
			return stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3) !== "Z";
		} catch {
			return false;
		}
	}
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

const standIn = (behaviour: string, beatMs?: number) => [process.execPath, join(ROOT, "test", "stand-in-engine.ts"), behaviour, ...(beatMs === undefined ? [] : [String(beatMs)])];

/** Run `body` with the engine omp's side starts being `command`, and what it logs collected; the real one after. */
async function withEngine<T>(command: string[], body: (logged: string[]) => Promise<T>): Promise<T> {
	const { engineCommand, log } = outside;
	const logged: string[] = [];
	outside.engineCommand = () => command;
	outside.log = (line) => void logged.push(line);
	try {
		return await body(logged);
	} finally {
		outside.engineCommand = engineCommand;
		outside.log = log;
	}
}

const startFailure = (behaviour: string) => withEngine(standIn(behaviour), async () => boot(await inMemory()).then(() => null, (error: Error) => error.message));

/** What the stand-in answers `/re <line>` with, when that is JSON. */
async function standInSays<T>(h: SdkHarness, line: string): Promise<T> {
	await h.session.prompt(`/re ${line}`);
	return JSON.parse(h.notes.at(-1)!.replace(/^\[info\] /, "")) as T;
}

interface Heard {
	heard: { method: string; params: Record<string, unknown> & { session?: { id: string; memory?: unknown } }; request: boolean }[];
	violations: string[];
}

describe("starting the engine", () => {
	test("with no SBCL the session fails to load the extension, and the error says what to install", async () => {
		const missing = join(agentDir(), "no-such-sbcl");
		const before = process.env.OMPRE_SBCL_PATH;
		process.env.OMPRE_SBCL_PATH = missing;
		try {
			const failure = await boot(await inMemory()).then(() => null, (error: Error) => error.message);
			expect(failure).toContain(`omp-re: SBCL was not found (tried ${JSON.stringify(missing)})`);
			expect(failure).toContain("apt install sbcl cl-ppcre");
			expect(failure).toContain("OMPRE_SBCL_PATH");
		} finally {
			if (before === undefined) delete process.env.OMPRE_SBCL_PATH;
			else process.env.OMPRE_SBCL_PATH = before;
		}
	});

	test("an engine that cannot load says why in its own words, and those are the error", async () => {
		expect(await startFailure("fatal")).toContain("omp-re: the Common Lisp library cl-ppcre was not found. Install it.");
	});

	test("an engine that dies without a word is reported with what it wrote to its log", async () => {
		expect(await startFailure("dying")).toContain("omp-re: the engine process ended (status 7): heap exhausted");
	});

	test("an engine of another protocol version is refused, and the error says to reinstall", async () => {
		const failure = await startFailure("other-version");
		expect(failure).toContain(`omp-re: the extension speaks protocol ${PROTOCOL} and its engine protocol ${PROTOCOL + 1}`);
		expect(failure).toContain("Reinstall or upgrade the omp-re plugin");
	});

	test("an engine that never becomes ready is ended at the start deadline, with what to check and what it had logged", async () => {
		const logged: string[] = [];
		const silent = new Engine({ command: standIn("silent"), handlers: {} as HostHandlers, log: (line) => void logged.push(line), deadlines: { startMs: 1000 } });
		const started = Date.now();
		const failure = await silent.request("describe", {}).then(() => null, (error: Error) => error.message);
		expect(failure).toContain("omp-re: the engine did not start within 1 s and was ended. Check that");
		expect(failure).toContain("; compiling file engine.lisp");
		expect(Date.now() - started).toBeLessThan(5000);
		await silent.exited;
		expect(alive(silent.pid!)).toBe(false);
		// What it wrote to its standard error reached the log as it came, not only in the error.
		expect(logged).toEqual(["; compiling file engine.lisp"]);
	});

	test("the tools registered are the ones the engine describes — read off a wire that splits a character in two, ends lines with CRLF, and carries lines that are not messages, each noted in the log", async () => {
		await withEngine(standIn("framing"), async (logged) => {
			const h = await boot(await inMemory());
			try {
				const registered = reTools(h.session).map((tool) => tool.definition);
				expect(registered.map((tool) => tool.name)).toEqual(["stand_in_tool"]);
				expect(registered[0]!.description).toBe("split — here");
				expect(registered[0]!.parameters).toEqual({ type: "object", properties: { addr: { type: "string" } } });
				// The approval prompt's sentence is filled from the call's arguments without asking the engine: quoted, cut at the engine's bound.
				const approval = registered[0]!.approval as (args: unknown) => unknown;
				expect(approval({ addr: "main" })).toEqual({ tier: "write", reason: 'Touch "main".' });
				expect(approval({ addr: "0x0123456789" })).toEqual({ tier: "write", reason: 'Touch "0x012...".' });
				expect(approval({})).toEqual({ tier: "write", reason: 'Touch "?".' });
				expect(h.session.extensionRunner!.getCommand("re")!.getArgumentCompletions!("h")).toEqual([expect.objectContaining({ value: "help ", label: "help" })]);
				expect(logged).toEqual(["skipped a line on the wire that is not a message: a line that is not JSON", "skipped a line on the wire that is not a message: [1, 2]"]);
			} finally {
				await h.shutdown();
			}
		});
	});
});

describe("the wire, method by method, against a stand-in that holds both sides to stdio/protocol.json", () => {
	test("everything the engine asks of omp is answered as the protocol says, and done", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await boot(await onDisk(), { sideModel: (prompt) => `the side model read: ${prompt}` });
			try {
				const id = h.session.sessionManager.getSessionId();
				const wire = await standInSays<Record<string, unknown> & { appended: { id: string } }>(h, "wire");
				expect(wire.violations).toEqual([]);
				// The record: nothing yet; the appended entry under the id omp gave it; nothing more after it; and the whole branch when the engine's copy is not its start.
				expect(wire.before).toEqual({ append: [] });
				const entry = { id: wire.appended.id, customType: "re.stand-in", data: { n: 1 } };
				expect(h.session.sessionManager.getEntries().find((one) => one.id === wire.appended.id)).toMatchObject({ type: "custom", customType: "re.stand-in", data: { n: 1 } });
				expect(wire.continues).toEqual({ append: [] });
				expect(wire.moved).toEqual({ all: [entry] });
				expect(wire.saved).toEqual({ id: expect.any(String) });
				expect(wire.readBack).toBe(true);
				expect(wire.readMissing).toEqual({});
				expect(wire.kept).toEqual({});
				expect(wire.judged).toEqual({ text: "the side model read: CLAIM 0: the stand-in asks" });
				expect(wire.unknownSession).toEqual({ error: 'omp-re: omp has no session "no-such-session"' });
				expect(wire.unknownMethod).toEqual({ error: 'omp-re: omp has no method "noSuchMethod"' });

				expect(h.notes).toEqual(expect.arrayContaining(["[info] notified at info", "[warning] notified at warning", "[error] notified at error", "[warning] told in passing"]));
				expect(h.session.sessionManager.getEntries().filter((one) => (one as { customType?: string }).customType === "re.binary")).toEqual([
					expect.objectContaining({ content: "[re: opened /stand/in]", details: { sha256: "00" } }),
				]);
				expect(h.session.extensionRunner!.getMessageRenderer("re.binary")).toBeDefined();
				// The state the engine sent outside any answer: the band is drawn as its lines, and its evidence completes an id.
				expect(h.widget("re.hud")).toEqual(["stand-in  ELF64 x86/64  entry 0x1000", "3 fn · 0 findings · 1 evidence"]);
				expect(h.widget("re.hud", 12)).toEqual(["stand-in  E…", "3 fn · 0 fi…"]);
				const complete = h.session.extensionRunner!.getCommand("re")!.getArgumentCompletions!;
				expect(complete("cite 0a")).toEqual([{ value: "cite 0a1b2c3d ", label: "0a1b2c3d", description: "rizin_command @ main" }]);
				expect(complete("cite ff")).toBeNull();
				expect(complete("help 0a")).toBeNull();
				// What the engine said it holds in no record is handed back with the next request.
				const { heard } = await standInSays<Heard>(h, "heard");
				expect(heard.at(-1)).toMatchObject({ method: "command", params: { line: "heard", session: { id, cwd: tmpdir(), hasUI: true, memory: { toolsOff: true } } } });
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("the session's life, a compaction, the approval gate and an environment change are each said to the engine, as the protocol has them", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await boot(await inMemory(), { flags: { binary: "/stand/in/binary" } });
			try {
				const id = h.session.sessionManager.getSessionId();
				const emit = (event: Record<string, unknown>) => h.session.extensionRunner!.emit({ sessionId: id, ...event } as never) as Promise<unknown>;
				await emit({ type: "session_before_switch", reason: "new" });
				await emit({ type: "session_switch", reason: "new" });
				await emit({ type: "session_branch" });
				await emit({ type: "session_tree" });
				expect(await emit({ type: "session.compacting", messages: [] })).toEqual({ context: ["preserve: the stand-in's binary", "- Open binary: stand-in"] });
				await emit({ type: "tool_approval_resolved", toolCallId: "call-yes", toolName: "stand_in_tool", approved: true });
				await emit({ type: "tool_approval_resolved", toolCallId: "call-no", toolName: "stand_in_tool", approved: false, reason: "not now" });
				await emit({ type: "tool_approval_resolved", toolCallId: "call-other", toolName: "bash", approved: true });
				process.env.OMPRE_STAND_IN_SETTING = "changed while the engine runs";
				const { heard, violations } = await standInSays<Heard>(h, "heard");
				delete process.env.OMPRE_STAND_IN_SETTING;
				expect(violations).toEqual([]);

				const said = heard.map((one) => [one.method, one.request ? "request" : "notification"]);
				expect(said).toEqual([
					["hello", "request"],
					["describe", "request"],
					...["event", "event", "event", "event", "event", "preserved", "approval", "approval"].map((method) => [method, "request"]),
					["environment", "notification"],
					["command", "request"],
				]);
				const session = { id, cwd: process.cwd(), hasUI: true };
				expect(heard[0]!.params).toMatchObject({ protocol: PROTOCOL, stateDir: agentDir(), variables: { PATH: process.env.PATH } });
				expect(heard.slice(2, 7).map((one) => one.params)).toMatchObject([
					{ session, kind: "start", binary: "/stand/in/binary" },
					{ session, kind: "before-switch" },
					{ session, kind: "switch" },
					{ session, kind: "branch", previous: id },
					{ session, kind: "tree" },
				]);
				expect(heard[7]!.params).toMatchObject({ session });
				expect(heard[8]!.params).toMatchObject({ session, callId: "call-yes", tool: "stand_in_tool", approved: true });
				expect(heard[9]!.params).toMatchObject({ session, callId: "call-no", tool: "stand_in_tool", approved: false, reason: "not now" });
				expect(heard[10]!.params).toMatchObject({ stateDir: agentDir(), variables: { OMPRE_STAND_IN_SETTING: "changed while the engine runs" } });
				expect(Object.keys(heard[10]!.params.variables as object).every((name) => name === "PATH" || name.startsWith(CONSTANTS.environmentPrefix))).toBe(true);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("a session that ends says so to the engine, by its own id, while the engine goes on for the others", async () => {
		await withEngine(standIn("serve"), async () => {
			const staying = await boot(await inMemory());
			try {
				const leaving = await boot(await inMemory());
				const left = leaving.session.sessionManager.getSessionId();
				const pid = engine().pid!;
				await leaving.shutdown();
				expect(alive(pid)).toBe(true);
				const { heard, violations } = await standInSays<Heard>(staying, "heard");
				expect(violations).toEqual([]);
				expect(heard.filter((one) => one.method === "event" && one.params.session?.id === left).map((one) => one.params.kind)).toEqual(["start", "shutdown"]);
			} finally {
				await staying.shutdown();
			}
		});
	}, 30_000);

	test("a call's answer is the tool's result: a refusal is thrown, a failure is a result marked as one, and a read carries its details", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await boot(await inMemory());
			try {
				const tool = h.session.getToolByName("stand_in_tool")!;
				await expect(tool.execute("c-refuse", { addr: "refuse" })).rejects.toThrow("omp-re: refused by the stand-in");
				expect(await tool.execute("c-fail", { addr: "fail" })).toMatchObject({ content: [{ type: "text", text: "the stand-in's tool failed" }], isError: true });
				const read = await tool.execute("c-read", { addr: "main" });
				expect(read).toMatchObject({ content: [{ type: "text", text: "header\nbody of main\n[evidence 0a1b2c3d — cite it in record_finding]" }], details: { evidenceId: "0a1b2c3d-0000-0000-0000-000000000000" } });
				expect((read as { isError?: boolean }).isError).toBeUndefined();
				// Drawn: the header, the body without the line that names the evidence record, and that line beside the header.
				const drawn = (tool as unknown as { renderResult(result: unknown, options: unknown, theme: unknown, args: unknown): { render(width: number): string[] } }).renderResult(read, { expanded: true, isPartial: false }, plainTheme, { addr: "main" });
				expect(drawn.render(200).map((line) => line.trimEnd())).toEqual(["<status.success> header (main) [evidence 0a1b2c3d — cite it in record_finding]", "body of main"]);
				const { heard, violations } = await standInSays<Heard>(h, "heard");
				expect(violations).toEqual([]);
				expect(heard.filter((one) => one.method === "call").map((one) => one.params)).toMatchObject([
					{ name: "stand_in_tool", arguments: { addr: "refuse" }, callId: "c-refuse" },
					{ name: "stand_in_tool", arguments: { addr: "fail" }, callId: "c-fail" },
					{ name: "stand_in_tool", arguments: { addr: "main" }, callId: "c-read" },
				]);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("a /re line's draft goes to the input box with its notice; a list opens as a panel, a row as its code, and the keys the protocol names drive it", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await boot(await inMemory());
			try {
				await h.session.prompt("/re cite 0a1b2c3d");
				expect(h.editor()).toBe("Re: evidence 0a1b2c3d");
				expect(h.notes.at(-1)).toBe("[info] the citation is in your draft");

				expect([...h.session.extensionRunner!.getShortcuts().keys()]).toEqual(expect.arrayContaining(KEYS.views.map((key) => key.key)));
				const opened = h.session.prompt("/re functions");
				expect(await until(() => h.overlays.length === 1, 5000)).toBe(true);
				const panel = h.overlays[0]!;
				expect(panel.render(80)[0]).toBe("omp-re: functions 2");
				expect(panel.render(80).join("\n")).toContain("helper");
				expect(panel.render(80).at(-1)).toBe("enter open · type to filter · esc close");
				// Typing filters by label; enter on the one row left asks for its view, which opens over the list.
				for (const key of "main") panel.handleInput!(key);
				expect(panel.render(80).join("\n")).not.toContain("helper");
				panel.handleInput!("\r");
				expect(await until(() => h.overlays.length === 2, 5000)).toBe(true);
				const code = h.overlays[1]!;
				const keyOf = (action: string) => KEYS.code.find((key) => key.action === action)!.key;
				expect(code.render(80)).toEqual(["main · disasm", "0x1000  push rbp", "0x1001  ret", "d decomp · x xrefs · a ask · esc back"]);
				code.handleInput!(keyOf("decompile"));
				expect(code.render(80)[0]).toBe("main · decompile");
				expect(code.render(80)[1]).toBe("// decompiled with pdg");
				// The references are a notice here: it is said, and the code stays.
				code.handleInput!(keyOf("xrefs"));
				expect(await until(() => h.notes.at(-1) === "[info] omp-re: no xrefs to 0x1000", 5000)).toBe(true);
				expect(h.overlays.length).toBe(2);
				code.handleInput!(keyOf("ask"));
				expect(await until(() => h.overlays.length === 1, 5000)).toBe(true);
				expect(h.editor()).toBe("Analyze function main at 0x1000.");
				panel.handleInput!("\x1b");
				panel.handleInput!("\x1b");
				await opened;
				expect(h.overlays.length).toBe(0);
				const { heard, violations } = await standInSays<Heard>(h, "heard");
				expect(violations).toEqual([]);
				expect(heard.filter((one) => one.method === "view").map((one) => [one.params.kind, one.params.arg])).toEqual([
					["functions", undefined],
					["code", { addr: "0x1000", name: "main" }],
					["xrefs", { addr: "0x1000" }],
				]);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("headless (omp -p), what a /re line says goes to standard output, an error to standard error with a failing exit status", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await boot(await inMemory(), { headless: true });
			const { print, printError, failExit } = outside;
			const said: string[] = [];
			outside.print = (text) => void said.push(`out: ${text}`);
			outside.printError = (text) => void said.push(`err: ${text}`);
			outside.failExit = () => void said.push("exit status: failing");
			try {
				await h.session.prompt("/re status");
				await h.session.prompt("/re bogus");
				expect(said).toEqual(["out: stand-in: status", "err: stand-in: bogus", "exit status: failing"]);
			} finally {
				Object.assign(outside, { print, printError, failExit });
				await h.shutdown();
			}
		});
	}, 30_000);
});

describe("how long omp's side waits for the engine", () => {
	const BEAT_MS = 100;
	const session = { id: "s", cwd: tmpdir(), hasUI: false };
	const call = { session, name: "stand_in_tool", arguments: {}, callId: "c" };
	const start = (behaviour: string, deadlines = {}) => {
		const logged: string[] = [];
		return { logged, engine: new Engine({ command: standIn(behaviour, BEAT_MS), handlers: {} as HostHandlers, log: (line) => void logged.push(line), deadlines: { beatMs: BEAT_MS, ...deadlines } }) };
	};
	const failure = (request: Promise<unknown>) => request.then(() => null, (error: Error) => error.message);

	test("a request the engine says it is serving is waited for, however long: no clock bounds an analysis", async () => {
		const { engine } = start("slow");
		try {
			const started = Date.now();
			expect(await engine.request("call", call)).toMatchObject({ failed: false });
			// Longer than the silence that would have ended it.
			expect(Date.now() - started).toBeGreaterThan(6 * BEAT_MS);
		} finally {
			await engine.stop();
		}
	});

	test("an engine that says nothing while a request waits is taken for hung: it is ended, and the request fails saying so", async () => {
		const { engine } = start("mute");
		expect(await failure(engine.request("call", call))).toContain("omp-re: the engine has said nothing for 1 s with 1 request(s) waiting (call); it was ended");
		await engine.exited;
		expect(alive(engine.pid!)).toBe(false);
	});

	test("a request the engine's beats do not name was lost: it alone fails, and the engine goes on", async () => {
		const { engine } = start("forgetful");
		try {
			expect(await failure(engine.request("call", call))).toBe("omp-re: the engine is not serving the request call: it was not received, or its answer was lost");
			expect(await engine.request("preserved", { session })).toEqual({ lines: expect.any(Array) });
		} finally {
			await engine.stop();
		}
	});

	test("when the engine dies every request in flight fails with what it last logged", async () => {
		const { engine, logged } = start("crashing");
		const waiting = [failure(engine.request("call", call)), failure(engine.request("call", { ...call, callId: "c2" }))];
		for (const one of await Promise.all(waiting)) expect(one).toBe("omp-re: the engine process ended (status 9): fatal error in the stand-in");
		expect(logged).toEqual(["fatal error in the stand-in"]);
	});

	test("a request that is not the protocol's is refused by the engine in words that name what is wrong", async () => {
		const { engine } = start("serve");
		try {
			expect(await failure(engine.request("view", { session, kind: 5 as never }))).toBe("omp-re: not the protocol (stdio/protocol.json): view's params.kind must be a string, not 5");
		} finally {
			await engine.stop();
		}
	});

	test("an engine is ended by telling it to leave and by closing its input, either of which is enough; one that heeds neither is killed when its grace is over, inside omp's two-second shutdown budget", async () => {
		let started = 0;
		for (const heeds of ["told-only", "eof-only"]) {
			const obedient = start(heeds).engine;
			await obedient.request("describe", {});
			started = Date.now();
			await obedient.stop();
			expect(Date.now() - started).toBeLessThan(1000);
		}

		const deaf = start("deaf").engine;
		await deaf.request("describe", {});
		started = Date.now();
		await deaf.stop();
		// omp gives shutdown handlers 2 s (an outside fact): the kill has to come inside it.
		expect(Date.now() - started).toBeGreaterThan(1000);
		expect(Date.now() - started).toBeLessThan(2000);
		expect(alive(deaf.pid!)).toBe(false);
	});
});

describe("the side model the engine's claim audit asks", () => {
	const turnWith = (run: (options: Record<string, unknown>) => Promise<{ replyText: string }>) => ({ model: {}, runEphemeralTurn: run }) as unknown as ExtensionContext;

	test("the prompt goes out as a side turn with no tools, whole replies kept, bounded by the seconds given", async () => {
		let sent: Record<string, unknown> = {};
		const answer = await askSideModel(
			turnWith(async (options) => {
				sent = options;
				return { replyText: '[{"index":1,"verdict":"supported"}]' };
			}),
			"CLAIM 1: x",
			30,
		);
		expect(answer).toEqual({ text: '[{"index":1,"verdict":"supported"}]' });
		expect(sent).toMatchObject({ promptText: "CLAIM 1: x", tools: false, dedupeReply: false, replyMaxBytes: Number.POSITIVE_INFINITY });
		expect(sent.signal).toBeInstanceOf(AbortSignal);
	});

	test("a transport that refuses `tools: false` is asked once more with the tools sent", async () => {
		const asked: unknown[] = [];
		const answer = await askSideModel(
			turnWith(async (options) => {
				asked.push(options.tools);
				if (options.tools === false) throw new Error("this transport does not support tools: false");
				return { replyText: "reply" };
			}),
			"p",
			30,
		);
		expect(asked).toEqual([false, undefined]);
		expect(answer).toEqual({ text: "reply" });
	});

	test("any other failure is not retried, and is answered as omp's reason, never thrown", async () => {
		let calls = 0;
		const answer = await askSideModel(
			turnWith(async () => {
				calls++;
				throw new Error("provider overloaded\nsecond line");
			}),
			"p",
			30,
		);
		expect(calls).toBe(1);
		expect(answer).toEqual({ reason: "provider overloaded\nsecond line" });
	});

	test("with no model, or a host with no side turns, there is nobody to ask", async () => {
		expect(await askSideModel({ runEphemeralTurn: async () => ({ replyText: "x" }) } as unknown as ExtensionContext, "p", 30)).toEqual({});
		expect(await askSideModel({ model: {} } as unknown as ExtensionContext, "p", 30)).toEqual({});
	});
});

describe("one engine for the omp process", () => {
	test("two sessions share one engine process and keep their own state; it ends with the last of them, inside omp's two-second shutdown budget", async () => {
		const a = await boot(await inMemory());
		const pid = engine().pid!;
		const b = await boot(await inMemory());
		expect(engine().pid).toBe(pid);
		expect(alive(pid)).toBe(true);

		await a.session.prompt("/re off");
		expect((await evalJs(a.session, caught('await tool.rizin_command({ command: "aflj" })'))).text).toContain("RE tools are off for this session");
		expect((await evalJs(b.session, caught('await tool.rizin_command({ command: "aflj" })'))).text).toContain("omp-re: no binary open");
		// With no binary there is nothing to show but that: the band is the engine's two lines.
		expect(b.widget("re.hud")).toEqual(["no binary", "0 fn · 0 findings · 0 evidence"]);

		await a.shutdown();
		expect(alive(pid)).toBe(true);
		expect((await evalJs(b.session, '(await tool.rizin_command({ command: "" })).text')).text).toContain("omp-re — reverse engineering with rizin");

		const started = Date.now();
		await b.shutdown();
		expect(await until(() => !alive(pid), 2000)).toBe(true);
		expect(Date.now() - started).toBeLessThan(2000);
	}, 30_000);

	test("an engine that died is not kept: the session's next call starts another, which is told what the first held in no record — /re off", async () => {
		const h = await boot(await inMemory());
		try {
			const pid = engine().pid!;
			await h.session.prompt("/re off");
			process.kill(pid, "SIGKILL");
			expect(await until(() => !alive(pid), 2000)).toBe(true);
			expect((await evalJs(h.session, caught('await tool.rizin_command({ command: "" })'))).text).toBe("omp-re: RE tools are off for this session — the user can re-enable them with /re on");
			expect(engine().pid).not.toBe(pid);
			await h.session.prompt("/re on");
			expect((await evalJs(h.session, '(await tool.rizin_command({ command: "" })).text')).text).toContain("omp-re — reverse engineering with rizin");
		} finally {
			await h.shutdown();
		}
	}, 30_000);

	test("every call that ran is in the audit log under omp's own tool-call id, and what the approval gate decided is forwarded to it", async () => {
		const h = await boot(await inMemory());
		try {
			const id = h.session.sessionManager.getSessionId();
			// Without rizin the call fails, after its line is written: either way it ran.
			await h.session
				.getToolByName("rizin_help")!
				.execute("call-from-omp", { query: "pdf" })
				.then(
					() => {},
					() => {},
				);
			const emit = (event: Record<string, unknown>) => h.session.extensionRunner!.emit({ type: "tool_approval_resolved", sessionId: id, ...event } as never);
			await emit({ toolCallId: "call-denied", toolName: "rename_function", approved: false, reason: "not now" });
			await emit({ toolCallId: "call-allowed", toolName: "rename_function", approved: true });
			await emit({ toolCallId: "call-other", toolName: "bash", approved: true });
			const lines = (await readFile(join(agentDir(), "re", "audit", `${id}.log`), "utf8"))
				.trim()
				.split("\n")
				.map((line) => JSON.parse(line) as Record<string, unknown>);
			expect(lines.map((line) => line.toolCallId)).toEqual(["call-from-omp", "call-denied", "call-allowed"]);
			expect(lines[0]).toMatchObject({ sessionId: id, tool: "rizin_help", args: { query: "pdf" } });
			expect(lines[1]).toMatchObject({ tool: "rename_function", approved: false, reason: "not now" });
			expect(lines[2]).toMatchObject({ tool: "rename_function", approved: true });
		} finally {
			await h.shutdown();
		}
	}, 30_000);
});

describe.skipIf(!canRunRizin)("against rizin", () => {
	test("a call omp aborts is cancelled in the engine: it rejects as aborted, and the session goes on", async () => {
		const h = await boot(await inMemory());
		try {
			const abort = new AbortController();
			let progress = "";
			const large = ["/usr/bin/python3", "/usr/bin/perl", "/bin/bash"].find((path) => Bun.file(path).size > 0) ?? TEST_BINARY;
			const opening = h.session
				.getToolByName("open_binary")!
				.execute("call-open", { path: large }, abort.signal, (partial) => {
					progress = partial.content.map((part) => (part.type === "text" ? part.text : "")).join("");
				})
				.then(
					() => "opened",
					(error: Error) => error.message,
				);
			expect(await until(() => progress.startsWith("rizin: analyzing "), 10_000)).toBe(true);
			const started = Date.now();
			abort.abort();
			expect(await opening).toMatch(/^omp-re: .* aborted$/);
			expect(Date.now() - started).toBeLessThan(3000);
			expect((await evalJs(h.session, caught('await tool.rizin_command({ command: "ij" })'))).text).toContain("omp-re: no binary open");
			expect((await evalJs(h.session, `(await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })).text ?? "opened"`)).isError).toBe(false);
		} finally {
			await h.shutdown();
		}
	}, 60_000);

	test("an annotation is recorded in omp's own session under the entry id omp gave it, which is what /re undo names", async () => {
		const h = await boot(await inMemory());
		try {
			const done = await evalJs(h.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })\nawait tool.set_comment({ addr: "main", text: "shim test" })`);
			expect(done.isError).toBe(false);
			await h.session.prompt("/re undo");
			expect(h.notes.at(-1)).toStartWith("[info] ");
			const custom = h.session.sessionManager.getEntries().filter((entry) => entry.type === "custom") as { id: string; customType: string; data: Record<string, unknown> }[];
			const annotation = custom.find((entry) => entry.customType === "re.annotation")!;
			const undo = custom.find((entry) => entry.customType === "re.undo")!;
			expect(annotation.data).toMatchObject({ kind: "set_comment", newValue: "shim test" });
			expect(undo.data.undidEntryId).toBe(annotation.id);
			await h.session.prompt("/re undo");
			expect(h.notes.at(-1)).toBe("[error] omp-re: no annotation left to undo");
		} finally {
			await h.shutdown();
		}
	}, 60_000);

	test("the claim audit reaches omp's side model through the real pair: the verdict it gives decides whether a finding is recorded, and a session with no model records it unaudited", async () => {
		const asked: string[] = [];
		const audited = await boot(await inMemory(), {
			sideModel: (prompt) => {
				asked.push(prompt);
				return '[{"index": 0, "verdict": "overreach", "reason": "the stand-in says the read shows less"}]';
			},
		});
		const unaudited = await boot(await inMemory());
		try {
			const record = (h: SdkHarness) =>
				evalJs(
					h.session,
					`await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })\nconst read = await tool.rizin_command({ command: "ij" })\n${caught('m = (await tool.record_finding({ claim: "The file is a program.", evidence: [read.details.evidenceId] })).text')}`,
				);
			const refused = await record(audited);
			expect(refused.text).toStartWith("record_finding: NOT recorded — the support auditor judged this claim overreach: the stand-in says the read shows less\n");
			expect(asked).toHaveLength(1);
			expect(asked[0]).toContain("CLAIM 0: The file is a program.");
			const recorded = await record(unaudited);
			expect(recorded.text).toMatch(/^record_finding: recorded [0-9a-f]{8}\n/);
			expect(recorded.text).toContain("support audit: unaudited — no model / side turns unavailable");
		} finally {
			await audited.shutdown();
			await unaudited.shutdown();
		}
	}, 90_000);

	test("a real session through the real pair: the band the engine sends is drawn, a list opens as a panel of the binary's own functions, a compaction keeps the binary, and a branch and a tree leave it open", async () => {
		const h = await boot(await inMemory());
		try {
			const id = h.session.sessionManager.getSessionId();
			expect((await evalJs(h.session, `(await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })).text`)).isError).toBe(false);
			const band = h.widget("re.hud")!;
			expect(band[0]).toStartWith(`${TEST_BINARY.split(/[\\/]/).at(-1)}  `);
			expect(band[1]).toMatch(/^[1-9]\d* fn · 0 findings · 0 evidence$/);

			const opened = h.session.prompt("/re functions");
			expect(await until(() => h.overlays.length === 1, 20_000)).toBe(true);
			expect(h.overlays[0]!.render(120)[0]).toMatch(/^omp-re: functions [1-9]\d*$/);
			h.overlays[0]!.handleInput!("\x1b");
			await opened;

			const emit = (event: Record<string, unknown>) => h.session.extensionRunner!.emit({ sessionId: id, ...event } as never) as Promise<unknown>;
			const kept = (await emit({ type: "session.compacting", messages: [] })) as { context: string[] };
			expect(kept.context.join("\n")).toContain(`- Open binary: ${TEST_BINARY.split(/[\\/]/).at(-1)} (`);
			await emit({ type: "session_branch" });
			await emit({ type: "session_tree" });
			expect((await evalJs(h.session, '(await tool.rizin_command({ command: "afij", addr: "main" })).text')).text).toStartWith("rizin> afij @ main\n");
			expect(h.notes.filter((note) => note.startsWith("[runtime]") || note.startsWith("[error]"))).toEqual([]);
			// A session omp leaves for another has its rizin ended; coming back restores it from the record.
			await emit({ type: "session_before_switch", reason: "resume" });
			await emit({ type: "session_switch", reason: "resume" });
			expect((await evalJs(h.session, '(await tool.rizin_command({ command: "afij", addr: "main" })).text')).text).toStartWith("rizin> afij @ main\n");
		} finally {
			await h.shutdown();
		}
	}, 90_000);

	// The wording is the engine's and the filling is omp's side's: this is the one place the two are read together, as the operator reads them.
	test("the approval prompt's sentences are the engine's, filled from each call's arguments", async () => {
		const previous = process.env.OMPRE_ENABLE_DEBUGGER;
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		const h = await boot(await inMemory());
		try {
			const tools = new Map(reTools(h.session).map((tool) => [tool.definition.name, tool.definition.approval]));
			const reason = (name: string, args: unknown) => {
				const approval = tools.get(name);
				return typeof approval === "function" ? (approval(args) as { tier: string; reason: string }) : approval;
			};
			expect(reason("rizin_help", { query: "pdf" })).toBe("read");
			expect(reason("record_finding", {})).toBe("read");
			expect(reason("rename_function", { addr: "main", new: "start" })).toEqual({ tier: "write", reason: 'Rename function "main" to "start". Reversible with /re undo.' });
			expect(reason("set_variable_type", { addr: "main", var: "x".repeat(100), type: "int" })).toEqual({
				tier: "write",
				reason: `Set the type of ${JSON.stringify(`${"x".repeat(77)}...`)} in "main" to "int". Reversible with /re undo.`,
			});
			expect(reason("rizin_command", { command: "pdf", addr: "main" })).toEqual({ tier: "exec", reason: 'Run the rizin command "pdf @ main" on the open binary.' });
			expect(reason("rizin_command", { command: "p".repeat(200) })).toEqual({ tier: "exec", reason: `Run the rizin command ${JSON.stringify(`${"p".repeat(117)}...`)} on the open binary.` });
			expect(reason("rizin_cli", { tool: "rz-bin", args: ["-I", "/bin/ls"] })).toEqual({ tier: "exec", reason: 'Run "rz-bin -I /bin/ls".' });
			expect(reason("map_file", { path: "/tmp/dump", addr: "0x50000" })).toEqual({
				tier: "exec",
				reason: 'Map "/tmp/dump" into the session\'s address space at 0x50000 (read-only; re-applied on respawn). The file on disk is not modified.',
			});
			expect(reason("map_file", {})).toEqual({ tier: "exec", reason: "Map a file into the session's address space at ? (read-only; re-applied on respawn). The file on disk is not modified." });
			expect(reason("analyze", { pass: "aaaa" })).toEqual({ tier: "exec", reason: 'Run rizin analysis pass "aaaa" — this changes the analysis (it adds functions, xrefs, names, or types).' });
			expect(reason("apply_signatures", { source: "file", path: "/tmp/libc.sig" })).toEqual({ tier: "exec", reason: 'Apply the FLIRT signature file "/tmp/libc.sig" — this renames matched functions.' });
			expect(reason("apply_signatures", { source: "sigdb" })).toEqual({ tier: "exec", reason: "Re-apply rizin's built-in signature database — this renames matched functions." });
			expect(reason("export_project", {})).toEqual({ tier: "exec", reason: "Write the current analysis to a rizin project file in omp-re's output directory — the sample and the analysis are not modified." });
			expect(reason("rizin_emulate", { action: "step" })).toEqual({ tier: "exec", reason: "Run the target's code logic inside rizin's RzIL VM (interpreted, no OS process)." });
			expect(reason("rizin_debug", { action: "start" })).toEqual({ tier: "exec", reason: "Launch the target under a debugger — this EXECUTES it on this machine." });
			expect(reason("rizin_debug", { action: "start", attach: { pid: 4242 } })).toEqual({ tier: "exec", reason: "Attach the debugger to running PID 4242 — it will control that process." });
			expect(reason("rizin_debug", { action: "start", attach: { remote: "gdb://127.0.0.1:1234" } })).toEqual({ tier: "exec", reason: 'Connect the debugger to the remote target "gdb://127.0.0.1:1234".' });
			expect(reason("rizin_debug", { action: "step_back" })).toEqual({ tier: "exec", reason: "Move the debugged process backward through the recorded trace (step_back)." });
			expect(reason("rizin_debug", { action: "write_memory" })).toEqual({ tier: "exec", reason: "Modify the debugged process (write_memory)." });
			expect(reason("rizin_debug", { action: "registers" })).toEqual({ tier: "exec", reason: "Inspect the debugged process (registers)." });
			expect(reason("rizin_debug", {})).toEqual({ tier: "exec", reason: "Drive the debugged process." });
		} finally {
			await h.shutdown();
			if (previous === undefined) delete process.env.OMPRE_ENABLE_DEBUGGER;
			else process.env.OMPRE_ENABLE_DEBUGGER = previous;
		}
	}, 30_000);
});
