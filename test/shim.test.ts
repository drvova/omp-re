/**
 * extensions/re as omp's side of the engine: the child process it starts and
 * ends, the wire to it, how long it waits, and what it does with the engine's
 * answers — loaded through omp's real SDK, like extension-sdk.test.ts, and
 * asked the way a model asks: from a cell of omp's own `eval`, through the
 * library the skill loads there.
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
import { boot, bootLoaded, canRunRizin, caught, evalJs, logSkip, ownSession, ROOT, runCell, type SdkHarness, scratchAgentDir, TEST_BINARY, until } from "./helpers.ts";

logSkip("shim rizin tests");

const agentDir = scratchAgentDir("shim-test");

/** A session with the plugin loaded and the library in its JavaScript kernel. */
const loaded = (options = {}) => bootLoaded(agentDir(), options);

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

/**
 * What a session is told when its engine does not start, and what a cell that asks for the engine is. omp's side
 * starts the engine when a session starts, to bring the session's binary back; a model's first call would start it
 * as well.
 */
async function startFailure(start: () => Promise<SdkHarness>): Promise<{ told: string; cell: string }> {
	const h = await start();
	try {
		expect(await until(() => h.notes.some((note) => note.startsWith("[error] ")), 10_000)).toBe(true);
		return { told: h.notes.find((note) => note.startsWith("[error] "))!, cell: (await evalJs(h.session, caught("await re.status()"))).text };
	} finally {
		await h.shutdown();
	}
}
const standInFailure = (behaviour: string) => withEngine(standIn(behaviour), () => startFailure(loaded));

/** What the stand-in answers the line `line` with, when that is JSON. What a cell shows is cut for a model's eyes, so the cell writes the answer to a file. */
async function standInSays<T>(h: SdkHarness, line: string): Promise<T> {
	const file = join(agentDir(), `said-${crypto.randomUUID()}.json`);
	const cell = await evalJs(h.session, `require("node:fs").writeFileSync(${JSON.stringify(file)}, await re.slash(${JSON.stringify(line)})); "written"`);
	expect(cell.text).toBe("written");
	return JSON.parse(await readFile(file, "utf8")) as T;
}

interface Heard {
	heard: { method: string; params: Record<string, unknown> & { session?: { id: string; cwd: string } }; request: boolean }[];
	violations: string[];
}

describe("starting the engine", () => {
	test("with no SBCL the session still loads, and both the operator and a cell that asks are told what to install", async () => {
		const missing = join(agentDir(), "no-such-sbcl");
		const before = process.env.OMPRE_SBCL_PATH;
		process.env.OMPRE_SBCL_PATH = missing;
		try {
			const { told, cell } = await startFailure(loaded);
			for (const said of [told, cell]) {
				expect(said).toContain(`omp-re: SBCL was not found (tried ${JSON.stringify(missing)})`);
				expect(said).toContain("apt install sbcl cl-ppcre");
				expect(said).toContain("OMPRE_SBCL_PATH");
			}
		} finally {
			if (before === undefined) delete process.env.OMPRE_SBCL_PATH;
			else process.env.OMPRE_SBCL_PATH = before;
		}
	}, 30_000);

	test("an engine that cannot load says why in its own words, and those are the error", async () => {
		const { told, cell } = await standInFailure("fatal");
		expect(told).toContain("omp-re: the Common Lisp library cl-ppcre was not found. Install it.");
		expect(cell).toContain("omp-re: the Common Lisp library cl-ppcre was not found. Install it.");
	}, 30_000);

	test("an engine that dies without a word is reported with what it wrote to its log", async () => {
		expect((await standInFailure("dying")).told).toContain("omp-re: the engine process ended (status 7): heap exhausted");
	}, 30_000);

	test("an engine of another protocol version is refused, and the error says to reinstall", async () => {
		const { told } = await standInFailure("other-version");
		expect(told).toContain(`omp-re: the extension speaks protocol ${PROTOCOL} and its engine protocol ${PROTOCOL + 1}`);
		expect(told).toContain("Reinstall or upgrade the omp-re plugin");
	}, 30_000);

	test("an engine that never becomes ready is ended at the start deadline, with what to check and what it had logged", async () => {
		const logged: string[] = [];
		const silent = new Engine({ command: standIn("silent"), handlers: {} as HostHandlers, log: (line) => void logged.push(line), deadlines: { startMs: 1000 } });
		const started = Date.now();
		const failure = await silent.request("preserved", { session: { id: "s", cwd: tmpdir() } }).then(() => null, (error: Error) => error.message);
		expect(failure).toContain("omp-re: the engine did not start within 1 s and was ended. Check that");
		expect(failure).toContain("; compiling file engine.lisp");
		expect(Date.now() - started).toBeLessThan(5000);
		await silent.exited;
		expect(alive(silent.pid!)).toBe(false);
		// What it wrote to its standard error reached the log as it came, not only in the error.
		expect(logged).toEqual(["; compiling file engine.lisp"]);
	});

	test("an answer is read off a wire that splits a character in two, ends lines with CRLF, and carries lines that are not messages, each noted in the log", async () => {
		await withEngine(standIn("framing"), async (logged) => {
			const h = await loaded();
			try {
				expect((await evalJs(h.session, 'await re.call("stand_in_tool", { addr: "split — here" })')).text).toBe("header\nbody of split — here\n[evidence 0a1b2c3d — cite it in record_finding]");
				expect(logged).toEqual(["skipped a line on the wire that is not a message: a line that is not JSON", "skipped a line on the wire that is not a message: [1, 2]"]);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);
});

describe("the wire, method by method, against a stand-in that holds both sides to stdio/protocol.json", () => {
	test("everything the engine asks of omp is answered as the protocol says, and done", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await loaded({ sideModel: (prompt: string) => `the side model read: ${prompt}` });
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
				expect(wire.judged).toEqual({ text: "the side model read: CLAIM 0: the stand-in asks" });
				expect(wire.unknownSession).toEqual({ error: 'omp-re: omp has no session "no-such-session"' });
				expect(wire.unknownMethod).toEqual({ error: 'omp-re: omp has no method "noSuchMethod"' });

				expect(h.notes).toEqual(expect.arrayContaining(["[info] notified at info", "[warning] notified at warning", "[error] notified at error", "[info] told at info", "[warning] told at warning", "[error] told at error"]));
				expect(h.session.sessionManager.getEntries().filter((one) => (one as { customType?: string }).customType === "re.binary")).toEqual([
					expect.objectContaining({ content: "[re: opened /stand/in]", details: { sha256: "00" } }),
				]);
				expect(h.session.extensionRunner!.getMessageRenderer("re.binary")).toBeDefined();
				// The state the engine sent outside any answer: the band is drawn as its lines.
				expect(h.widget("re.hud")).toEqual(["stand-in  ELF64 x86/64  entry 0x1000", "3 fn · 0 findings · 1 evidence"]);
				expect(h.widget("re.hud", 12)).toEqual(["stand-in  E…", "3 fn · 0 fi…"]);
				const { heard } = await standInSays<Heard>(h, "heard");
				expect(heard.at(-1)!.params).toEqual({ line: "heard", session: { id, cwd: h.session.sessionManager.getCwd() } });
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("the session's life, a compaction and an environment change are each said to the engine, as the protocol has them", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await loaded();
			try {
				const id = h.session.sessionManager.getSessionId();
				const emit = (event: Record<string, unknown>) => h.session.extensionRunner!.emit({ sessionId: id, ...event } as never) as Promise<unknown>;
				await emit({ type: "session_before_switch", reason: "new" });
				await emit({ type: "session_switch", reason: "new" });
				await emit({ type: "session_branch" });
				await emit({ type: "session_tree" });
				expect(await emit({ type: "session.compacting", messages: [] })).toEqual({ context: ["preserve: the stand-in's binary", "- Open binary: stand-in"] });
				process.env.OMPRE_STAND_IN_SETTING = "changed while the engine runs";
				const { heard, violations } = await standInSays<Heard>(h, "heard");
				delete process.env.OMPRE_STAND_IN_SETTING;
				expect(violations).toEqual([]);

				const said = heard.map((one) => [one.method, one.request ? "request" : "notification"]);
				expect(said).toEqual([["hello", "request"], ...["event", "event", "event", "event", "event", "preserved"].map((method) => [method, "request"]), ["environment", "notification"], ["command", "request"]]);
				const session = { id, cwd: h.session.sessionManager.getCwd() };
				expect(heard[0]!.params).toMatchObject({ protocol: PROTOCOL, stateDir: agentDir(), variables: { PATH: process.env.PATH } });
				expect(heard.slice(1, 6).map((one) => one.params)).toEqual([
					{ session, kind: "start" },
					{ session, kind: "before-switch" },
					{ session, kind: "switch" },
					{ session, kind: "branch", previous: id },
					{ session, kind: "tree" },
				]);
				expect(heard[6]!.params).toEqual({ session });
				expect(heard[7]!.params).toMatchObject({ stateDir: agentDir(), variables: { OMPRE_STAND_IN_SETTING: "changed while the engine runs" } });
				expect(Object.keys(heard[7]!.params.variables as object).every((name) => name === "PATH" || name.startsWith(CONSTANTS.environmentPrefix))).toBe(true);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("a session that ends says so to the engine, by its own id, while the engine goes on for the others", async () => {
		await withEngine(standIn("serve"), async () => {
			const staying = await loaded();
			try {
				const leaving = await loaded();
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

	test("a call's answer is what the cell gets: a refusal and a failure are thrown with the engine's words, a read is its text, and each is named in the engine's log by the eval call it came from", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await loaded();
			try {
				const cell = (code: string, callId: string) => runCell(h.session, "js", code, {}, undefined, callId);
				expect((await cell(caught('await re.call("stand_in_tool", { addr: "refuse" })'), "eval-1")).text).toBe("omp-re: refused by the stand-in");
				expect((await cell(caught('await re.call("stand_in_tool", { addr: "fail" })'), "eval-2")).text).toBe("the stand-in's tool failed");
				// Two calls of one cell, and a third from the next.
				const read = await cell('const first = await re.call("stand_in_tool", { addr: "main" }); await re.call("stand_in_tool", { addr: "other" }); first', "eval-3");
				expect(read).toMatchObject({ isError: false, text: "header\nbody of main\n[evidence 0a1b2c3d — cite it in record_finding]" });
				// What rizin printed comes whole and apart from the text, an integer past 2^53 exact, with the evidence id as it is cited.
				expect((await cell('const { data, evidence } = await re.json("ij", "main"); `${typeof data.wide} ${data.wide} ${data.addr} ${evidence}`', "eval-4")).text).toBe("bigint 18446744073709551615 main 0a1b2c3d");
				const { heard, violations } = await standInSays<Heard>(h, "heard");
				expect(violations).toEqual([]);
				const session = { id: h.session.sessionManager.getSessionId(), cwd: h.session.sessionManager.getCwd() };
				expect(heard.filter((one) => one.method === "call").map((one) => one.params)).toEqual([
					{ session, name: "stand_in_tool", arguments: { addr: "refuse" }, callId: "eval-1#1" },
					{ session, name: "stand_in_tool", arguments: { addr: "fail" }, callId: "eval-2#1" },
					{ session, name: "stand_in_tool", arguments: { addr: "main" }, callId: "eval-3#1" },
					{ session, name: "stand_in_tool", arguments: { addr: "other" }, callId: "eval-3#2" },
					{ session, name: "rizin_command", arguments: { command: "ij", addr: "main" }, callId: "eval-4#1" },
				]);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("a key the protocol names opens its list as a panel, a row as its code, and the code view's keys drive it", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await loaded();
			try {
				expect([...h.session.extensionRunner!.getShortcuts().keys()]).toEqual(expect.arrayContaining(KEYS.views.map((key) => key.key)));
				const opened = h.press(KEYS.views.find((key) => key.view === "functions")!.key);
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

	test("headless (omp -p), what the engine has to tell goes to standard output, a warning or an error to standard error, an error with a failing exit status", async () => {
		await withEngine(standIn("serve"), async () => {
			const h = await loaded({ headless: true });
			const { print, printError, failExit } = outside;
			const said: string[] = [];
			outside.print = (text) => void said.push(`out: ${text}`);
			outside.printError = (text) => void said.push(`err: ${text}`);
			outside.failExit = () => void said.push("exit status: failing");
			try {
				await standInSays(h, "wire");
				expect(said).toEqual(["out: told at info", "err: told at warning", "err: told at error", "exit status: failing"]);
			} finally {
				Object.assign(outside, { print, printError, failExit });
				await h.shutdown();
			}
		});
	}, 30_000);
});

describe("how long omp's side waits for the engine", () => {
	const BEAT_MS = 100;
	const session = { id: "s", cwd: tmpdir() };
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
			await obedient.request("preserved", { session });
			started = Date.now();
			await obedient.stop();
			expect(Date.now() - started).toBeLessThan(1000);
		}

		const deaf = start("deaf").engine;
		await deaf.request("preserved", { session });
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
		const a = await loaded();
		const pid = engine().pid!;
		const b = await loaded();
		expect(engine().pid).toBe(pid);
		expect(alive(pid)).toBe(true);

		expect((await evalJs(a.session, caught('await re.cmd("aflj")'))).text).toContain("omp-re: no binary open");
		// With no binary there is nothing to show but that: the band is the engine's two lines.
		expect(b.widget("re.hud")).toEqual(["no binary", "0 fn · 0 findings · 0 evidence"]);

		await a.shutdown();
		expect(alive(pid)).toBe(true);
		expect((await evalJs(b.session, "await re.help()")).text).toContain("omp-re — reverse engineering with rizin");

		const started = Date.now();
		await b.shutdown();
		expect(await until(() => !alive(pid), 2000)).toBe(true);
		expect(Date.now() - started).toBeLessThan(2000);
	}, 30_000);

	test("an engine that died is not kept: the session's next call starts another", async () => {
		const h = await loaded();
		try {
			const pid = engine().pid!;
			process.kill(pid, "SIGKILL");
			expect(await until(() => !alive(pid), 2000)).toBe(true);
			expect((await evalJs(h.session, "await re.help()")).text).toContain("omp-re — reverse engineering with rizin");
			expect(engine().pid).not.toBe(pid);
		} finally {
			await h.shutdown();
		}
	}, 30_000);

	test("every call that ran is in the audit log, named by the eval call it came from and its place in that cell; a line is not a call and leaves none", async () => {
		const h = await loaded();
		try {
			const id = h.session.sessionManager.getSessionId();
			// Without rizin the calls fail, after their lines are written: either way they ran.
			await runCell(h.session, "js", 'await re.call("rizin_help", { query: "pdf" }).catch(() => {}); await re.status(); await re.call("rizin_help", { query: "px" }).catch(() => {})', {}, undefined, "call-from-omp");
			const lines = (await readFile(join(agentDir(), "re", "audit", `${id}.log`), "utf8"))
				.trim()
				.split("\n")
				.map((line) => JSON.parse(line) as Record<string, unknown>);
			expect(lines.map((line) => line.toolCallId)).toEqual(["call-from-omp#1", "call-from-omp#2"]);
			expect(lines[0]).toMatchObject({ sessionId: id, tool: "rizin_help", args: { query: "pdf" } });
			expect(Object.keys(lines[0]!).sort()).toEqual(["args", "sessionId", "tool", "toolCallId", "ts"]);
		} finally {
			await h.shutdown();
		}
	}, 30_000);
});

describe.skipIf(!canRunRizin)("against rizin", () => {
	const open = `await re.open(${JSON.stringify(TEST_BINARY)})`;

	test("an annotation is recorded in omp's own session under the entry id omp gave it, which is what the line undo names", async () => {
		const h = await loaded();
		try {
			const done = await evalJs(h.session, `${open}\nawait re.call("set_comment", { addr: "main", text: "shim test" })`);
			expect(done.isError).toBe(false);
			expect((await evalJs(h.session, 'await re.slash("undo")')).text).toStartWith("omp-re: undid set_comment @ ");
			const custom = h.session.sessionManager.getEntries().filter((entry) => entry.type === "custom") as { id: string; customType: string; data: Record<string, unknown> }[];
			const annotation = custom.find((entry) => entry.customType === "re.annotation")!;
			const undo = custom.find((entry) => entry.customType === "re.undo")!;
			expect(annotation.data).toMatchObject({ kind: "set_comment", newValue: "shim test" });
			expect(undo.data.undidEntryId).toBe(annotation.id);
			expect((await evalJs(h.session, caught('await re.slash("undo")'))).text).toBe("omp-re: no annotation left to undo");
		} finally {
			await h.shutdown();
		}
	}, 60_000);

	test("the claim audit reaches omp's side model through the real pair: the verdict it gives decides whether a finding is recorded, and a session with no model records it unaudited", async () => {
		const asked: string[] = [];
		const audited = await loaded({
			sideModel: (prompt: string) => {
				asked.push(prompt);
				return '[{"index": 0, "verdict": "overreach", "reason": "the stand-in says the read shows less"}]';
			},
		});
		const unaudited = await loaded();
		try {
			const record = (h: SdkHarness) => evalJs(h.session, `${open}\nconst read = await re.json("ij")\n${caught('m = await re.call("record_finding", { claim: "The file is a program.", evidence: [read.evidence] })')}`);
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

	test("a real session through the real pair: the band the engine sends is drawn, a key opens a panel of the binary's own functions, a compaction keeps the binary, and a branch and a tree leave it open", async () => {
		const h = await loaded();
		try {
			const id = h.session.sessionManager.getSessionId();
			expect((await evalJs(h.session, open)).isError).toBe(false);
			const band = h.widget("re.hud")!;
			expect(band[0]).toStartWith(`${TEST_BINARY.split(/[\\/]/).at(-1)}  `);
			expect(band[1]).toMatch(/^[1-9]\d* fn · 0 findings · 0 evidence$/);

			const opened = h.press("alt+g");
			expect(await until(() => h.overlays.length === 1, 20_000)).toBe(true);
			expect(h.overlays[0]!.render(120)[0]).toMatch(/^omp-re: functions [1-9]\d*$/);
			h.overlays[0]!.handleInput!("\x1b");
			await opened;

			const emit = (event: Record<string, unknown>) => h.session.extensionRunner!.emit({ sessionId: id, ...event } as never) as Promise<unknown>;
			const kept = (await emit({ type: "session.compacting", messages: [] })) as { context: string[] };
			expect(kept.context.join("\n")).toContain(`- Open binary: ${TEST_BINARY.split(/[\\/]/).at(-1)} (`);
			await emit({ type: "session_branch" });
			await emit({ type: "session_tree" });
			expect((await evalJs(h.session, 'await re.cmd("afij", "main")')).text).toStartWith("rizin> afij @ main\n");
			expect(h.notes.filter((note) => note.startsWith("[runtime]") || note.startsWith("[error]"))).toEqual([]);
			// A session omp leaves for another has its rizin ended; coming back restores it from the record.
			await emit({ type: "session_before_switch", reason: "resume" });
			await emit({ type: "session_switch", reason: "resume" });
			expect((await evalJs(h.session, 'await re.cmd("afij", "main")')).text).toStartWith("rizin> afij @ main\n");
		} finally {
			await h.shutdown();
		}
	}, 90_000);

	test("a session whose binary is gone when it comes back is told so, once, as an error", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		const copy = join(agentDir(), "gone-binary");
		await Bun.write(copy, Bun.file(TEST_BINARY));
		const manager = (await ownSession(agentDir())) as { getCwd(): string; ensureOnDisk(): Promise<void>; getSessionFile(): string };
		await manager.ensureOnDisk();
		const first = await boot(manager, { skills: true, cwd: manager.getCwd() });
		expect((await evalJs(first.session, `%load skill://re-triage/recipes.js`)).isError).toBe(false);
		expect((await evalJs(first.session, `await re.open(${JSON.stringify(copy)})`)).isError).toBe(false);
		const file = manager.getSessionFile();
		await first.shutdown();
		const { rmSync } = await import("node:fs");
		rmSync(copy);
		const second = await boot(await SessionManager.open(file), { cwd: manager.getCwd() });
		try {
			expect(await until(() => second.notes.some((note) => note.startsWith("[error] ")), 20_000)).toBe(true);
			expect(second.notes.filter((note) => note.startsWith("[error] "))).toEqual([expect.stringContaining("gone-binary")]);
		} finally {
			await second.shutdown();
		}
	}, 60_000);
});
