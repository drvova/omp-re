/**
 * The way from omp's `eval` to the engine (extensions/re/bridge.ts and the
 * client in skills/re-triage/recipes.js and recipes.py): who may use it,
 * which session a kernel's request is for, and what a cell that stops
 * waiting does to the engine's work.
 *
 * It is driven as a model drives it — real cells in omp's two kernels — and,
 * for what no cell would send, by requests made straight at the listener.
 * The engine is test/stand-in-engine.ts wherever what matters is what omp's
 * side said to it, and the real one where rizin has to be there.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bridgeDirectories } from "../extensions/re/bridge.ts";
import { outside } from "../extensions/re/host.ts";
import { CONSTANTS } from "../extensions/re/protocol.ts";
import { boot, bootLoaded, canRunRizin, caught, evalJs, evalPy, LOAD, logSkip, ownSession, pythonKernel, ROOT, runCell, type SdkHarness, scratchAgentDir, TEST_BINARY } from "./helpers.ts";

logSkip("bridge rizin tests");

const agentDir = scratchAgentDir("bridge-test");
const python = await pythonKernel();
if (!python.ok) console.log(`omp-re: skipping the Python cells of bridge — ${python.reason ?? "omp found no Python"}`);
const posix = process.platform !== "win32";

/** Run `body` with the stand-in where the engine would be. */
async function withStandIn<T>(body: () => Promise<T>): Promise<T> {
	const { engineCommand } = outside;
	outside.engineCommand = () => [process.execPath, join(ROOT, "test", "stand-in-engine.ts"), "serve"];
	try {
		return await body();
	} finally {
		outside.engineCommand = engineCommand;
	}
}

interface Heard {
	heard: { method: string; params: Record<string, unknown> & { session?: { id: string } }; request: boolean }[];
}

/** Everything omp's side said to the stand-in, read through a cell of `h`. */
async function heardBy(h: SdkHarness): Promise<Heard["heard"]> {
	const file = join(agentDir(), `heard-${crypto.randomUUID()}.json`);
	expect((await evalJs(h.session, `require("node:fs").writeFileSync(${JSON.stringify(file)}, await re.slash("heard")); "written"`)).text).toBe("written");
	return (JSON.parse(await readFile(file, "utf8")) as Heard).heard;
}

/** The file this omp process's kernels find the listener by, and what it holds. */
function discovery(): { file: string; url: string; token: string; pid: number; bridge: number } | undefined {
	for (const directory of bridgeDirectories()) {
		const file = join(directory, `${process.pid}.json`);
		if (existsSync(file)) return { file, ...(JSON.parse(readFileSync(file, "utf8")) as { url: string; token: string; pid: number; bridge: number }) };
	}
	return undefined;
}

const post = (url: string, method: string, body: unknown, token?: string) =>
	fetch(`${url}/v${CONSTANTS.bridgeVersion}/${method}`, { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body), headers: token === undefined ? {} : { authorization: `Bearer ${token}` } }).then(async (response) => ({
		status: response.status,
		body: (await response.json()) as { error?: string } & Record<string, unknown>,
	}));

describe("the listener: one per omp process, for this user's kernels alone", () => {
	test("its file is the owner's alone, in a directory that is, holds what a kernel needs, and is gone when the last session is", async () => {
		await withStandIn(async () => {
			expect(discovery()).toBeUndefined();
			const a = await bootLoaded(agentDir());
			const found = discovery()!;
			expect(found).toMatchObject({ url: expect.stringMatching(/^http:\/\/127\.0\.0\.1:\d+$/), token: expect.stringMatching(/^[0-9a-f]{64}$/), pid: process.pid, bridge: CONSTANTS.bridgeVersion });
			if (posix) {
				expect(statSync(found.file).mode & 0o777).toBe(0o600);
				expect(statSync(join(found.file, "..")).mode & 0o777).toBe(0o700);
			}
			// A second session of the process is served by the same listener.
			const b = await bootLoaded(agentDir());
			expect(discovery()).toEqual(found);
			await a.shutdown();
			expect(discovery()).toEqual(found);
			await b.shutdown();
			expect(discovery()).toBeUndefined();
			expect(await fetch(found.url).then(() => "answered", () => "gone")).toBe("gone");
			// The next session gets a listener, and a token, of its own.
			const c = await bootLoaded(agentDir());
			try {
				expect(discovery()!.token).not.toBe(found.token);
			} finally {
				await c.shutdown();
			}
		});
	}, 30_000);

	test("a request without the token, or with another, is refused before anything of it is read; with it, only what the listener has is served", async () => {
		await withStandIn(async () => {
			const h = await bootLoaded(agentDir());
			try {
				const { url, token } = discovery()!;
				const kernel = { language: "js", sessionFile: h.session.sessionManager.getSessionFile(), cwd: h.session.sessionManager.getCwd() };
				const refused = { status: 401, body: { error: "omp-re: this request does not carry the token of omp's listener" } };
				expect(await post(url, "command", { kernel, line: "status" })).toEqual(refused);
				expect(await post(url, "command", { kernel, line: "status" }, `${token.slice(0, -1)}0`)).toEqual(refused);
				expect(await post(url, "command", { kernel, line: "status" }, "")).toEqual(refused);
				expect(await post(url, "command", "this is not JSON")).toEqual(refused);
				expect((await heardBy(h)).filter((one) => one.method === "command").map((one) => one.params.line)).toEqual(["heard"]);

				expect(await post(url, "command", { kernel, line: "status" }, token)).toEqual({ status: 200, body: { text: "stand-in: status", failed: false } });
				expect(await post(url, "whoami", { kernel }, token)).toEqual({ status: 200, body: { bridge: CONSTANTS.bridgeVersion } });
				expect(await post(url, "describe", { kernel }, token)).toMatchObject({ status: 404 });
				expect((await fetch(`${url}/v${CONSTANTS.bridgeVersion}/whoami`, { headers: { authorization: `Bearer ${token}` } })).status).toBe(404);
				expect(await post(url, "command", "this is not JSON", token)).toEqual({ status: 400, body: { error: "omp-re: the request's body is not JSON" } });
				expect(await post(url, "command", { line: "status" }, token)).toEqual({ status: 400, body: { error: "omp-re: the request does not say which kernel sent it" } });
				expect(await post(url, "command", { kernel, line: 42 }, token)).toEqual({ status: 400, body: { error: "omp-re: a line is a string" } });
				expect(await post(url, "call", { kernel, name: "stand_in_tool", arguments: [] }, token)).toMatchObject({ status: 400 });
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test.skipIf(!posix)("a file left by an omp process that is gone is removed when the next one starts listening", async () => {
		await withStandIn(async () => {
			const first = await bootLoaded(agentDir());
			const directory = join(discovery()!.file, "..");
			await first.shutdown();
			// No process has this id: it is past what the system gives out.
			const stale = join(directory, "4194999.json");
			writeFileSync(stale, "{}");
			const h = await bootLoaded(agentDir());
			try {
				expect(existsSync(stale)).toBe(false);
				expect(readdirSync(directory)).toContain(`${process.pid}.json`);
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test("with OMPRE_DISABLED=1 the plugin starts nothing: no listener, no engine, nothing bound — and a cell that loads the library is told so", async () => {
		const { engineCommand, listen } = outside;
		const started: string[] = [];
		outside.engineCommand = () => {
			started.push("engine");
			return engineCommand();
		};
		outside.listen = (answer) => {
			started.push("listener");
			return listen(answer);
		};
		process.env.OMPRE_DISABLED = "1";
		try {
			const manager = (await ownSession(agentDir())) as { getCwd(): string };
			const h = await boot(manager, { skills: true, cwd: manager.getCwd() });
			try {
				expect(started).toEqual([]);
				expect(discovery()).toBeUndefined();
				expect(h.widget("re.hud")).toBeUndefined();
				expect([...h.session.extensionRunner!.getShortcuts().values()].filter((shortcut) => shortcut.extensionPath.includes(join("extensions", "re")))).toEqual([]);
				// The skill is omp's to list; its library finds nobody to ask, and says why.
				expect((await evalJs(h.session, LOAD.js)).isError).toBe(false);
				const refused = (await evalJs(h.session, caught("await re.status()"))).text;
				expect(refused).toStartWith("omp-re: no omp-re listener for this eval kernel was found in ");
				expect(refused).toEndWith("The plugin is not loaded in this omp, or is switched off (OMPRE_DISABLED=1).");
				// An unloaded library is nobody's to explain here.
				expect((await evalPy(h.session, "omp_re")).text).not.toContain("omp-re:");
				expect(started).toEqual([]);
			} finally {
				await h.shutdown();
			}
		} finally {
			delete process.env.OMPRE_DISABLED;
			Object.assign(outside, { engineCommand, listen });
		}
	}, 30_000);
});

describe("which session a kernel's request is for", () => {
	test("two sessions in one omp process, each with its file: a cell's request reaches the engine as its own session's, never the other's", async () => {
		await withStandIn(async () => {
			const a = await bootLoaded(agentDir());
			const b = await bootLoaded(agentDir());
			try {
				const [idA, idB] = [a, b].map((h) => h.session.sessionManager.getSessionId());
				await runCell(a.session, "js", 'await re.call("stand_in_tool", { addr: "from-a" })', {}, undefined, "cell-a");
				await runCell(b.session, "js", 'await re.call("stand_in_tool", { addr: "from-b" })', {}, undefined, "cell-b");
				// At once from both, each with a call that waits its turn in the other's shadow.
				await Promise.all([runCell(a.session, "js", 'await Promise.all([re.slash("one"), re.call("stand_in_tool", { addr: "again-a" })])'), runCell(b.session, "js", 'await Promise.all([re.slash("two"), re.call("stand_in_tool", { addr: "again-b" })])')]);
				const calls = (await heardBy(a)).filter((one) => one.method === "call").map((one) => [one.params.session!.id, (one.params.arguments as { addr: string }).addr]);
				expect(calls.slice(0, 2)).toEqual([
					[idA, "from-a"],
					[idB, "from-b"],
				]);
				expect(calls.slice(2).sort()).toEqual(
					[
						[idA, "again-a"],
						[idB, "again-b"],
					].sort(),
				);
				const lines = (await heardBy(a)).filter((one) => one.method === "command" && ["one", "two"].includes(one.params.line as string)).map((one) => [one.params.session!.id, one.params.line]);
				expect(lines.sort()).toEqual(
					[
						[idA, "one"],
						[idB, "two"],
					].sort(),
				);
			} finally {
				await a.shutdown();
				await b.shutdown();
			}
		});
	}, 30_000);

	test("sessions omp keeps no file for are told apart by their directory; two in one directory share a kernel, and its request is refused, not guessed", async () => {
		await withStandIn(async () => {
			const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
			const shared = mkdtempSync(join(tmpdir(), "omp-re-shared-"));
			const apart = mkdtempSync(join(tmpdir(), "omp-re-apart-"));
			const first = await boot(SessionManager.inMemory(shared), { skills: true, cwd: shared });
			const alone = await boot(SessionManager.inMemory(apart), { skills: true, cwd: apart });
			try {
				for (const h of [first, alone]) expect((await evalJs(h.session, LOAD.js)).isError).toBe(false);
				expect((await evalJs(first.session, 'await re.slash("mine")')).text).toBe("stand-in: mine");
				const second = await boot(SessionManager.inMemory(shared), { skills: true, cwd: shared });
				try {
					const refusal = `omp-re: 2 sessions without a session file in ${shared} share this eval kernel, and a cell cannot say which of them it runs for. Give each a directory of its own, or let omp keep a session file.`;
					expect((await evalJs(first.session, caught('await re.slash("whose")'))).text).toBe(refusal);
					expect((await evalJs(second.session, caught('await re.call("stand_in_tool", { addr: "whose" })'))).text).toBe(refusal);
					// The one in a directory of its own is served all the while.
					expect((await evalJs(alone.session, 'await re.slash("still mine")')).text).toBe("stand-in: still mine");
				} finally {
					await second.shutdown();
				}
				// With the other gone there is one again.
				expect((await evalJs(first.session, 'await re.slash("mine again")')).text).toBe("stand-in: mine again");
				const said = (await heardBy(first)).filter((one) => one.method !== "event" && one.method !== "hello").map((one) => one.params.line ?? (one.params.arguments as { addr?: string } | undefined)?.addr);
				expect(said).toEqual(["mine", "still mine", "mine again", "heard"]);
			} finally {
				await first.shutdown();
				await alone.shutdown();
			}
		});
	}, 30_000);

	test("a kernel that names a session this omp does not have is refused, by what it named", async () => {
		await withStandIn(async () => {
			const h = await bootLoaded(agentDir());
			try {
				const { url, token } = discovery()!;
				expect(await post(url, "whoami", { kernel: { language: "py", sessionFile: "/no/such/session.jsonl", cwd: "/" } }, token)).toEqual({
					status: 409,
					body: { error: "omp-re: omp has no session with the session file /no/such/session.jsonl that this plugin is loaded in" },
				});
				expect(await post(url, "command", { kernel: { language: "js", cwd: "/no/such/directory" }, line: "status" }, token)).toEqual({
					status: 409,
					body: { error: "omp-re: omp has no session without a session file in /no/such/directory that this plugin is loaded in" },
				});
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test.skipIf(!posix)("where the kernel's parent is not omp, a session with a file is found by a listener that knows that file; one without is not looked for", async () => {
		await withStandIn(async () => {
			const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
			const cwd = mkdtempSync(join(tmpdir(), "omp-re-launcher-"));
			const withFile = await boot(await ownSession(agentDir()), { skills: true });
			const fileless = await boot(SessionManager.inMemory(cwd), { skills: true, cwd });
			const found = discovery()!;
			// As a launcher between omp and the kernel leaves it: no file under the kernel's parent's id. Process 1 is always there, so the file is not swept.
			const elsewhere = join(found.file, "..", "1.json");
			renameSync(found.file, elsewhere);
			try {
				for (const h of [withFile, fileless]) expect((await evalJs(h.session, LOAD.js)).isError).toBe(false);
				expect((await evalJs(withFile.session, 'await re.slash("found")')).text).toBe("stand-in: found");
				expect((await evalJs(fileless.session, caught('await re.slash("found")'))).text).toStartWith("omp-re: no omp-re listener for this eval kernel was found in ");
			} finally {
				renameSync(elsewhere, found.file);
				await withFile.shutdown();
				await fileless.shutdown();
			}
		});
	}, 30_000);
});

describe("a cell that stops waiting", () => {
	const waiting = 'await re.call("stand_in_tool", { addr: "wait" })';
	const cancelled = async (h: SdkHarness) => {
		const heard = await heardBy(h);
		const asked = heard.filter((one) => one.method === "call" && (one.params.arguments as { addr: string }).addr === "wait").length;
		return { asked, cancels: heard.filter((one) => one.method === "cancel").length };
	};
	/** Wait until the stand-in has been asked `asked` calls that wait and told to cancel `cancels` of them, as `through` hears it. */
	async function comesTo(through: SdkHarness, wanted: { asked: number; cancels: number }): Promise<{ asked: number; cancels: number }> {
		let seen = await cancelled(through);
		for (const deadline = Date.now() + 10_000; Date.now() < deadline && (seen.asked < wanted.asked || seen.cancels < wanted.cancels); seen = await cancelled(through)) await Bun.sleep(50);
		return seen;
	}

	test("a JavaScript cell that is interrupted, or runs past its timeout, cancels the engine's call; the kernel is gone, and the next cell is told to load the library again", async () => {
		await withStandIn(async () => {
			const h = await bootLoaded(agentDir());
			// A second session, to ask the stand-in what it heard while the first one's cell waits.
			const watcher = await bootLoaded(agentDir());
			try {
				const stop = new AbortController();
				const interrupted = runCell(h.session, "js", waiting, {}, stop.signal);
				// Asked, and not cancelled while the cell waits.
				expect(await comesTo(watcher, { asked: 1, cancels: 0 })).toEqual({ asked: 1, cancels: 0 });
				stop.abort();
				expect((await interrupted).isError).toBe(true);
				expect(await comesTo(watcher, { asked: 1, cancels: 1 })).toEqual({ asked: 1, cancels: 1 });

				const lost = await evalJs(h.session, "await re.status()");
				expect(lost.text).toEndWith(`then run yours again: ${LOAD.js}`);
				expect((await evalJs(h.session, LOAD.js)).isError).toBe(false);
				const late = await runCell(h.session, "js", waiting, { timeout: 1 });
				expect(late.isError).toBe(true);
				expect(await comesTo(watcher, { asked: 2, cancels: 2 })).toEqual({ asked: 2, cancels: 2 });
				// The session is served as before.
				expect((await evalJs(h.session, LOAD.js)).isError).toBe(false);
				expect((await evalJs(h.session, 'await re.slash("after")')).text).toBe("stand-in: after");
			} finally {
				await h.shutdown();
				await watcher.shutdown();
			}
		});
	}, 60_000);

	test.skipIf(!python.ok)("a Python cell that is interrupted, or runs past its timeout, cancels the engine's call and keeps its kernel: `omp_re` and the cell's own names are still there", async () => {
		await withStandIn(async () => {
			const h = await bootLoaded(agentDir());
			const watcher = await bootLoaded(agentDir());
			try {
				expect((await evalPy(h.session, `${LOAD.py}`)).isError).toBe(false);
				expect((await evalPy(h.session, "kept = 41")).isError).toBe(false);
				const call = 'omp_re.call("stand_in_tool", addr="wait")';
				const stop = new AbortController();
				const interrupted = runCell(h.session, "py", call, {}, stop.signal);
				expect(await comesTo(watcher, { asked: 1, cancels: 0 })).toEqual({ asked: 1, cancels: 0 });
				stop.abort();
				expect((await interrupted).text).toContain("KeyboardInterrupt");
				expect(await comesTo(watcher, { asked: 1, cancels: 1 })).toEqual({ asked: 1, cancels: 1 });

				const late = await runCell(h.session, "py", call, { timeout: 1 });
				expect(late.isError).toBe(true);
				expect(await comesTo(watcher, { asked: 2, cancels: 2 })).toEqual({ asked: 2, cancels: 2 });
				expect((await evalPy(h.session, 'print(kept + 1, omp_re.slash("after"))')).text).toBe("42 stand-in: after");
			} finally {
				await h.shutdown();
				await watcher.shutdown();
			}
		});
	}, 60_000);

	test("a cell that ended without waiting for what it asked cancels nothing: omp may have moved it to the background, where it runs on", async () => {
		await withStandIn(async () => {
			const h = await bootLoaded(agentDir());
			try {
				const cell = runCell(h.session, "js", 'globalThis.pending = re.call("stand_in_tool", { addr: "wait" }).catch((error) => error.message); await new Promise((done) => setTimeout(done, 300)); "left it"', {}, undefined, "cell-left");
				expect((await cell).text).toBe("left it");
				// The agent loop says a tool call is over (tool_execution_end); the suites run the tool itself, so it is said here.
				await h.session.extensionRunner!.emit({ type: "tool_execution_end", toolName: "eval", toolCallId: "cell-left", sessionId: h.session.sessionManager.getSessionId() } as never);
				await Bun.sleep(300);
				expect(await cancelled(h)).toEqual({ asked: 1, cancels: 0 });
			} finally {
				await h.shutdown();
			}
		});
	}, 30_000);

	test.skipIf(!canRunRizin)("against rizin: an interrupted cell ends the analysis it was waiting for, as aborted, and the session goes on", async () => {
		const h = await bootLoaded(agentDir());
		try {
			const large = ["/usr/bin/python3", "/usr/bin/perl", "/bin/bash"].find((path) => existsSync(path)) ?? TEST_BINARY;
			const stop = new AbortController();
			const opening = runCell(h.session, "js", `await re.open(${JSON.stringify(large)})`, { timeout: 60 }, stop.signal);
			// The engine says the analysis is under way on the session's status line; by then rizin is running.
			await Bun.sleep(1500);
			const started = Date.now();
			stop.abort();
			expect((await opening).isError).toBe(true);
			expect((await evalJs(h.session, LOAD.js)).isError).toBe(false);
			// The engine gave the session back at once: the open did not finish, and nothing is open.
			expect((await evalJs(h.session, caught('await re.cmd("ij")'))).text).toContain("omp-re: no binary open");
			expect(Date.now() - started).toBeLessThan(5000);
			expect((await evalJs(h.session, `await re.open(${JSON.stringify(TEST_BINARY)})`)).isError).toBe(false);
		} finally {
			await h.shutdown();
		}
	}, 60_000);
});
