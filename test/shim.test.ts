/**
 * extensions/re as omp's side of the engine: the child process it starts and
 * ends, the wire to it, and what it does with the engine's answers — loaded
 * through omp's real SDK, like extension-sdk.test.ts.
 *
 * The first half needs neither SBCL's engine nor rizin: it puts a stand-in
 * where `sbcl` would be (OMPRE_SBCL_PATH), a script that speaks just enough
 * of docs/engine-protocol.md to be described. The second half runs the real
 * engine and, where rizin is there, a real binary.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { askSideModel, engine } from "../extensions/re/host.ts";
import { boot, canRunRizin, caught, evalJs, logSkip, rmDirSafe, type SdkHarness, TEST_BINARY } from "./helpers.ts";

logSkip("shim rizin tests");

let agentDir: string;
let originalAgentDir: string;
let scratch: string;

beforeAll(async () => {
	originalAgentDir = getAgentDir();
	agentDir = await mkdtemp(join(tmpdir(), "omp-re-shim-test-"));
	scratch = await mkdtemp(join(tmpdir(), "omp-re-shim-scratch-"));
	setAgentDir(agentDir);
});

afterAll(async () => {
	setAgentDir(originalAgentDir);
	rmDirSafe(agentDir);
	rmDirSafe(scratch);
});

const inMemory = async () => (await import("@oh-my-pi/pi-coding-agent")).SessionManager.inMemory();

/** Whether the process `pid` is still running. A child that exited stays in the process table until its parent collects it, so where the system says a process's state, that is read. */
function alive(pid: number): boolean {
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		return stat.slice(stat.lastIndexOf(")") + 2, stat.lastIndexOf(")") + 3) !== "Z";
	} catch (error) {
		if (existsSync("/proc/self/stat")) return false;
	}
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

async function until(holds: () => boolean, ms: number): Promise<boolean> {
	const deadline = Date.now() + ms;
	while (Date.now() < deadline) {
		if (holds()) return true;
		await Bun.sleep(20);
	}
	return holds();
}

/** Run `body` with OMPRE_SBCL_PATH naming `path`, and the variable as it was after. */
async function withSbcl<T>(path: string, body: () => Promise<T>): Promise<T> {
	const before = process.env.OMPRE_SBCL_PATH;
	process.env.OMPRE_SBCL_PATH = path;
	try {
		return await body();
	} finally {
		if (before === undefined) delete process.env.OMPRE_SBCL_PATH;
		else process.env.OMPRE_SBCL_PATH = before;
	}
}

/** The tools this extension registered, as opposed to omp's other extensions'. */
const ownTools = (h: SdkHarness) => h.session.extensionRunner!.getAllRegisteredTools().filter((tool) => tool.extensionPath.includes(join("extensions", "re")));

async function standIn(name: string, script: string): Promise<string> {
	const path = join(scratch, name);
	await writeFile(path, `#!/bin/sh\n${script}`);
	await chmod(path, 0o755);
	return path;
}

describe("starting the engine", () => {
	test("with no SBCL the session fails to load the extension, and the error says what to install", async () => {
		const missing = join(scratch, "no-such-sbcl");
		const failure = await withSbcl(missing, async () => boot(await inMemory()).then(() => null, (error: Error) => error.message));
		expect(failure).toContain(`omp-re: SBCL was not found (tried ${JSON.stringify(missing)})`);
		expect(failure).toContain("apt install sbcl cl-ppcre");
		expect(failure).toContain("OMPRE_SBCL_PATH");
	});

	// The stand-ins are shell scripts.
	test.skipIf(process.platform === "win32")("an engine that cannot load says why in its own words, and those are the error", async () => {
		const fatal = await standIn("fatal-engine", `printf '{"fatal":"omp-re: the Common Lisp library cl-ppcre was not found. Install it."}\\n'\nexit 3\n`);
		const failure = await withSbcl(fatal, async () => boot(await inMemory()).then(() => null, (error: Error) => error.message));
		expect(failure).toContain("omp-re: the Common Lisp library cl-ppcre was not found. Install it.");
	});

	test.skipIf(process.platform === "win32")("an engine that dies without a word is reported with what it wrote to its log", async () => {
		const dying = await standIn("dying-engine", "echo 'heap exhausted' >&2\nexit 7\n");
		const failure = await withSbcl(dying, async () => boot(await inMemory()).then(() => null, (error: Error) => error.message));
		expect(failure).toContain("omp-re: the engine process ended (status 7): heap exhausted");
	});

	test.skipIf(process.platform === "win32")(
		"the tools registered are the ones the engine describes — read off a wire that splits lines and characters, ends lines with CRLF, and carries a line that is not JSON",
		async () => {
			// Answers every request with {}, and `describe` with one tool whose description holds an em dash cut in two writes.
			const described = await standIn(
				"described-engine",
				[
					`printf '{"ready":1}\\r\\n'`,
					`printf 'a line that is not JSON\\n'`,
					"while IFS= read -r line; do",
					`  id=$(printf '%s' "$line" | sed -n 's/^{"id":\\([0-9]*\\),.*/\\1/p')`,
					`  [ -z "$id" ] && continue`,
					`  case "$line" in`,
					`    *'"method":"describe"'*)`,
					`      printf '{"id":%s,"result":{"tools":[{"name":"stand_in_tool","description":"split \\342\\200' "$id"`,
					"      sleep 0.2",
					`      printf '\\224 here","parameters":{"type":"object","properties":{"addr":{"type":"string"}}},"approval":"write",'`,
					`      printf '"approvalReason":[{"parts":["Touch ",{"pieces":[{"arg":"addr","missing":"?"}],"quote":true,"clip":8},"."]}]}],'`,
					`      printf '"commands":[{"name":"help","description":"show this list"}]}}\\r\\n' ;;`,
					`    *) printf '{"id":%s,"result":{}}\\n' "$id" ;;`,
					"  esac",
					"done",
					"",
				].join("\n"),
			);
			await withSbcl(described, async () => {
				const h = await boot(await inMemory());
				try {
					const registered = ownTools(h).map((tool) => tool.definition);
					expect(registered.map((tool) => tool.name)).toEqual(["stand_in_tool"]);
					expect(registered[0]!.description).toBe("split — here");
					expect(registered[0]!.parameters).toEqual({ type: "object", properties: { addr: { type: "string" } } });
					// The approval prompt's sentence is filled from the call's arguments without asking the engine: quoted, cut at the engine's bound.
					const approval = registered[0]!.approval as (args: unknown) => unknown;
					expect(approval({ addr: "main" })).toEqual({ tier: "write", reason: 'Touch "main".' });
					expect(approval({ addr: "0x0123456789" })).toEqual({ tier: "write", reason: 'Touch "0x012...".' });
					expect(approval({})).toEqual({ tier: "write", reason: 'Touch "?".' });
					expect(h.session.extensionRunner!.getCommand("re")!.getArgumentCompletions!("h")).toEqual([expect.objectContaining({ value: "help ", label: "help" })]);
				} finally {
					await h.shutdown();
				}
			});
		},
	);
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

	test("any other failure is not retried, and is answered as a reason, never thrown", async () => {
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
		expect(answer).toEqual({ reason: "the audit side turn failed: provider overloaded" });
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

		await a.shutdown();
		expect(alive(pid)).toBe(true);
		expect((await evalJs(b.session, '(await tool.rizin_command({ command: "" })).text')).text).toContain("omp-re — reverse engineering with rizin");

		const started = Date.now();
		await b.shutdown();
		expect(await until(() => !alive(pid), 2000)).toBe(true);
		expect(Date.now() - started).toBeLessThan(2000);
	}, 30_000);

	test("an engine that died is not kept: the session's next call starts another and is answered", async () => {
		const h = await boot(await inMemory());
		try {
			const pid = engine().pid!;
			await h.session.prompt("/re off");
			process.kill(pid, "SIGKILL");
			expect(await until(() => !alive(pid), 2000)).toBe(true);
			const manual = await evalJs(h.session, '(await tool.rizin_command({ command: "" })).text');
			expect(engine().pid).not.toBe(pid);
			// The new engine knows nothing the old one held in memory alone: `/re off` is such a thing, the record is not.
			expect(manual.text).toContain("omp-re — reverse engineering with rizin");
		} finally {
			await h.shutdown();
		}
	}, 30_000);

	test("every call that ran is in the audit log under omp's own tool-call id, and what the approval gate decided is forwarded to it", async () => {
		const h = await boot(await inMemory());
		try {
			const id = h.session.sessionManager.getSessionId();
			await h.session.getToolByName("rizin_help")!.execute("call-from-omp", { query: "pdf" }).catch(() => {});
			await h.session.extensionRunner!.emit({ type: "tool_approval_resolved", sessionId: id, toolCallId: "call-denied", toolName: "rename_function", approved: false, reason: "not now" } as never);
			await h.session.extensionRunner!.emit({ type: "tool_approval_resolved", sessionId: id, toolCallId: "call-other", toolName: "bash", approved: true } as never);
			const lines = (await readFile(join(agentDir, "re", "audit", `${id}.log`), "utf8"))
				.trim()
				.split("\n")
				.map((line) => JSON.parse(line) as Record<string, unknown>);
			expect(lines.map((line) => line.toolCallId)).toEqual(["call-from-omp", "call-denied"]);
			expect(lines[0]).toMatchObject({ sessionId: id, tool: "rizin_help", args: { query: "pdf" } });
			expect(lines[1]).toMatchObject({ tool: "rename_function", approved: false, reason: "not now" });
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

	test("the approval prompt's sentences are the engine's, filled from each call's arguments", async () => {
		const previous = process.env.OMPRE_ENABLE_DEBUGGER;
		process.env.OMPRE_ENABLE_DEBUGGER = "1";
		const h = await boot(await inMemory());
		try {
			const tools = new Map(ownTools(h).map((tool) => [tool.definition.name, tool.definition.approval]));
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
