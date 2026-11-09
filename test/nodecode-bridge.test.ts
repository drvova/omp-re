/**
 * The headless host (nodecode/host.ts) and the stdio bridge (nodecode/bridge.ts)
 * that the nodecode cell drives. The host is exercised in-process; the bridge
 * as the child process the cell spawns, over its real line protocol.
 *
 * The rizin-free half runs everywhere (CI included). The rizin half opens the
 * test binary and checks what only a second host can get wrong: that a call
 * made here is audited and recorded as evidence exactly like one made in omp,
 * and that a new process restores the session from its record.
 * The Lisp side of the seam has its own suite: test/nodecode/smoke.lisp.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { RE_MUTATE_TOOL_NAMES, RE_RIZIN_TOOL_NAMES, RE_SESSION_TOOL_NAMES } from "../extensions/re/audit.ts";
import { HeadlessSession } from "../nodecode/host.ts";
import { canRunRizin, logSkip, rmDirSafe, TEST_BINARY } from "./helpers.ts";

logSkip("nodecode bridge rizin tests");

const BRIDGE = resolve(import.meta.dir, "../nodecode/bridge.ts");

interface Reply {
	id?: number;
	ok: boolean;
	text?: string;
	isError?: boolean;
	error?: string;
	version?: string;
	tools?: { name: string; description: string; approval: string; parameters: { type?: string; properties?: Record<string, unknown>; required?: string[] } }[];
	commands?: { name: string }[];
}

/** The bridge as the cell runs it: a child process, one JSON line each way. */
function startBridge(agentDir: string, env: Record<string, string> = {}) {
	const proc = Bun.spawn(["bun", BRIDGE], {
		stdin: "pipe",
		stdout: "pipe",
		stderr: "pipe",
		env: { ...process.env, PI_CODING_AGENT_DIR: agentDir, ...env },
	});
	const waiting = new Map<number, (reply: Reply) => void>();
	const unsolicited: Reply[] = [];
	let nextId = 0;
	const pump = (async () => {
		let buffered = "";
		const decoder = new TextDecoder();
		for await (const chunk of proc.stdout) {
			buffered += decoder.decode(chunk, { stream: true });
			let newline = buffered.indexOf("\n");
			while (newline !== -1) {
				const line = buffered.slice(0, newline);
				buffered = buffered.slice(newline + 1);
				newline = buffered.indexOf("\n");
				// Every stdout line must be a frame: the engine's own prints may never reach this stream.
				const reply = JSON.parse(line) as Reply;
				const resolveReply = reply.id === undefined ? undefined : waiting.get(reply.id);
				if (resolveReply) {
					waiting.delete(reply.id!);
					resolveReply(reply);
				} else unsolicited.push(reply);
			}
		}
	})();
	return {
		proc,
		unsolicited,
		raw(line: string) {
			proc.stdin.write(`${line}\n`);
			proc.stdin.flush();
		},
		send(request: Record<string, unknown>): { id: number; reply: Promise<Reply> } {
			const id = ++nextId;
			const reply = new Promise<Reply>((done) => waiting.set(id, done));
			this.raw(JSON.stringify({ id, ...request }));
			return { id, reply };
		},
		ask(request: Record<string, unknown>): Promise<Reply> {
			return this.send(request).reply;
		},
		async stop(): Promise<number> {
			proc.stdin.end();
			const code = await proc.exited;
			await pump;
			return code;
		},
	};
}

describe("headless host", () => {
	let dir: string;
	let session: HeadlessSession;
	let previousAgentDir: string;

	beforeAll(async () => {
		dir = await mkdtemp(join(tmpdir(), "omp-re-headless-"));
		// The agent dir is process-wide and other suites share this process: put it back afterwards.
		previousAgentDir = getAgentDir();
		setAgentDir(dir);
		session = await HeadlessSession.open("host-test", { stateDir: join(dir, "state") });
	});
	afterAll(async () => {
		await session.close();
		setAgentDir(previousAgentDir);
		rmDirSafe(dir);
	});

	test("registers the engine's tools, with JSON schemas a foreign host can advertise", () => {
		const tools = session.tools();
		const names = tools.map((t) => t.name);
		for (const name of [...Object.keys(RE_MUTATE_TOOL_NAMES), ...Object.keys(RE_RIZIN_TOOL_NAMES), ...Object.keys(RE_SESSION_TOOL_NAMES)]) expect(names).toContain(name);
		const command = tools.find((t) => t.name === "rizin_command")!;
		expect(command.parameters.type).toBe("object");
		expect(command.parameters.required).toEqual(["command"]);
		expect(command.description.length).toBeGreaterThan(20);
		expect(tools.find((t) => t.name === "open_binary")!.approval).toBe("read");
	});

	test("registers the /re command", () => {
		expect(session.commands().map((c) => c.name)).toEqual(["re"]);
	});

	test("arguments that do not fit the schema are a failed result, not a throw", async () => {
		const result = await session.callTool("rizin_command", {});
		expect(result.isError).toBe(true);
		expect(result.text).toContain("do not fit its schema");
	});

	test("an unknown tool is a failed result", async () => {
		expect(await session.callTool("no_such_tool", {})).toEqual({ text: expect.stringContaining("no tool named"), isError: true });
	});

	test("a tool that needs a binary fails in the engine's own words when none is open", async () => {
		const result = await session.callTool("rizin_command", { command: "aflj" });
		expect(result.isError).toBe(true);
		expect(result.text.length).toBeGreaterThan(0);
	});

	test("/re answers through the captured headless output", async () => {
		const status = await session.runCommand("re", "status");
		expect(status.isError).toBe(false);
		expect(status.text).toContain("binary: none");
		const help = await session.runCommand("re", "help");
		expect(help.text).toContain("verify");
	});

	test("a failing /re line fails that command only, and leaves the process exit code alone", async () => {
		const before = process.exitCode;
		const result = await session.runCommand("re", "no-such-subcommand");
		expect(result.isError).toBe(true);
		expect(result.text).toContain("unknown /re subcommand");
		expect(process.exitCode ?? 0).toBe(before ?? 0);
	});

	test("/re off blocks tool calls through the tool_call gate, and /re on lifts it", async () => {
		await session.runCommand("re", "off");
		const blocked = await session.callTool("rizin_help", { query: "afl" });
		expect(blocked).toEqual({ text: expect.stringContaining("RE tools are off"), isError: true });
		await session.runCommand("re", "on");
		expect((await session.callTool("rizin_command", {})).text).toContain("schema");
	});
});

describe("stdio bridge", () => {
	let dir: string;
	let bridge: ReturnType<typeof startBridge>;

	beforeAll(async () => {
		dir = await mkdtemp(join(tmpdir(), "omp-re-bridge-"));
		bridge = startBridge(dir);
	});
	afterAll(async () => {
		await bridge.stop();
		rmDirSafe(dir);
	});

	test("hello describes the engine: its version, tools and commands", async () => {
		const hello = await bridge.ask({ op: "hello" });
		expect(hello.ok).toBe(true);
		expect(hello.version).toBe(JSON.parse(readFileSync(resolve(import.meta.dir, "../package.json"), "utf8")).version);
		expect(hello.tools!.map((t) => t.name)).toContain("record_finding");
		expect(hello.commands).toEqual([expect.objectContaining({ name: "re" })]);
	});

	test("a command answers with its text, and nothing the engine prints leaks into the protocol", async () => {
		const reply = await bridge.ask({ op: "command", session: "a", name: "re", args: "status" });
		expect(reply).toMatchObject({ ok: true, isError: false });
		expect(reply.text).toContain("rizin");
		expect(bridge.unsolicited).toEqual([]);
	});

	test("replies carry their request's id, whatever order sessions finish in", async () => {
		const requests = Array.from({ length: 8 }, (_, i) => bridge.send({ op: "command", session: `s${i % 3}`, name: "re", args: i % 2 ? "help" : "status" }));
		const replies = await Promise.all(requests.map((r) => r.reply));
		replies.forEach((reply, i) => {
			expect(reply.id).toBe(requests[i]!.id);
			expect(reply.text).toContain(i % 2 ? "verify" : "audit log");
		});
	});

	test("a malformed line and an unknown op are bridge errors; the bridge keeps serving", async () => {
		bridge.raw("this is not json");
		const unknown = await bridge.ask({ op: "frobnicate" });
		expect(unknown).toMatchObject({ ok: false, error: expect.stringContaining("unknown op") });
		expect(bridge.unsolicited).toEqual([{ ok: false, error: expect.stringContaining("one JSON object") }]);
		expect((await bridge.ask({ op: "command", session: "a", name: "re", args: "help" })).ok).toBe(true);
	});

	test("closing a session answers, and the session can be used again", async () => {
		expect(await bridge.ask({ op: "close", session: "a" })).toMatchObject({ ok: true });
		expect((await bridge.ask({ op: "command", session: "a", name: "re", args: "status" })).ok).toBe(true);
	});

	test("stdin closing answers what was already asked, then exits 0", async () => {
		const own = await mkdtemp(join(tmpdir(), "omp-re-bridge-eof-"));
		const batch = startBridge(own);
		const last = batch.send({ op: "command", session: "b", name: "re", args: "status" });
		const code = await batch.stop();
		expect((await last.reply).text).toContain("rizin");
		expect(code).toBe(0);
		rmDirSafe(own);
	});
});

describe.skipIf(!canRunRizin)("stdio bridge with rizin", () => {
	let dir: string;
	let bridge: ReturnType<typeof startBridge>;
	let evidenceId: string;

	beforeAll(async () => {
		dir = await mkdtemp(join(tmpdir(), "omp-re-bridge-rz-"));
		bridge = startBridge(dir);
	});
	afterAll(async () => {
		await bridge.stop();
		rmDirSafe(dir);
	});

	const call = (tool: string, args: Record<string, unknown>) => bridge.ask({ op: "call", session: "rz", tool, args });

	test("opens a binary and reads it; the result carries an evidence id", async () => {
		const opened = await call("open_binary", { path: TEST_BINARY });
		expect(opened).toMatchObject({ ok: true, isError: false });
		expect(opened.text).toContain("Binary opened");
		const listed = await call("rizin_command", { command: "aflj" });
		expect(listed.isError).toBe(false);
		const tag = /\[evidence ([0-9a-f]{8})/.exec(listed.text!);
		expect(tag).not.toBeNull();
		evidenceId = tag![1]!;
	}, 120_000);

	test("output past the size cap is spilled to a file the result names", async () => {
		// aflj on a real binary is far larger than a tool result may be.
		const listed = await call("rizin_command", { command: "aflj" });
		const named = /Full output: (\S+?)\]/.exec(listed.text!);
		expect(named).not.toBeNull();
		expect(named![1]).not.toContain("artifact://");
		const full = readFileSync(named![1]!, "utf8");
		expect(full.startsWith("rizin> aflj\n")).toBe(true);
		expect(JSON.parse(full.slice(full.indexOf("\n") + 1))).toBeInstanceOf(Array);
	});

	test("the call was audited and its evidence persisted, as under omp", () => {
		const audit = readFileSync(join(dir, "re", "audit", "rz.log"), "utf8");
		expect(audit).toContain('"tool":"rizin_command"');
		const branch = readFileSync(join(dir, "re", "headless", "sessions", "rz", "branch.jsonl"), "utf8")
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line) as { customType: string });
		expect(branch.map((e) => e.customType)).toEqual(expect.arrayContaining(["re.binary", "re.evidence"]));
	});

	test("a finding is gated on evidence that exists", async () => {
		const refused = await call("record_finding", { claim: "Unsupported.", evidence: ["00000000"] });
		expect(refused.isError).toBe(true);
		const recorded = await call("record_finding", { claim: "rizin lists the binary's functions.", evidence: [evidenceId], confidence: "confirmed" });
		expect(recorded.isError).toBe(false);
	});

	test("cancel aborts a running call, which still answers under its own id", async () => {
		const own = await mkdtemp(join(tmpdir(), "omp-re-bridge-cancel-"));
		const other = startBridge(own);
		const opening = other.send({ op: "call", session: "c", tool: "open_binary", args: { path: TEST_BINARY } });
		other.raw(JSON.stringify({ op: "cancel", id: opening.id }));
		const reply = await opening.reply;
		expect(reply.id).toBe(opening.id);
		expect(reply.ok).toBe(true);
		expect(reply.isError).toBe(true);
		await other.stop();
		rmDirSafe(own);
	}, 120_000);

	test("a new process restores the session from its record: binary, evidence, finding", async () => {
		await bridge.stop();
		bridge = startBridge(dir);
		const status = await bridge.ask({ op: "command", session: "rz", name: "re", args: "status" });
		expect(status.text).toContain("evidence on this branch: 2");
		expect(status.text).toContain("findings on this branch: 1");
		const again = await call("rizin_command", { command: "iIj" });
		expect(again.isError).toBe(false);
		expect((await bridge.ask({ op: "command", session: "rz", name: "re", args: "verify" })).text).toContain("0 FAILED");
		expect(existsSync(join(dir, "re", "headless", "sessions", "rz", "branch.jsonl"))).toBe(true);
	}, 120_000);
});
