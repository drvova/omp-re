/**
 * The `run` tool's own machinery, rizin-free: the cell compiler (cell.ts),
 * the per-session namespace and its kept definitions (namespace.ts,
 * kept.ts), the capability dispatcher (capabilities.ts), and — through a
 * child process booting omp's real SDK — that a definition kept by one
 * process is loaded into a fresh one.
 *
 * Every test points the kept directory (OMPRE_KEPT_DIR) and omp's agent dir
 * at throwaway paths, so nothing touches a real user's directories.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { CapabilityRegistry } from "../extensions/re/capabilities.ts";
import { compileCell } from "../extensions/re/cell.ts";
import { collectEvidence } from "../extensions/re/entries.ts";
import { listKept } from "../extensions/re/kept.ts";
import { CellError, type CellOutcome, type ReNamespace, namespaceFor } from "../extensions/re/namespace.ts";
import { plainResult } from "../extensions/re/format.ts";
import { shutdownState } from "../extensions/re/state.ts";
// Failing runs are asserted through captureError, never `expect(promise).rejects`: under bun test that
// form can stop delivering the namespace worker's messages while the promise is still pending.
import { captureError, makeHarness, rmDirSafe } from "./helpers.ts";

let root: string;
const originalAgentDir = getAgentDir();
const originalKeptDir = process.env.OMPRE_KEPT_DIR;

beforeAll(async () => {
	root = await mkdtemp(join(tmpdir(), "omp-re-run-test-"));
	setAgentDir(join(root, "agent"));
});

afterAll(() => {
	setAgentDir(originalAgentDir);
	if (originalKeptDir === undefined) delete process.env.OMPRE_KEPT_DIR;
	else process.env.OMPRE_KEPT_DIR = originalKeptDir;
	rmDirSafe(root);
});

let keptCounter = 0;
/** A fresh, empty kept directory for one test. */
function freshKeptDir(): string {
	const dir = join(root, `kept-${keptCounter++}`);
	process.env.OMPRE_KEPT_DIR = dir;
	return dir;
}

describe("compileCell", () => {
	test("finds top-level functions, classes, and static consts as definitions — with their TypeScript and doc comments", async () => {
		const { definitions } = await compileCell(
			[
				"/** Doubles. */",
				"function twice(x: number): number { return x * 2 }",
				"class Box { v = 1 }",
				"const LIMIT: number = 10, TABLE = { a: [1, 2], f: (x: string) => x.length }, NAMES = new Set(['a'])",
				"const live = await fetchSomething()",
				"let counter = 0",
				"const { a, b } = { a: 1, b: 2 }",
				"twice(LIMIT)",
			].join("\n"),
		);
		expect(definitions.map((d) => `${d.kind}:${d.name}`)).toEqual(["function:twice", "class:Box", "const:LIMIT", "const:TABLE", "const:NAMES"]);
		expect(definitions[0]!.source).toBe("/** Doubles. */\nfunction twice(x: number): number { return x * 2 }");
		expect(definitions[2]!.source).toBe("const LIMIT: number = 10;");
	});

	test("a const that does work — a call, an await, a template with a live call — is never a definition", async () => {
		const { definitions } = await compileCell("const a = f()\nconst b = await g\nconst c = `x${h()}`\nconst d = new Date()\nconst e = obj.method()");
		expect(definitions).toEqual([]);
	});

	test("rejects export, reserved names, and syntax errors with the line and a caret", async () => {
		await expect(compileCell("export const x = 1")).rejects.toThrow("`export` is not needed");
		await expect(compileCell("const __ompre_g = 1")).rejects.toThrow("__ompre_g is reserved");
		await expect(compileCell("const x = 1\nconst = 2")).rejects.toThrow("(line 2, column 7)\n  const = 2\n        ^");
	});
});

/** A namespace over a fake capability set, with a stub host: `probe` (evidence-tier, named like a real read tool) and `label` (annotate tier). */
function setup(sessionId: string) {
	const h = makeHarness(sessionId);
	const registry = new CapabilityRegistry();
	const host = registry.host(h.pi);
	const z = h.pi.zod;
	const hashParams = z.object({ salt: z.string().optional().describe("Mixed into the fake digest.") });
	host.registerTool({
		name: "hash_binary",
		label: "Hash",
		description: "Fake digest of the open binary. Second sentence.",
		approval: "read",
		parameters: hashParams,
		async execute(_id, params) {
			return { ...plainResult(`sha256 ${params.salt ?? ""}deadbeef`), details: { summary: "digest", header: "digest", ea: "0x1000" } };
		},
	});
	const labelParams = z.object({ addr: z.string().describe("Address."), name: z.string().describe("New name.") });
	host.registerTool({
		name: "set_flag",
		label: "Label",
		description: "Fake annotation.",
		approval: (args) => ({ tier: "write", reason: `flag ${JSON.stringify(args)}` }),
		parameters: labelParams,
		async execute(_id, params) {
			if (params.addr === "bad") throw new Error("omp-re: invalid address or expression: \"bad\"");
			return plainResult(`flagged ${params.addr} as ${params.name}`);
		},
	});
	// A slow operation that waits until its call is cancelled, like a long rizin analysis.
	const slow = { started: false, aborted: false };
	host.registerTool({
		name: "analyze",
		label: "Slow",
		description: "Fake slow pass.",
		approval: "exec",
		parameters: z.object({}),
		async execute(_id, _params, signal) {
			slow.started = true;
			await new Promise<void>((resolve) => signal?.addEventListener("abort", () => resolve(), { once: true }));
			slow.aborted = signal?.aborted === true;
			return plainResult("never seen");
		},
	});
	let ns: ReNamespace | undefined;
	const run = async (code: string, strings: Record<string, string> = {}, signal?: AbortSignal): Promise<CellOutcome> => {
		ns ??= await namespaceFor(h.ctx, registry, "run");
		return ns.run(code, { pi: h.pi, ctx: h.ctx, signal, onUpdate: undefined, toolCallId: "call", strings });
	};
	return { h, registry, run, slow, namespace: () => namespaceFor(h.ctx, registry, "run") };
}

/** Run one cell through the real `run` tool in a fresh process booting omp's SDK (test/e2e/run-cell.ts), with `keptDir` as its kept directory. */
async function child(keptDir: string, code: string): Promise<{ ok: boolean; text: string }> {
	const proc = Bun.spawn([process.execPath, resolve(import.meta.dir, "e2e/run-cell.ts"), join(root, "child-agent"), code], {
		env: { ...process.env, OMPRE_KEPT_DIR: keptDir },
		stdout: "pipe",
		stderr: "pipe",
	});
	const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
	if ((await proc.exited) !== 0) throw new Error(`child failed: ${stderr}`);
	return JSON.parse(stdout.trim().split("\n").at(-1)!) as { ok: boolean; text: string };
}

let sessionCounter = 0;
const newSession = () => `run-test-${sessionCounter++}`;

describe("the namespace", () => {
	beforeEach(() => {
		freshKeptDir();
	});

	test("a helper defined in one call is reusable in the next, reads names late, and the last expression is the value", async () => {
		const { run } = setup(newSession());
		await run("function parse(s: string) { return s.split(',') }\nfunction count(s: string) { return parse(s).length }");
		expect((await run("count('a,b,c')")).value).toBe(3);
		// Redefining parse is seen by count, defined earlier: names resolve in the namespace, not in the old cell.
		await run("function parse(s: string) { return [s] }");
		expect((await run("count('a,b,c')")).value).toBe(1);
		expect((await run("let total = 0\nfor (const n of [1, 2, 3]) total += n\ntotal")).value).toBe(6);
		expect((await run("total * 2")).value).toBe(12);
	});

	test("print/console output is captured, strings arrive verbatim, and await works at the top level", async () => {
		const { run } = setup(newSession());
		const outcome = await run("print('a', 1, { b: [2] })\nconsole.log(strings.rule)\nawait new Promise((r) => setTimeout(r, 1))\n'done'", { rule: 'rule r { strings: $s = "\\x41" condition: $s }' });
		expect(outcome.output).toEqual(['a 1 {\n  "b": [\n    2\n  ]\n}', 'rule r { strings: $s = "\\x41" condition: $s }']);
		expect(outcome.value).toBe("done");
	});

	test("the namespace's own vocabulary cannot be overwritten by accident", async () => {
		const { run } = setup(newSession());
		expect((await captureError(run("const re = 1"))).message).toContain("`re` is part of the namespace (see man()) and cannot be redeclared");
		expect((await captureError(run("function describe() {}"))).message).toContain("`describe` is part of the namespace");
		expect((await captureError(run("re = 1"))).message).toMatch(/read.?only/i);
		expect((await run("typeof re.hash_binary")).value).toBe("function");
	});

	test("capability calls validate params against the schema, record evidence, and audit — the same path a tool call took", async () => {
		const { run, h } = setup(newSession());
		const outcome = await run("const d = await re.hash_binary({ salt: 'x' })\nawait re.set_flag({ addr: '0x10', name: 'entry' })\nd");
		expect(outcome.value).toMatch(/^sha256 xdeadbeef\n\[evidence [0-9a-f]{8} — cite it in re\.record_finding\]$/);
		expect(outcome.scope.calls).toEqual(["hash_binary", "set_flag"]);
		const [record] = collectEvidence(h.entries);
		expect(record).toMatchObject({ tool: "hash_binary", args: { salt: "x" }, ea: "0x1000" });
		expect(outcome.scope.evidence).toEqual([{ id: record!.id, tool: "hash_binary", ea: "0x1000" }]);
		const audit = await readFile(join(getAgentDir(), "re", "audit", `${h.ctx.sessionManager.getSessionId()}.log`), "utf8");
		expect(audit.trim().split("\n").map((line) => JSON.parse(line).tool)).toEqual(["hash_binary", "set_flag"]);

		expect((await captureError(run("await re.set_flag({ addr: '0x10' })"))).message).toContain("re.set_flag: name must be");
		expect((await captureError(run("await re.set_flag({ addr: '0x10', name: 'x', nmae: 'y' })"))).message).toContain("re.set_flag: unknown parameter nmae — expected addr, name");
		expect((await captureError(run("await re.set_flag('0x10')"))).message).toContain("re.set_flag takes one params object (required: addr, name)");
		expect((await run("(await re.hash_binary('salt-')).split('\\n')[0]")).value).toBe("sha256 salt-deadbeef");
		expect((await run("let msg\ntry { await re.set_flag({ addr: 'bad', name: 'n' }) } catch (e) { msg = e.message }\nmsg")).value).toBe('omp-re: invalid address or expression: "bad"');
	});

	test("describe shows live capabilities with signatures from their schemas, one capability in full, and plain values", async () => {
		const { run } = setup(newSession());
		const all = (await run("describe(re)")).value as string;
		expect(all).toContain("  hash_binary(params?: { salt?: string }) — Fake digest of the open binary.\n");
		expect(all).toContain("annotate — written to rizin");
		expect(all).toContain("  set_flag({ addr: string, name: string }) — Fake annotation.");
		const one = (await run("describe(re.set_flag)")).value as string;
		expect(one).toContain("re.set_flag({ addr: string, name: string }) → Promise<string>\ntier: write");
		expect(one).toContain("  name: string — New name.");
		await run("/** Adds one. */\nfunction inc(n: number) { return n + 1 }");
		expect((await run("describe(inc)")).value).toBe("inc(n)\nAdds one.");
		expect((await run("describe({ a: 1, f(x) { return x } })")).value).toBe("object with 2 members:\n  a: number = 1\n  f(x)");
	});

	test("kept definitions are written one unit per name; forget removes the file and the binding", async () => {
		const { run } = setup(newSession());
		const outcome = await run("/** Square. */\nfunction sq(x: number) { return x * x }\nconst SCALE = 3\nconst result = sq(SCALE)");
		expect(outcome.kept).toEqual(["sq", "SCALE"]);
		expect((await listKept(process.env.OMPRE_KEPT_DIR!)).map((u) => [u.name, u.source])).toEqual([
			["SCALE", "const SCALE = 3;"],
			["sq", "/** Square. */\nfunction sq(x: number) { return x * x }"],
		]);
		expect((await run("kept()")).value).toMatch(/2 kept in .*:\n {2}SCALE — const SCALE = 3;\n {2}sq — function sq\(x: number\) \{ return x \* x \} — Square\./);
		expect((await run("forget('sq')")).value).toBe("forgot sq");
		expect((await listKept(process.env.OMPRE_KEPT_DIR!)).map((u) => u.name)).toEqual(["SCALE"]);
		expect((await captureError(run("sq(2)"))).message).toContain("sq is not defined");
		expect((await run("forget('result')")).value).toBe("forgot result (it was defined, not kept)");
	});

	test("a failed call keeps nothing", async () => {
		const { run } = setup(newSession());
		expect((await captureError(run("function half(x: number) { return x / 2 }\nthrow new Error('boom')"))).message).toContain("boom");
		expect(await listKept(process.env.OMPRE_KEPT_DIR!)).toEqual([]);
	});

	test("a new session's namespace loads kept units — in dependency order, each isolated — and refuses a unit that does work", async () => {
		const dir = process.env.OMPRE_KEPT_DIR!;
		const first = setup(newSession());
		// BASE is defined after the const that names it, so it loads only on a retry pass.
		await first.run("function base() { return 40 }");
		await first.run("const FN = base\nconst TABLE = { fn: base }");
		await writeFile(join(dir, "broken.ts"), "const broken = missingThing;\n");
		await writeFile(join(dir, "sneaky.ts"), "await fetch('http://example.invalid');\nfunction sneaky() {}\n");

		const second = setup(newSession());
		expect((await second.run("FN() + TABLE.fn() / 20")).value).toBe(42);
		const manual = await (await second.namespace()).manual(second.h.ctx);
		expect(manual).toContain("not loaded: broken (ReferenceError: missingThing is not defined); sneaky (not a single definition of sneaky)");
		expect((await second.run("typeof sneaky")).value).toBe("undefined");
		expect((await second.run("kept()")).value).toContain("broken — const broken = missingThing; (NOT LOADED: ReferenceError: missingThing is not defined)");
		shutdownState(first.h.ctx.sessionManager.getSessionId());
		shutdownState(second.h.ctx.sessionManager.getSessionId());
	});

	test("cells in one namespace run one at a time", async () => {
		const { run } = setup(newSession());
		await run("let log = []");
		await Promise.all([run("log.push('a1'); await new Promise((r) => setTimeout(r, 20)); log.push('a2')"), run("log.push('b1')")]);
		expect((await run("log")).value).toEqual(["a1", "a2", "b1"]);
	});

	test("re.* used after its call has finished says to await it", async () => {
		const { run } = setup(newSession());
		await run("var pending = new Promise((r) => setTimeout(() => r(re.hash_binary().catch((e) => e.message)), 5))");
		await new Promise((r) => setTimeout(r, 30)); // no call is running when the timer fires
		expect((await run("await pending")).value).toBe("omp-re: re.hash_binary can only be used while a run call is running — await it inside the cell");
	});
});

describe("stopping a call", () => {
	beforeEach(() => {
		freshKeptDir();
	});

	test("cancelling stops a cell mid-statement — even a loop that never yields — and resets the namespace", async () => {
		const { run } = setup(newSession());
		await run("function survivor() { return 'still here' }\nvar scratch = 1");
		const controller = new AbortController();
		const looping = run("print('looping')\nfor (;;) {}", {}, controller.signal);
		setTimeout(() => controller.abort(), 150);
		const err = (await looping.catch((e) => e)) as CellError;
		expect(err).toBeInstanceOf(CellError);
		expect(err.message).toBe("omp-re: cancelled — the call was stopped where it was; the namespace was reset — kept definitions reload on the next call; other variables are gone");
		expect(err.output).toEqual(["looping"]);
		// A fresh worker: kept definitions are back, plain variables are gone.
		expect((await run("survivor()")).value).toBe("still here");
		expect((await captureError(run("scratch"))).message).toContain("scratch is not defined");
	});

	test("cancelling while a capability runs hands the cancellation to the capability too", async () => {
		const { run, slow } = setup(newSession());
		const controller = new AbortController();
		const waiting = run("await re.analyze()", {}, controller.signal);
		while (!slow.started) await new Promise((r) => setTimeout(r, 5));
		controller.abort();
		expect((await captureError(waiting)).message).toContain("omp-re: cancelled");
		while (!slow.aborted) await new Promise((r) => setTimeout(r, 5));
		expect(slow.aborted).toBe(true);
	});

	test("process.exit() in a cell ends only the namespace's worker, never omp", async () => {
		const { run } = setup(newSession());
		expect((await captureError(run("process.exit(7)"))).message).toContain("omp-re: the run namespace's worker exited (code 7); the namespace was reset");
		expect((await run("6 * 7")).value).toBe(42);
	});

	// In a child process booting omp's SDK: bun test installs its own uncaught-error handling in
	// workers, which would end the worker before the namespace's own handler sees the error.
	test("an exception a timer throws later is printed into the running call, not fatal", async () => {
		const dir = freshKeptDir();
		expect(await child(dir, "setTimeout(() => { throw new Error('late') }, 0)\nawait new Promise((r) => setTimeout(r, 30))\n'alive'")).toEqual({ ok: true, text: "ran\n(uncaught: late)\nalive" });
		expect(await child(dir, "setTimeout(() => Promise.reject(new Error('later')), 0)\nawait new Promise((r) => setTimeout(r, 30))\n'alive'")).toEqual({ ok: true, text: "ran\n(unhandled rejection: later)\nalive" });
	}, 60_000);
});

describe("MCP servers as functions", () => {
	beforeEach(() => {
		freshKeptDir();
	});

	const echoServer = JSON.stringify({ name: "echo", command: process.execPath, args: [resolve(import.meta.dir, "e2e/mcp-echo.ts")] });

	test("a connected server's tools are async methods with signatures from their schemas; results, errors, and audit lines", async () => {
		const { run, h } = setup(newSession());
		await run(`var echo = await mcp.connect(${echoServer})`);
		expect((await run("describe(echo)")).value).toBe(
			[
				"echo — a connected MCP server; each tool is an async method taking one params object. describe(echo.<tool>) shows its parameters; close() disconnects.",
				"",
				"A test server.",
				"",
				"tools",
				"  echo({ text: string }) — Return the text you send.",
				"  add({ a: number, b: number }) — Add two numbers.",
				"  fail() — Always fails.",
			].join("\n"),
		);
		expect((await run("describe(echo.echo)")).value).toContain("echo.echo({ text: string }) → Promise<unknown>");
		expect((await run("await echo.echo({ text: 'hi' })")).value).toBe("hi");
		expect((await run("await echo.echo('shorthand')")).value).toBe("shorthand");
		expect((await run("await echo.add({ a: 2, b: 3 })")).value).toEqual({ sum: 5 });
		expect((await captureError(run("await echo.fail()"))).message).toContain("echo.fail: deliberate failure");
		const audit = await readFile(join(getAgentDir(), "re", "audit", `${h.ctx.sessionManager.getSessionId()}.log`), "utf8");
		expect(audit.trim().split("\n").map((line) => JSON.parse(line).tool)).toEqual(["mcp.connect", "mcp:echo/echo", "mcp:echo/echo", "mcp:echo/add", "mcp:echo/fail"]);
		await run("await echo.close()");
		expect((await captureError(run("await echo.echo({ text: 'x' })"))).message).toContain("this server connection is closed");
	}, 30_000);

	test("mcp.servers() lists omp's configured servers, and an unknown name says how to find them", async () => {
		const { run } = setup(newSession());
		expect(typeof (await run("await mcp.servers()")).value).toBe("object");
		expect((await captureError(run("await mcp.connect('no-such-server-anywhere')"))).message).toContain('no MCP server named "no-such-server-anywhere" is configured');
	}, 30_000);
});

describe("restart persistence (a fresh process)", () => {
	test("a definition kept by one process is loaded and usable in a fresh process pointed at the same directory, and forget removes it there too", async () => {
		const dir = freshKeptDir();
		const { run } = setup(newSession());
		await run("/** Answer helper. */\nfunction restartAnswer(x: number): number { return x + 2 }\nconst RESTART_BASE = 40");

		expect(await child(dir, "restartAnswer(RESTART_BASE)")).toEqual({ ok: true, text: "ran\n42" });
		expect((await child(dir, "forget('restartAnswer')")).text).toBe("ran\nforgot restartAnswer");
		const after = await child(dir, "restartAnswer(1)");
		expect(after.ok).toBe(false);
		expect(after.text).toContain("restartAnswer is not defined");
	}, 60_000);
});
