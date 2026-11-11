#!/usr/bin/env bun
/**
 * A stand-in for the engine, for the suites that test omp's side of the wire
 * without SBCL: `bun test/stand-in-engine.ts <behaviour>` speaks
 * docs/engine-protocol.md on its standard input and output as stdio/serve.lisp
 * does. It is a bun script, not a shell script, so it runs wherever the suites
 * do.
 *
 * It cannot speak a protocol of its own: everything omp's side sends it, and
 * every answer omp gives to what it asks, is held to stdio/protocol.json, and
 * what was wrong is in what `/re wire` and `/re heard` answer.
 *
 * Behaviours (the first argument):
 *   fatal           says it cannot load, as serve.lisp does, and exits 3
 *   dying           writes to its log and exits 7 without a word on the wire
 *   other-version   is ready, with a protocol version that is not this one
 *   silent          never becomes ready
 *   framing         serves, on a wire that ends lines with CRLF, carries lines that are not messages, and splits a character in two writes
 *   serve           serves (the default)
 *   deaf            serves, and ignores `shutdown` and the end of its input
 *   told-only       serves, and leaves when told `shutdown` but not at the end of its input
 *   eof-only        serves, and leaves at the end of its input but not when told `shutdown`
 *   mute            serves, but never answers a `call` and says nothing while it is waited for
 *   forgetful       serves, never answers a `call`, and its `alive` names no request
 *   slow            serves; a `call` is answered after ten beats, `alive` naming it meanwhile
 *   crashing        serves, and exits 9 on a `call`, having written to its log
 * A second argument is the pace of `alive` in milliseconds (default: the protocol's).
 */
import { writeSync } from "node:fs";
import { paramsViolation, readProtocol, resultViolation } from "../scripts/protocol.ts";

const behaviour = process.argv[2] ?? "serve";
const protocol = readProtocol();
const beatMs = Number(process.argv[3] ?? Number(protocol.constants.aliveSeconds) * 1000);
const crlf = behaviour === "framing";

type Message = { id?: number; method?: string; params?: Record<string, unknown>; result?: unknown; error?: { message: string } };

const say = (message: unknown) => writeSync(1, `${JSON.stringify(message)}${crlf ? "\r\n" : "\n"}`);

if (behaviour === "fatal") {
	say({ fatal: "omp-re: the Common Lisp library cl-ppcre was not found. Install it." });
	process.exit(3);
}
if (behaviour === "dying") {
	writeSync(2, "heap exhausted\n");
	process.exit(7);
}
if (behaviour === "silent") {
	writeSync(2, "; compiling file engine.lisp\n");
	await new Promise(() => {});
}

/** What was said that the protocol does not have, by either side. */
const violations: string[] = [];
/** Everything omp's side sent that was not an answer, in order. */
const heard: { method: string; params: Record<string, unknown>; request: boolean }[] = [];
/** The requests of omp's being served, for `alive`. */
const serving = new Set<number>();
let asked = 0;
const waiting = new Map<number, { method: string; settle: (answer: Message) => void }>();

/** Ask omp `method` => its result, or {error} as it answered one. The answer is held to the protocol. */
function ask(method: string, params: Record<string, unknown>): Promise<unknown> {
	const id = ++asked;
	const answered = new Promise<Message>((settle) => waiting.set(id, { method, settle }));
	say({ id, method, params });
	return answered.then((answer) => {
		if (answer.error) return { error: answer.error.message };
		const wrong = resultViolation(protocol, "toHost", method, answer.result);
		if (wrong) violations.push(`omp answered: ${wrong}`);
		return answer.result;
	});
}
const tell = (method: string, params: Record<string, unknown>) => say({ method, params });

const state = (memory: Record<string, unknown> = {}) => ({ band: ["stand-in  ELF64 x86/64  entry 0x1000", "3 fn · 0 findings · 1 evidence"], evidence: [["0a1b2c3d", "rizin_command @ main"]], memory });

/**
 * Everything the engine may ask omp, asked once of `session`, and what omp answered — but for `judge`: omp would put
 * it to whatever model the machine running the suite has configured, and no suite calls a model.
 */
async function askEverything(session: string, request: number): Promise<Record<string, unknown>> {
	const before = await ask("entries", { session, after: null, count: 0 });
	const appended = (await ask("append", { session, type: "re.stand-in", data: { n: 1 } })) as { id: string };
	const big = `stand-in artifact\n${"x".repeat(200_000)}`;
	const saved = (await ask("saveArtifact", { session, content: big, label: "stand-in" })) as { id?: string };
	for (const level of ["info", "warning", "error"]) tell("notify", { session, text: `notified at ${level}`, level });
	tell("progress", { session, request, text: "stand-in: working" });
	tell("progress", { session, request, text: null });
	tell("progress", { session, request: null, text: null });
	tell("transcript", { session, type: "re.binary", text: "[re: opened /stand/in]", details: { sha256: "00" } });
	tell("tell", { session, text: "told in passing", level: "warning" });
	tell("state", { session, state: state({ toolsOff: true }) });
	return {
		before,
		appended,
		continues: await ask("entries", { session, after: appended.id, count: 1 }),
		moved: await ask("entries", { session, after: "not-the-last-entry", count: 1 }),
		saved,
		readBack: saved.id === undefined ? null : ((await ask("readArtifact", { session, id: saved.id })) as { text?: string }).text === big,
		readMissing: await ask("readArtifact", { session, id: "no-such-artifact" }),
		kept: await ask("keepSession", { session, name: "kept by the stand-in" }),
		unknownSession: await ask("append", { session: "no-such-session", type: "re.stand-in", data: null }),
		unknownMethod: await ask("noSuchMethod", { session }),
	};
}

const FUNCTIONS = {
	type: "panel",
	title: "omp-re: functions",
	hint: "enter open · type to filter · esc close",
	rows: [
		{ value: "0x1000", label: "main", description: "0x1000", enter: { view: { kind: "code", arg: { addr: "0x1000", name: "main" } } } },
		{ value: "0x2000", label: "helper", enter: { draft: "Re: helper" } },
	],
};

async function result(method: string, params: Record<string, unknown>, id: number): Promise<unknown> {
	const session = (params.session as { id: string } | undefined)?.id ?? "";
	switch (method) {
		case "hello":
			return { protocol: protocol.version, version: "0.0.0-stand-in" };
		case "describe":
			return {
				tools: [
					{
						name: "stand_in_tool",
						description: "split — here",
						parameters: { type: "object", properties: { addr: { type: "string" } } },
						approval: "write",
						approvalReason: [{ parts: ["Touch ", { pieces: [{ arg: "addr", missing: "?" }], quote: true, clip: 8 }, "."] }],
						render: { title: "Stand-in", subject: "addr", body: "text" },
					},
				],
				commands: [
					{ name: "help", description: "show this list" },
					{ name: "functions", description: "function navigator", view: true },
					{ name: "cite", usage: "<id>", description: "cite an evidence entry", completes: "evidence" },
				],
			};
		case "call": {
			if (behaviour === "crashing") {
				writeSync(2, "fatal error in the stand-in\n");
				process.exit(9);
			}
			if (behaviour === "mute" || behaviour === "forgetful") return new Promise(() => {});
			if (behaviour === "slow") await Bun.sleep(10 * beatMs);
			const args = params.arguments as { addr?: string };
			if (args.addr === "refuse") return { text: "omp-re: refused by the stand-in", failed: true, refused: true, state: state() };
			if (args.addr === "fail") return { text: "the stand-in's tool failed", failed: true, details: {}, state: state() };
			return { text: `header\nbody of ${args.addr}\n[evidence 0a1b2c3d — cite it in record_finding]`, failed: false, details: { evidenceId: "0a1b2c3d-0000-0000-0000-000000000000" }, state: state() };
		}
		case "command": {
			const line = String(params.line).trim();
			if (line === "wire") return { text: JSON.stringify({ ...(await askEverything(session, id)), violations }), failed: false, level: "info", state: state({ toolsOff: true }) };
			if (line === "heard") return { text: JSON.stringify({ heard, violations }), failed: false, level: "info", state: state() };
			if (line === "cite 0a1b2c3d") return { text: "cited", failed: false, level: "info", draft: { text: "Re: evidence 0a1b2c3d", notice: "the citation is in your draft" }, state: state() };
			if (line === "agenda") return { text: "sent", failed: false, level: "info", userMessage: "the stand-in's agenda", state: state() };
			if (line === "off") return { text: "off", failed: false, level: "info", state: state({ toolsOff: true }) };
			return { text: `stand-in: ${line}`, failed: line === "bogus", level: line === "bogus" ? "error" : "info", state: state() };
		}
		case "view": {
			if (params.kind === "functions") return FUNCTIONS;
			if (params.kind === "code")
				return {
					type: "code",
					title: "main",
					disasm: ["0x1000  push rbp", "0x1001  ret"],
					...((params.arg as { addr?: string }).addr === "0x1000" ? { decompile: { label: "decompile", note: "// decompiled with pdg", tone: "dim", code: "int main(void) {\n}" } } : {}),
					noDecompile: "omp-re: no decompiler output for this function",
					ask: "Analyze function main at 0x1000.",
					xrefs: { kind: "xrefs", arg: { addr: "0x1000" } },
				};
			return { type: "notice", text: `omp-re: no xrefs to ${(params.arg as { addr?: string } | undefined)?.addr}`, level: "info" };
		}
		case "preserved":
			return { lines: ["preserve: the stand-in's binary", "- Open binary: stand-in"] };
		case "approval":
			return {};
		case "event":
			return params.kind === "before-switch" || params.kind === "shutdown" ? {} : { state: state() };
		default:
			throw new Error(`omp-re: the engine has no method ${method}`);
	}
}

async function receive(message: Message): Promise<void> {
	if (message.method === undefined) {
		const asked = message.id === undefined ? undefined : waiting.get(message.id);
		if (asked) {
			waiting.delete(message.id!);
			asked.settle(message);
		}
		return;
	}
	const params = message.params ?? {};
	const wrong = paramsViolation(protocol, "toEngine", message.method, params, message.id !== undefined);
	heard.push({ method: message.method, params, request: message.id !== undefined });
	if (wrong) violations.push(`omp sent: ${wrong}`);
	if (message.id === undefined) {
		if (message.method === "shutdown" && behaviour !== "deaf" && behaviour !== "eof-only") process.exit(0);
		return;
	}
	const id = message.id;
	if (wrong) {
		say({ id, error: { message: `omp-re: not the protocol (stdio/protocol.json): ${wrong}` } });
		return;
	}
	if (message.method !== "hello") serving.add(id);
	try {
		const answer = await result(message.method, params, id);
		const unfit = resultViolation(protocol, "toEngine", message.method, answer);
		if (unfit) throw new Error(`the stand-in's own answer is not the protocol's: ${unfit}`);
		if (behaviour === "framing" && message.method === "describe") {
			// One character of the answer, the em dash of the tool's description, cut in two writes.
			const bytes = Buffer.from(`${JSON.stringify({ id, result: answer })}\r\n`);
			const cut = bytes.indexOf(Buffer.from("—")) + 2;
			writeSync(1, bytes.subarray(0, cut));
			await Bun.sleep(200);
			writeSync(1, bytes.subarray(cut));
		} else say({ id, result: answer });
	} catch (error) {
		say({ id, error: { message: error instanceof Error ? error.message : String(error) } });
	} finally {
		serving.delete(id);
	}
}

const version = behaviour === "other-version" ? protocol.version + 1 : protocol.version;
say({ ready: version });
if (behaviour === "framing") writeSync(1, "a line that is not JSON\n\n[1, 2]\n");

setInterval(() => {
	if (behaviour === "mute") return;
	if (serving.size > 0) tell("alive", { serving: behaviour === "forgetful" ? [] : [...serving] });
}, beatMs);

for await (const line of console) {
	let message: Message | undefined;
	try {
		message = JSON.parse(line) as Message;
	} catch {
		// Not a message: skipped, as the engine skips it.
	}
	if (message !== undefined && message !== null && typeof message === "object") void receive(message);
}
// The end of the input: omp is gone, or done.
if (behaviour === "deaf" || behaviour === "told-only") await new Promise(() => {});
process.exit(0);
