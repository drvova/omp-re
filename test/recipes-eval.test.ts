/**
 * skills/re-triage/recipes.js — the five recipes for omp's eval — driven
 * through omp's REAL eval tool, loaded the way a session loads it
 * (`%load skill://re-triage/recipes.js`), with the extension booted by the
 * SDK as test/extension-sdk.test.ts boots it. Nothing here calls a model.
 *
 * Three groups:
 *  1. no rizin: the script loads, defines `re` and nothing else, registers no
 *     tool, and a recipe with no binary open fails with the engine's words;
 *     the generated tables block is current.
 *  2. rizin: each recipe on the test binary — its structure, that every id it
 *     cites is a real `re.evidence` record, that a finding citing one passes
 *     record_finding, bounds, "not shown" lines, refusals.
 *  3. parity: the same recipes run by the Lisp twin (nodecode/recipes.lisp,
 *     through test/nodecode/recipes-out.lisp) on the same two files must
 *     answer the same text, evidence ids aside. Needs SBCL and cl-ppcre, and
 *     says so when it skips.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";
import { RE_ALL_TOOL_NAMES } from "../extensions/re/audit.ts";
import { canRunRizin, logSkip, rmDirSafe, TEST_BINARY } from "./helpers.ts";

logSkip("recipes-eval rizin tests");

const ROOT = resolve(import.meta.dir, "..");
const EXTENSION = join(ROOT, "extensions", "re");
const SKILLS = join(ROOT, "skills");
const RECIPES = join(SKILLS, "re-triage", "recipes.js");
/** How the skill tells the model to load the script: omp resolves `skill://<name>/<path>` inside the skill's own directory, wherever the plugin is installed. */
const LOAD = "%load skill://re-triage/recipes.js";

const canRunLisp = (() => {
	if (Bun.which("sbcl") === null) return false;
	const probe = Bun.spawnSync(["sbcl", "--non-interactive", "--eval", "(require :asdf)", "--eval", '(asdf:load-system "cl-ppcre")'], { stdout: "ignore", stderr: "ignore" });
	return probe.exitCode === 0;
})();
if (canRunRizin && !canRunLisp) console.log("omp-re: SKIPPING the recipes parity comparison with nodecode/recipes.lisp — needs sbcl and cl-ppcre");

interface Harness {
	session: AgentSession;
	shutdown: () => Promise<void>;
}

/** Boot a session with the extension and the plugin's skills loaded, headless, as `omp -p` runs. */
async function boot(sessionManager: unknown): Promise<Harness> {
	const sdk = await import("@oh-my-pi/pi-coding-agent");
	const { initializeExtensions } = await import("@oh-my-pi/pi-coding-agent/modes/runtime-init");
	const { skills } = await sdk.loadSkillsFromDir({ dir: SKILLS, source: "omp-re:user" });
	expect(skills.map((skill) => skill.name)).toContain("re-triage");
	const { session, extensionsResult } = await sdk.createAgentSession({
		cwd: tmpdir(),
		additionalExtensionPaths: [EXTENSION],
		disableExtensionDiscovery: true,
		sessionManager: sessionManager as never,
		skills,
	});
	expect(extensionsResult.errors).toEqual([]);
	await initializeExtensions(session, { reportSendError: () => {}, reportRuntimeError: () => {} });
	return { session, shutdown: () => session.dispose() };
}

/** Run one JavaScript cell through omp's own `eval` tool, as the model does. An error the cell threw comes back as its output, with isError. */
async function evalJs(session: AgentSession, code: string): Promise<{ text: string; isError: boolean }> {
	const result = await session.getToolByName("eval")!.execute(`t-eval-${Math.random().toString(36).slice(2)}`, { language: "js", code } as never);
	const text = result.content.map((part) => (part.type === "text" ? part.text : "")).join("\n");
	return { text, isError: (result as { isError?: boolean }).isError === true };
}

/** A cell that returns the message of whatever `body` throws, or "ok". */
const caught = (body: string) => `let m = "ok"; try { ${body} } catch (e) { m = e.message }; m`;

type Answers = Record<string, string | { error: string }>;

/**
 * Run named recipe calls in one cell and bring every answer back whole. The cell writes them
 * to a file rather than returning them: what a cell returns is shown to a model and may be cut
 * for it, and these texts are compared byte for byte.
 */
async function answers(session: AgentSession, dir: string, calls: Record<string, string>): Promise<Answers> {
	const out = join(dir, `answers-${Math.random().toString(36).slice(2)}.json`);
	const body = Object.entries(calls)
		.map(([name, call]) => `try { out[${JSON.stringify(name)}] = await ${call}; } catch (e) { out[${JSON.stringify(name)}] = { error: e.message }; }`)
		.join("\n");
	const cell = await evalJs(session, `const out = {};\n${body}\nawait Bun.write(${JSON.stringify(out)}, JSON.stringify(out));\n"written"`);
	expect(cell).toEqual({ text: "written", isError: false });
	return JSON.parse(await readFile(out, "utf8")) as Answers;
}

const text = (answer: string | { error: string } | undefined): string => {
	if (typeof answer !== "string") throw new Error(`expected a report, got ${JSON.stringify(answer)}`);
	return answer;
};
const refusal = (answer: string | { error: string } | undefined): string => {
	if (answer === undefined || typeof answer === "string") throw new Error(`expected a refusal, got ${JSON.stringify(answer)}`);
	return answer.error;
};

/** Every evidence id a report cites, in order, without duplicates. */
const citedIds = (report: string): string[] => [...new Set([...report.matchAll(/\[evidence ([0-9a-f]{8})\]/g)].map((match) => match[1]!))];

/** The ids and labels of a report's closing "Evidence taken" list. */
function evidenceTaken(report: string): { id: string; label: string }[] {
	const lines = report.split("\n");
	const at = lines.findIndex((line) => line.startsWith("Evidence taken "));
	expect(at).toBeGreaterThan(0);
	return lines.slice(at + 1).map((line) => {
		const match = /^ {2}([0-9a-f]{8}) {2}(.+)$/.exec(line);
		expect(match).not.toBeNull();
		return { id: match![1]!, label: match![2]! };
	});
}

interface EvidenceEntry {
	id: string;
	tool: string;
	args: { command: string; addr?: string };
	reproHash?: string;
}
const recordedEvidence = (session: AgentSession): EvidenceEntry[] =>
	session.sessionManager
		.getEntries()
		.filter((entry) => entry.type === "custom" && (entry as { customType?: string }).customType === "re.evidence")
		.map((entry) => (entry as { data?: EvidenceEntry }).data!);

/** A report with what differs from run to run — the evidence ids — put out of the comparison. */
const withoutIds = (report: string): string => report.replace(/\[evidence [0-9a-f]{8}\]/g, "[evidence ########]").replace(/^ {2}[0-9a-f]{8} {2}/gm, "  ########  ");
/** A report above its "Evidence taken" list. */
const aboveEvidenceList = (report: string): string => report.slice(0, report.indexOf("\nEvidence taken "));

let agentDir: string;
let originalAgentDir: string;
let scratch: string;

beforeAll(async () => {
	originalAgentDir = getAgentDir();
	agentDir = await mkdtemp(join(tmpdir(), "omp-re-recipes-test-"));
	scratch = await mkdtemp(join(tmpdir(), "omp-re-recipes-out-"));
	setAgentDir(agentDir);
});

afterAll(async () => {
	setAgentDir(originalAgentDir);
	rmDirSafe(agentDir);
	rmDirSafe(scratch);
});

describe("recipes.js in omp's eval (no rizin needed)", () => {
	let h: Harness;

	beforeAll(async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		h = await boot(SessionManager.inMemory());
	});

	afterAll(async () => {
		await h.shutdown();
	});

	test("the generated tables block is current with recipes/tables.json", () => {
		const check = Bun.spawnSync(["bun", join(ROOT, "scripts", "gen-recipes.ts"), "--check"], { stdout: "pipe", stderr: "pipe" });
		expect(check.stderr.toString()).toBe("");
		expect(check.exitCode).toBe(0);
	});

	test("%load by the skill's own URL defines `re` with the five recipes, and nothing else", async () => {
		// What a cell returns is cut for a model's eyes, so the realm's names are written out to be compared whole.
		const names = async (file: string) => {
			expect((await evalJs(h.session, `await Bun.write(${JSON.stringify(join(scratch, file))}, JSON.stringify(Object.getOwnPropertyNames(globalThis))); "written"`)).text).toBe("written");
			return JSON.parse(await readFile(join(scratch, file), "utf8")) as string[];
		};
		const before = await names("globals-before.json");
		expect(before).not.toContain("re"); // the name is free in omp's realm: the script takes nothing from the host
		const tools = h.session.getAllToolNames().sort();

		const loaded = await evalJs(h.session, LOAD);
		expect(loaded.isError).toBe(false);
		expect(loaded.text).toContain("omp-re recipes loaded: re.triage, re.scanImports, re.inspectFunction, re.findComparisons, re.findCrypto");

		const after = await names("globals-after.json");
		expect(after.filter((name) => !before.includes(name))).toEqual(["re"]);
		expect((await evalJs(h.session, "Object.keys(re).sort().join(' ')")).text).toBe("findComparisons findCrypto help inspectFunction scanImports triage");
		expect((await evalJs(h.session, "['triage','scanImports','inspectFunction','findComparisons','findCrypto'].map((n) => re[n].constructor.name).join(' ')")).text).toBe(
			Array(5).fill("AsyncFunction").join(" "),
		);
		// Recipes are code in eval, not tools: the session's tool set is what it was.
		expect(h.session.getAllToolNames().sort()).toEqual(tools);
		for (const name of ["triage", "scan_imports", "inspect_function", "find_comparisons", "find_crypto"]) {
			expect(RE_ALL_TOOL_NAMES[name]).toBeUndefined();
			expect(h.session.getToolByName(name)).toBeUndefined();
		}
	});

	test("the skill's URL resolves to the file in this repository, and its plain path loads too", async () => {
		// omp's read names the file a skill:// URL resolved to: the script beside SKILL.md, wherever the plugin is installed.
		const viaUrl = (await evalJs(h.session, '(await read("skill://re-triage/recipes.js")).split("\\n").slice(0, 2).join("\\n")')).text;
		expect(viaUrl).toBe(`[Skill file: ${RECIPES}]\n/*`);
		const again = await evalJs(h.session, `%load ${JSON.stringify(RECIPES)}`);
		expect(again.isError).toBe(false); // loading it again (an edited file needs another %load) replaces `re` without complaint
		expect((await evalJs(h.session, "typeof re.triage")).text).toBe("function");
	});

	test("help() says what each recipe answers", async () => {
		const help = (await evalJs(h.session, "re.help()")).text;
		for (const name of ["re.triage(", "re.scanImports(", "re.inspectFunction(", "re.findComparisons(", "re.findCrypto("]) expect(help).toContain(name);
		expect(help).toContain("Not tools");
	});

	test("with no binary open every recipe fails with the engine's own message", async () => {
		const message = "omp-re: no binary open — use /re open <path>, open_binary, or --binary <path> first";
		for (const call of ["re.triage()", "re.scanImports()", 're.inspectFunction("main")', 're.findComparisons("main")', "re.findCrypto()"]) {
			expect((await evalJs(h.session, caught(`await ${call}`))).text).toBe(message);
		}
	});

	test("a recipe is stopped by /re off at its first read, like any call", async () => {
		await h.session.prompt("/re off");
		expect((await evalJs(h.session, caught("await re.triage()"))).text).toBe("omp-re: RE tools are off for this session — the user can re-enable them with /re on");
		await h.session.prompt("/re on");
	});

	test("arguments of the wrong shape are refused in words before any read", async () => {
		expect((await evalJs(h.session, caught("await re.inspectFunction(4096)"))).text).toBe("a function is named by a string, not 4096");
		expect((await evalJs(h.session, caught("await re.findComparisons()"))).text).toBe("a function is named by a string, not null");
		expect((await evalJs(h.session, caught("await re.triage(5)"))).text).toBe("omp-re: triage: options are one object, e.g. { maxItems: 20 }, not 5");
	});
});

/** A headerless file of published constants, as test/nodecode/suite-recipes.lisp builds one: an AES S-box at 0x40, SHA-256's K at 0x80, the ChaCha sigma at 0xc0. */
function constantsBlob(): Uint8Array {
	const bytes = (hex: string) => Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16));
	const fill = (count: number, value = 0) => Array<number>(count).fill(value);
	return new Uint8Array([
		...fill(64),
		...bytes("637c777bf26b6fc53001672bfed7ab76"),
		...fill(48, 0x90),
		...bytes("982f8a4291443771cffbc0b5a5dbb5e9"),
		...fill(48),
		...bytes("657870616e642033322d62797465206b"),
		...fill(64),
	]);
}

describe.skipIf(!canRunRizin)("recipes.js in omp's eval, against rizin", () => {
	let h: Harness;
	let blob: string;
	/** The recipes' answers on the test binary, then on the blob — the same calls, under the same names, as test/nodecode/recipes-out.lisp makes. */
	let omp: Answers;
	/** Evidence recorded before the blob was opened: the test binary's. */
	let binaryEvidence: EvidenceEntry[];

	beforeAll(async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		// On disk, so a read past the size cap has a session artifact store to spill its whole output to.
		h = await boot(SessionManager.create(tmpdir(), join(agentDir, "sessions")));
		await h.session.sessionManager.ensureOnDisk();
		blob = join(scratch, "tables.bin");
		await writeFile(blob, constantsBlob());

		expect((await evalJs(h.session, LOAD)).isError).toBe(false);
		expect((await evalJs(h.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`)).isError).toBe(false);
		omp = await answers(h.session, scratch, {
			triage: "re.triage()",
			triageShort: "re.triage({ maxStrings: 1, maxFunctions: 2 })",
			scanImports: "re.scanImports()",
			scanImportsBounded: "re.scanImports({ maxCallers: 1 })",
			scanImportsNoCallers: "re.scanImports({ callers: false })",
			inspectFunction: 're.inspectFunction("main")',
			inspectFunctionBounded: 're.inspectFunction("main", { maxItems: 3 })',
			inspectFunctionNone: 're.inspectFunction("0x1")',
			inspectFunctionInvalid: 're.inspectFunction("main;!id")',
			findComparisons: 're.findComparisons("main")',
			findComparisonsBounded: 're.findComparisons("main", { maxItems: 20 })',
			findComparisonsNone: 're.findComparisons("0x1")',
			findCrypto: "re.findCrypto()",
		});
		binaryEvidence = recordedEvidence(h.session);

		expect((await evalJs(h.session, `await tool.open_binary({ path: ${JSON.stringify(blob)}, arch: "x86", bits: 64, format: "any" })`)).isError).toBe(false);
		Object.assign(
			omp,
			await answers(h.session, scratch, {
				blobTriage: "re.triage()",
				blobFindCrypto: "re.findCrypto()",
				blobFindCryptoNoReferences: "re.findCrypto({ references: false })",
			}),
		);
	}, 180_000);

	afterAll(async () => {
		await h.shutdown();
	});


	test("triage says what the binary is, which protections the build has, and lists sections, imports, strings, functions and entry points", () => {
		const triage = text(omp.triage);
		expect(triage.split("\n")[0]).toMatch(/^triage: \/.+/);
		for (const part of ["Identity [evidence ", "Build protections [evidence ", "stack canary:", "NX:", "PIE:", "RELRO:", "Sections: ", "entropy", "Imports: ", "Strings: ", "largest by code size", "Entry points [evidence "]) {
			expect(triage).toContain(part);
		}
		// A section row: name, permissions, size, entropy to two places.
		expect(triage).toMatch(/^ {2}\.text +-r-x +\d+ bytes {2}entropy \d\.\d\d$/m);
		// A function row: address, size, blocks, name — read from the whole of `aflj`, which is past the size cap for this binary.
		expect(triage).toMatch(/^ {2}0x[0-9a-f]+ +\d+ bytes {2}\d+ blocks {2}\S+$/m);
		expect(Number(/^Functions: (\d+);/m.exec(triage)![1])).toBeGreaterThan(20);
		expect(Number(/^Strings: (\d+);/m.exec(triage)![1])).toBeGreaterThan(20);
	});

	test("a read cut at the size cap is read back whole from its artifact, not parsed cut", () => {
		// The premise: this binary's function list is past the cap, so the text the call returned held none of its JSON.
		const record = binaryEvidence.find((entry) => entry.args.command === "aflj") as (EvidenceEntry & { artifactId?: string; summary?: string }) | undefined;
		expect(record?.artifactId).toEqual(expect.any(String));
		expect(record?.summary).toContain("[Output truncated: 0 of 1 lines");
		// And yet the report counts and lists the functions (the parity group holds the count to the Lisp twin's, which reads rizin's pipe directly).
		expect(Number(/^Functions: (\d+);/m.exec(text(omp.triage))![1])).toBeGreaterThan(20);
		expect(text(omp.triage)).toMatch(/^ {2}… \d+ more functions not shown$/m);
	});

	test("when the whole of a cut read cannot be had, the recipe stops and says so instead of reporting from cut JSON", async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		// A session that is not on disk has no artifact store to read back from.
		const memory = await boot(SessionManager.inMemory());
		try {
			expect((await evalJs(memory.session, LOAD)).isError).toBe(false);
			expect((await evalJs(memory.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`)).isError).toBe(false);
			const message = (await evalJs(memory.session, caught("await re.triage()"))).text;
			expect(message).toMatch(/^omp-re: triage: the output of rizin_command "(?:izj|aflj)" was cut at the size cap and the whole of it could not be read back \(/);
			expect(message).toContain("will not report from cut JSON");
		} finally {
			await memory.shutdown();
		}
	}, 60_000);

	test("every id a recipe cites is a real re.evidence record of a rizin_command read, and the closing list names each read by its command", () => {
		const recorded = new Map(recordedEvidence(h.session).map((record) => [record.id.slice(0, 8), record]));
		for (const name of ["triage", "scanImports", "scanImportsNoCallers", "inspectFunction", "findComparisons", "findCrypto", "blobTriage", "blobFindCrypto"]) {
			const report = text(omp[name]);
			const taken = evidenceTaken(report);
			expect(taken.length).toBeGreaterThan(0);
			for (const { id, label } of taken) {
				const record = recorded.get(id);
				expect(record).toBeDefined();
				expect(record!.tool).toBe("rizin_command");
				expect(record!.reproHash).toMatch(/^[0-9a-f]{64}$/);
				expect(label).toBe(record!.args.addr ? `${record!.args.command} @ ${record!.args.addr}` : record!.args.command);
			}
			// Nothing is cited that the list does not own up to.
			const listed = new Set(taken.map((entry) => entry.id));
			for (const id of citedIds(report)) expect(listed.has(id)).toBe(true);
		}
		expect(evidenceTaken(text(omp.triage)).map((entry) => entry.label)).toEqual(["ij", "iIj", "iSj entropy", "iij", "izj", "aflj", "iej"]);
		expect(citedIds(text(omp.triage)).length).toBe(6);
		expect(evidenceTaken(text(omp.inspectFunction)).map((entry) => entry.label.split(" ")[0])).toEqual(["afij", "pdfj", "afvlj", "izj", "axtj", "aflj"]);
	});

	test("a finding citing what triage read passes record_finding", async () => {
		// The blob is open now; cite its triage, since a finding is bound to the open binary.
		const id = evidenceTaken(text(omp.blobTriage)).find((entry) => entry.label === "iIj")!.id;
		const recorded = await evalJs(h.session, `const r = await tool.record_finding({ claim: "The file has no stack canary and its data pages are executable.", evidence: [${JSON.stringify(id)}], confidence: "likely" }); typeof r === "string" ? r : r.text`);
		expect(recorded.isError).toBe(false);
		expect(recorded.text).toMatch(/^record_finding: recorded [0-9a-f]{8}\n/);
	});

	test("the list sizes are the caller's to bound, and a cut list says what was left out", () => {
		const short = text(omp.triageShort);
		expect(short).toMatch(/^ {2}… \d+ more functions not shown$/m);
		expect(short).toMatch(/^ {2}… \d+ more notable strings not shown$/m);
		expect(short.length).toBeLessThan(text(omp.triage).length);
		expect(short.match(/^ {2}0x[0-9a-f]+ +\d+ bytes {2}\d+ blocks/gm)!.length).toBe(2);

		expect(text(omp.inspectFunctionBounded)).toMatch(/^ {2}… \d+ more callees not shown$/m);
		expect(text(omp.findComparisonsBounded)).toMatch(/^ {2}… \d+ more comparisons not shown$/m);
		expect(text(omp.findComparisonsBounded).match(/^ {2}0x[0-9a-f]+ {2}(?:cmp|test) /gm)!.length).toBeLessThanOrEqual(20);
	});

	test("scan_imports reads reach off the imports and lists the ones worth a look, with why and who calls them", () => {
		const scan = text(omp.scanImports);
		expect(scan).toMatch(/^scan_imports: \d+ imports, \d+ worth a look$/m);
		for (const part of ["Reach, by what it links [evidence ", "Imports worth a reviewer's look [evidence ", "An import is a lead."]) expect(scan).toContain(part);
		expect(scan).toMatch(/^ {2}\[(?:high|medium|low|info)\] \S+ .*\((?:memory|command|format|race|random|crypto)[^)]*\) @ 0x[0-9a-f]+ — /m);
		expect(scan).toMatch(/^ {6}called from \d+ places? \[evidence [0-9a-f]{8}\]: /m);
		// The function list is read once, the first time a caller has to be named.
		expect(evidenceTaken(scan).filter((entry) => entry.label === "aflj").length).toBe(1);
		// Without callers it makes the one read.
		expect(evidenceTaken(text(omp.scanImportsNoCallers)).map((entry) => entry.label)).toEqual(["iij"]);
		expect(text(omp.scanImportsNoCallers)).not.toContain("called from");
		if (/called from (?:[2-9]|\d\d+) places/.test(scan)) expect(text(omp.scanImportsBounded)).toMatch(/^ {2}… \d+ more callers not shown$/m);
	});

	test("inspect_function gives a function's shape, variables, callers, callees and strings", () => {
		const fn = text(omp.inspectFunction);
		expect(fn.split("\n")[0]).toBe("inspect_function: main");
		for (const part of ["Shape [evidence ", "cyclomatic complexity", "basic blocks", "calling convention", "Body [evidence ", "Variables: ", "Called from ", "distinct target", "Refers to "]) {
			expect(fn).toContain(part);
		}
		expect(fn).toContain("sym.imp."); // its callees are the calls rizin disassembled, by name
	});

	test("find_comparisons pairs each compare with the branch that follows and where it goes", () => {
		const comparisons = text(omp.findComparisons);
		expect(comparisons.split("\n")[0]).toBe("find_comparisons: main");
		expect(comparisons).toMatch(/^ {2}0x[0-9a-f]+ {2}(?:cmp|test) .+ {2}-> {2}j\w+ .+: taken when .+, to 0x[0-9a-f]+, else 0x[0-9a-f]+$/m);
		for (const part of ["Compares and the branches that follow: ", "Calls that compare or validate: ", "Strings on the way: ", "not what the comparison means"]) expect(comparisons).toContain(part);
	});

	test("an address that is no function, or that could open another command, is refused in words", () => {
		expect(refusal(omp.inspectFunctionNone)).toBe('omp-re: inspect_function: no function at 0x1 — list them with await tool.rizin_command({ command: "aflj" }), or define one with define_function');
		// The engine's own gate on what may follow `@`: nothing of this reached rizin.
		expect(refusal(omp.inspectFunctionInvalid)).toBe('omp-re: invalid address or expression: "main;!id"');
		// rizin's own words for a read that failed, passed on as the recipe's refusal.
		expect(refusal(omp.findComparisonsNone)).toMatch(/^rizin> pdfj @ 0x1\n\(no output; rizin said:\)\n.*Cannot find function/);
		expect(binaryEvidence.some((record) => record.args.addr === "main;!id")).toBe(false);
	});

	test("find_crypto finds an AES S-box, SHA-256 constants and the ChaCha sigma where they lie, and says what that does and does not show", () => {
		const crypto = text(omp.blobFindCryptoNoReferences);
		expect(crypto.split("\n")[0]).toBe("find_crypto: 3 constant hits");
		expect(crypto).toMatch(/^ {2}0x40 {2}AES — S-box \[evidence [0-9a-f]{8}\]$/m);
		expect(crypto).toMatch(/^ {2}0x80 {2}SHA-256 — .+ \[evidence [0-9a-f]{8}\]$/m);
		expect(crypto).toMatch(/^ {2}0xc0 {2}ChaCha \/ Salsa20 — .+ \[evidence [0-9a-f]{8}\]$/m);
		expect(crypto).toContain("linked in");
		expect(text(omp.blobFindCrypto)).toMatch(/^ {6}(?:referred to from .+|no reference found by analysis) \[evidence [0-9a-f]{8}\]/m);
		expect(text(omp.findCrypto)).toContain("rizin's search for keys and certificates [evidence ");
	});

	test("in find_crypto a search that finds nothing is a recorded read too: listed as evidence, never as a hit", async () => {
		const tables = JSON.parse(await readFile(join(ROOT, "recipes", "tables.json"), "utf8")) as { cryptoConstants: { hex: string }[] };
		const crypto = text(omp.blobFindCryptoNoReferences);
		const taken = evidenceTaken(crypto);
		expect(taken.map((entry) => entry.label)).toEqual(["/cmj", ...tables.cryptoConstants.map((constant) => `/xj ${constant.hex}`)]);
		// Only the three hits (and rizin's own search) are cited in the body.
		expect(citedIds(aboveEvidenceList(crypto)).length).toBe(4);
		expect(aboveEvidenceList(crypto).match(/^ {2}0x[0-9a-f]+ {2}.+ — .+ \[evidence /gm)!.length).toBe(3);
	});

	describe.skipIf(!canRunLisp)("held to the Lisp twin (nodecode/recipes.lisp)", () => {
		let lisp: Answers;

		beforeAll(async () => {
			const out = join(scratch, "lisp.json");
			const run = Bun.spawnSync(["sbcl", "--non-interactive", "--load", join(ROOT, "test", "nodecode", "recipes-out.lisp"), TEST_BINARY, blob, out], { stdout: "pipe", stderr: "pipe" });
			if (run.exitCode !== 0) throw new Error(`recipes-out.lisp failed:\n${run.stdout.toString().slice(-2000)}\n${run.stderr.toString().slice(-2000)}`);
			lisp = JSON.parse(await readFile(out, "utf8")) as Answers;
		}, 180_000);

		/** omp's triage with its one extra read — `ij`, for the path in the title — taken out of the closing list, after checking it is there and first. */
		const withoutPathRead = (report: string): string => {
			const lines = report.split("\n");
			const at = lines.findIndex((line) => line.startsWith("Evidence taken ")) + 1;
			expect(lines[at]).toMatch(/^ {2}[0-9a-f]{8} {2}ij$/);
			lines.splice(at, 1);
			return lines.join("\n");
		};

		test.each(["triage", "triageShort", "blobTriage"])("%s answers the same text, apart from the one read that names the open file", (name) => {
			expect(withoutIds(withoutPathRead(text(omp[name])))).toBe(withoutIds(text(lisp[name])));
		});

		test.each(["scanImports", "scanImportsBounded", "scanImportsNoCallers", "inspectFunction", "inspectFunctionBounded", "findComparisons", "findComparisonsBounded"])(
			"%s answers the same text, line for line",
			(name) => {
				expect(withoutIds(text(omp[name]))).toBe(withoutIds(text(lisp[name])));
			},
		);

		test.each(["findCrypto", "blobFindCrypto", "blobFindCryptoNoReferences"])("%s answers the same text above the evidence list, where omp also lists the searches that found nothing", (name) => {
			expect(withoutIds(aboveEvidenceList(text(omp[name])))).toBe(withoutIds(aboveEvidenceList(text(lisp[name]))));
			// The Lisp list is omp's with the misses left out: same reads, same order.
			const hits = new Set(citedIds(text(omp[name])));
			expect(
				evidenceTaken(text(omp[name]))
					.filter((entry) => hits.has(entry.id))
					.map((entry) => entry.label),
			).toEqual(evidenceTaken(text(lisp[name])).map((entry) => entry.label));
		});

		test("the refusals are the same words, each host naming its own call", () => {
			expect(refusal(omp.inspectFunctionInvalid)).toBe(refusal(lisp.inspectFunctionInvalid));
			expect(refusal(omp.findComparisonsNone)).toBe(refusal(lisp.findComparisonsNone));
			expect(refusal(omp.inspectFunctionNone).replace('await tool.rizin_command({ command: "aflj" })', '(re:json "aflj")')).toBe(refusal(lisp.inspectFunctionNone));
		});
	});
});

describe.skipIf(!canRunRizin)("a long read through omp's eval is cut once", () => {
	let h: Harness;

	beforeAll(async () => {
		const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
		h = await boot(SessionManager.create(tmpdir(), join(agentDir, "sessions-long-read")));
		await h.session.sessionManager.ensureOnDisk();
		expect((await evalJs(h.session, `await tool.open_binary({ path: ${JSON.stringify(TEST_BINARY)} })`)).isError).toBe(false);
	}, 120_000);

	afterAll(async () => {
		await h.shutdown();
	});

	test("the engine's own cut stays under omp's limit, so omp cuts no second hole in it", async () => {
		// Regression: a body cut to exactly omp's 50 KB tool-result limit, plus the header line, the truncation note and the
		// evidence tag, landed just over it. omp then elided the middle of what the engine had kept and named a second
		// artifact holding the already-cut text. format.ts now leaves headroom; docs/omp-eval.md has the mechanism.
		const out = await evalJs(
			h.session,
			'const r = await tool.rizin_command({ command: "pd 3000", addr: "entry0" }); print("NOTES=" + (r.text.match(/\\[Output truncated/g) || []).length + " HOLE=" + /elided|\\[Showing lines/.test(r.text) + " BYTES=" + new TextEncoder().encode(r.text).length + " TAG=" + /\\[evidence [0-9a-f]{8}/.test(r.text.split("\\n").at(-1)));',
		);
		expect(out.isError).toBe(false);
		expect(out.text).toContain("NOTES=1 HOLE=false");
		expect(out.text).toContain("TAG=true");
		expect(Number(/BYTES=(\d+)/.exec(out.text)![1])).toBeLessThanOrEqual(50 * 1024);
	});
});
