/**
 * skills/re-triage/recipes.js and recipes.py — omp-re's library for omp's
 * eval, one script for each of its kernels, and above all the five recipes
 * in it — driven through omp's REAL eval tool, loaded the way a session
 * loads them (`%load skill://re-triage/recipes.js` in a JavaScript cell,
 * `…/recipes.py` in a Python one), with the extension booted by the suites'
 * one harness (helpers.ts). Nothing here calls a model. (The verbs the
 * recipes are composed over are extension-sdk.test.ts's and bridge.test.ts's.)
 *
 * Three groups for the JavaScript script:
 *  1. no rizin: the script loads, defines `re` and nothing else, registers no
 *     tool, and a recipe with no binary open fails with the engine's words;
 *     what the generators wrote is current.
 *  2. rizin: what the code does on the test binary — that every id a recipe
 *     cites is a real `re.evidence` record, that a finding citing one passes
 *     record_finding, a read past the size cap, bounds, refusals.
 *  3. the three hosts: the same recipes run by the Lisp twin
 *     (nodecode/recipes.lisp, through test/nodecode/recipes-out.lisp) on the
 *     same two files must answer the same reports whole — every line, the
 *     list of reads included, evidence ids aside. Needs SBCL and cl-ppcre,
 *     and says so when it skips.
 *
 * And the same for the Python script, as groups of their own beside those:
 * what loading it leaves in the kernel (one name, `omp_re`, and the standard
 * library's `re` where it was), refusals; then, in the rizin session, every
 * report held to the JavaScript one for the same binary. They need a Python
 * omp can start, and say so when they skip.
 *
 * What a report says is not spelled out here: the wording, the tables and
 * the sections are data (recipes/tables.json), scripts/gen-recipes.ts refuses
 * to generate from a table that is unsound, and the comparison of the three
 * hosts is what holds each one's rendering of that data to the others'.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentSession } from "@oh-my-pi/pi-coding-agent";
import { boot as bootSession, canRunRizin, caught, evalJs, evalPy, logSkip, ownSession, pythonKernel, rmDirSafe, ROOT, scratchAgentDir, type SdkHarness as Harness, SKILLS, TEST_BINARY } from "./helpers.ts";

logSkip("recipes-eval rizin tests");

const RECIPES = join(SKILLS, "re-triage", "recipes.js");
/** How the skill tells the model to load the script: omp resolves `skill://<name>/<path>` inside the skill's own directory, wherever the plugin is installed. */
const LOAD = "%load skill://re-triage/recipes.js";
const RECIPES_PY = join(SKILLS, "re-triage", "recipes.py");
/** The same, for a `language: "py"` cell. */
const LOAD_PY = "%load skill://re-triage/recipes.py";

const python = await pythonKernel();
const canRunPython = python.ok;
if (!canRunPython) console.log(`omp-re: SKIPPING every recipes.py test — omp reports its Python backend unavailable here: ${python.reason ?? "no reason given"}`);

const canRunLisp = (() => {
	if (Bun.which("sbcl") === null) return false;
	const probe = Bun.spawnSync(["sbcl", "--non-interactive", "--eval", "(require :asdf)", "--eval", '(asdf:load-system "cl-ppcre")'], { stdout: "ignore", stderr: "ignore" });
	return probe.exitCode === 0;
})();
if (canRunRizin && !canRunLisp) console.log("omp-re: SKIPPING the recipes parity comparison with nodecode/recipes.lisp — needs sbcl and cl-ppcre");

/** Boot a session with the extension and the plugin's skills loaded, headless, as `omp -p` runs. */
const boot = (sessionManager: unknown) => bootSession(sessionManager, { headless: true, skills: true });
/** The same, for a session with a file and a directory of its own. */
const bootOwn = async () => boot(await ownSession(agentDir()));
/** The same, for a session omp keeps no file for, in a directory of its own. */
const bootFileless = async () => {
	const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
	const cwd = await mkdtemp(join(tmpdir(), "omp-re-recipes-fileless-"));
	return bootSession(SessionManager.inMemory(cwd), { headless: true, skills: true, cwd });
};

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
	expect(cell).toMatchObject({ text: "written", isError: false });
	return JSON.parse(await readFile(out, "utf8")) as Answers;
}

/** A Python cell that prints the kind and message of whatever `statement` raises, or "ok". */
const caughtPy = (statement: string) => `try:\n    ${statement}\n    print("ok")\nexcept Exception as error:\n    print(type(error).__name__ + ": " + str(error))`;

/** answers(), for the Python kernel: `calls` are Python expressions. A refusal keeps the kind of exception it was raised as. */
async function answersPy(session: AgentSession, dir: string, calls: Record<string, string>): Promise<Answers> {
	const out = join(dir, `answers-py-${Math.random().toString(36).slice(2)}.json`);
	const body = Object.entries(calls)
		.map(([name, call]) => `    try:\n        out[${JSON.stringify(name)}] = ${call}\n    except Exception as error:\n        out[${JSON.stringify(name)}] = {"error": str(error), "kind": type(error).__name__}`)
		.join("\n");
	// In a function, so that the test leaves no names of its own in the kernel; `json` and `Path` are omp's.
	const cell = await evalPy(session, `def answers():\n    out = {}\n${body}\n    Path(${JSON.stringify(out)}).write_text(json.dumps(out), encoding="utf-8")\nanswers()\ndel answers\nprint("written")`);
	expect(cell).toMatchObject({ text: "written", isError: false });
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

/** Every report asked of each host, by the name its answer is kept under. */
const REPORTS = [
	"triage",
	"triageShort",
	"scanImports",
	"scanImportsBounded",
	"scanImportsNoCallers",
	"inspectFunction",
	"inspectFunctionBounded",
	"findComparisons",
	"findComparisonsBounded",
	"findCrypto",
	"blobTriage",
	"blobScanImports",
	"blobFindCrypto",
	"blobFindCryptoNoReferences",
];

const agentDir = scratchAgentDir("recipes-test");
let scratch: string;

beforeAll(async () => {
	scratch = await mkdtemp(join(tmpdir(), "omp-re-recipes-out-"));
});

afterAll(() => rmDirSafe(scratch));

describe("recipes.js in omp's eval (no rizin needed)", () => {
	let h: Harness;

	beforeAll(async () => {
		h = await bootOwn();
	});

	afterAll(async () => {
		await h.shutdown();
	});

	test.each(["gen-recipes.ts", "gen-api.ts"])("what scripts/%s writes into the three hosts is current with its description", (script) => {
		const check = Bun.spawnSync(["bun", join(ROOT, "scripts", script), "--check"], { stdout: "pipe", stderr: "pipe" });
		expect(check.stderr.toString()).toBe("");
		expect(check.exitCode).toBe(0);
	});

	test("%load by the skill's own URL defines `re` with the verbs and the five recipes, and nothing else", async () => {
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
		expect(loaded.text).toBe(
			"omp-re loaded: re.open, re.cmd, re.json, re.call, re.tools, re.doc, re.slash, re.status, re.help, and the recipes re.triage, re.scanImports, re.inspectFunction, re.findComparisons, re.findCrypto. Every one is async: await it. print(await re.help()) is the manual; print(re.recipes()) says what each recipe answers.",
		);

		const after = await names("globals-after.json");
		expect(after.filter((name) => !before.includes(name))).toEqual(["re"]);
		expect((await evalJs(h.session, "Object.keys(re).sort().join(' ')")).text).toBe("call cmd doc findComparisons findCrypto help inspectFunction json open recipes scanImports slash status tools triage");
		// Everything that asks the engine is async; recipes() is the library's own text.
		expect((await evalJs(h.session, "Object.keys(re).filter((name) => re[name].constructor.name !== 'AsyncFunction').join(' ')")).text).toBe("recipes");
		// Recipes are code in eval, not tools: the session's tool set is what it was.
		expect(h.session.getAllToolNames().sort()).toEqual(tools);
		for (const name of ["triage", "scan_imports", "inspect_function", "find_comparisons", "find_crypto"]) {
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

	test("recipes() shows how each recipe is called", async () => {
		const help = (await evalJs(h.session, "re.recipes()")).text;
		for (const name of ["re.triage(", "re.scanImports(", "re.inspectFunction(", "re.findComparisons(", "re.findCrypto("]) expect(help).toContain(name);
	});

	test("with no binary open every recipe fails with the engine's own message", async () => {
		const message = 'omp-re: no binary open — open one first: await re.open("/path/to/binary") — in Python, omp_re.open("/path/to/binary")';
		for (const call of ["re.triage()", "re.scanImports()", 're.inspectFunction("main")', 're.findComparisons("main")', "re.findCrypto()"]) {
			expect((await evalJs(h.session, caught(`await ${call}`))).text).toBe(message);
		}
	});

	test("arguments of the wrong shape are refused in words before any read", async () => {
		expect((await evalJs(h.session, caught("await re.inspectFunction(4096)"))).text).toBe("omp-re: inspect_function: a function is named by a string, not 4096");
		expect((await evalJs(h.session, caught("await re.findComparisons()"))).text).toBe("omp-re: find_comparisons: a function is named by a string, not null");
		expect((await evalJs(h.session, caught("await re.triage(5)"))).text).toBe("omp-re: triage: options are one object, e.g. { maxItems: 20 }, not 5");
	});
});

describe.skipIf(!canRunPython)("recipes.py in omp's Python kernel (no rizin needed)", () => {
	let h: Harness;

	beforeAll(async () => {
		h = await bootOwn();
	});

	afterAll(async () => {
		await h.shutdown();
	});

	const RECIPE_NAMES = ["triage", "scan_imports", "inspect_function", "find_comparisons", "find_crypto"];

	test("%load by the skill's own URL defines `omp_re` with the verbs and the five recipes and nothing else, and leaves the standard library's `re` where omp put it", async () => {
		const names = async (file: string) => {
			expect((await evalPy(h.session, `Path(${JSON.stringify(join(scratch, file))}).write_text(json.dumps(sorted(globals())), encoding="utf-8")\nprint("written")`)).text).toBe("written");
			return JSON.parse(await readFile(join(scratch, file), "utf8")) as string[];
		};
		const before = await names("py-globals-before.json");
		// Why the Python global is not `re`: omp's own prelude has already bound that name, to the regex module, in every Python cell.
		expect(before).toContain("re");
		expect((await evalPy(h.session, 'print(type(re).__name__, re.__name__, re.sub("a", "b", "aaa"))')).text).toBe("module re bbb");
		expect(before).not.toContain("omp_re");
		const tools = h.session.getAllToolNames().sort();

		const loaded = await evalPy(h.session, LOAD_PY);
		expect(loaded).toMatchObject({
			isError: false,
			text: "omp-re loaded: omp_re.open, omp_re.cmd, omp_re.json, omp_re.call, omp_re.tools, omp_re.doc, omp_re.slash, omp_re.status, omp_re.help, and the recipes omp_re.triage, omp_re.scan_imports, omp_re.inspect_function, omp_re.find_comparisons, omp_re.find_crypto. Every one is a plain call: nothing is awaited. print(omp_re.help()) is the manual; print(omp_re.recipes()) says what each recipe answers.",
		});

		const after = await names("py-globals-after.json");
		// `__file__` is omp's doing, for any script it %loads (eval/py/runner.py, _prepare_file_source); the script's own one name is `omp_re`.
		expect(after.filter((name) => !before.includes(name))).toEqual(["__file__", "omp_re"]);
		expect((await evalPy(h.session, "print(__file__)")).text).toBe(RECIPES_PY);
		expect((await evalPy(h.session, 'print(type(re).__name__, re.__name__, re.sub("a", "b", "aaa"))')).text).toBe("module re bbb");
		expect((await evalPy(h.session, 'print(" ".join(sorted(name for name in dir(omp_re) if not name.startswith("_"))))')).text).toBe("call cmd doc find_comparisons find_crypto help inspect_function json open recipes scan_imports slash status tools triage");
		// Python helpers in omp's eval are synchronous, and so are these: plain functions, not coroutine functions.
		expect((await evalPy(h.session, 'print(all(callable(getattr(omp_re, name)) and not inspect.iscoroutinefunction(getattr(omp_re, name)) for name in dir(omp_re) if not name.startswith("_")))')).text).toBe("True");
		expect((await evalPy(h.session, "omp_re")).text).toBe("<omp-re: open, cmd, json, call, tools, doc, slash, status, help; recipes triage, scan_imports, inspect_function, find_comparisons, find_crypto — print(omp_re.help()) is the manual>");
		// Recipes are code in eval, not tools: the session's tool set is what it was.
		expect(h.session.getAllToolNames().sort()).toEqual(tools);
		for (const name of RECIPE_NAMES) expect(h.session.getToolByName(name)).toBeUndefined();
	});

	test("the skill's URL resolves to the file in this repository, and its plain path loads too", async () => {
		expect((await evalPy(h.session, 'print("\\n".join(read("skill://re-triage/recipes.py").split("\\n")[:2]))')).text).toBe(`[Skill file: ${RECIPES_PY}]\n# recipes.py — omp-re in omp's eval, for the Python kernel: the verbs that reach`);
		const again = await evalPy(h.session, `%load ${JSON.stringify(RECIPES_PY)}`);
		expect(again.isError).toBe(false); // loading it again replaces `omp_re` without complaint
		expect((await evalPy(h.session, "print(callable(omp_re.triage))")).text).toBe("True");
	});

	test("recipes() shows how each recipe is called, in this kernel's call forms", async () => {
		const help = (await evalPy(h.session, "print(omp_re.recipes())")).text;
		for (const name of RECIPE_NAMES) expect(help).toContain(`omp_re.${name}(`);
	});

	test("what the library answers is text: shown as written when it is the cell's value, and a cell that awaits it gets the same string", async () => {
		const printed = (await evalPy(h.session, "print(omp_re.recipes())")).text;
		// A plain str left as a cell's last expression is shown as its repr, on one quoted line; a text of the library's is shown as written.
		expect((await evalPy(h.session, '"two\\nlines"')).text).toBe("'two\\nlines'");
		expect((await evalPy(h.session, "omp_re.recipes()")).text).toBe(printed);
		expect((await evalPy(h.session, "print(isinstance(omp_re.recipes(), str), type(await omp_re.recipes()).__name__, (await omp_re.recipes()) == omp_re.recipes())")).text).toBe("True str True");
		// The engine's own text is one too: a line's answer is read as it stands.
		expect((await evalPy(h.session, 'omp_re.slash("help")')).text).toStartWith("/re open <path>");
		expect((await evalPy(h.session, 'print((await omp_re.status()) == omp_re.status())')).text).toBe("True");
	});

	test("with no binary open every recipe fails with the engine's own message", async () => {
		const message = 'RuntimeError: omp-re: no binary open — open one first: await re.open("/path/to/binary") — in Python, omp_re.open("/path/to/binary")';
		for (const call of ["omp_re.triage()", "omp_re.scan_imports()", 'omp_re.inspect_function("main")', 'omp_re.find_comparisons("main")', "omp_re.find_crypto()"]) {
			expect((await evalPy(h.session, caughtPy(call))).text).toBe(message);
		}
	});

	test("arguments of the wrong shape are refused before any read: an address in recipes.js's words, an option in Python's own", async () => {
		expect((await evalPy(h.session, caughtPy("omp_re.inspect_function(4096)"))).text).toBe("TypeError: omp-re: inspect_function: a function is named by a string, not 4096");
		expect((await evalPy(h.session, caughtPy("omp_re.find_comparisons()"))).text).toBe("TypeError: omp-re: find_comparisons: a function is named by a string, not null");
		// Options are keyword arguments here, so Python itself refuses a stray positional one or a misspelt name — naming the recipe as it is called.
		expect((await evalPy(h.session, caughtPy("omp_re.triage(5)"))).text).toBe("TypeError: omp_re.triage() takes 0 positional arguments but 1 was given");
		expect((await evalPy(h.session, caughtPy("omp_re.triage(maxStrings=5)"))).text).toStartWith("TypeError: omp_re.triage() got an unexpected keyword argument 'maxStrings'");
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
	/** The same calls made of recipes.py in the same session's Python kernel, under the same names; empty when omp has no Python here. */
	let py: Answers = {};
	/** Evidence recorded before the blob was opened: the test binary's. */
	let binaryEvidence: EvidenceEntry[];

	beforeAll(async () => {
		h = await bootOwn();
		await h.session.sessionManager.ensureOnDisk();
		blob = join(scratch, "tables.bin");
		await writeFile(blob, constantsBlob());

		expect((await evalJs(h.session, LOAD)).isError).toBe(false);
		expect((await evalJs(h.session, `await re.open(${JSON.stringify(TEST_BINARY)})`)).isError).toBe(false);
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
			inspectFunctionNotAString: "re.inspectFunction(4096)",
			findComparisons: 're.findComparisons("main")',
			findComparisonsBounded: 're.findComparisons("main", { maxItems: 20 })',
			findComparisonsNone: 're.findComparisons("0x1")',
			findComparisonsNotAString: "re.findComparisons()",
			findCrypto: "re.findCrypto()",
		});
		if (canRunPython) {
			expect((await evalPy(h.session, LOAD_PY)).isError).toBe(false);
			py = await answersPy(h.session, scratch, {
				triage: "omp_re.triage()",
				triageShort: "omp_re.triage(max_strings=1, max_functions=2)",
				scanImports: "omp_re.scan_imports()",
				scanImportsBounded: "omp_re.scan_imports(max_callers=1)",
				scanImportsNoCallers: "omp_re.scan_imports(callers=False)",
				inspectFunction: 'omp_re.inspect_function("main")',
				inspectFunctionBounded: 'omp_re.inspect_function("main", max_items=3)',
				inspectFunctionNone: 'omp_re.inspect_function("0x1")',
				inspectFunctionInvalid: 'omp_re.inspect_function("main;!id")',
				inspectFunctionNotAString: "omp_re.inspect_function(4096)",
				findComparisons: 'omp_re.find_comparisons("main")',
				findComparisonsBounded: 'omp_re.find_comparisons("main", max_items=20)',
				findComparisonsNone: 'omp_re.find_comparisons("0x1")',
				findComparisonsNotAString: "omp_re.find_comparisons()",
				findCrypto: "omp_re.find_crypto()",
			});
		}
		binaryEvidence = recordedEvidence(h.session);

		expect((await evalJs(h.session, `await re.open(${JSON.stringify(blob)}, { arch: "x86", bits: 64, format: "any" })`)).isError).toBe(false);
		Object.assign(
			omp,
			await answers(h.session, scratch, {
				blobTriage: "re.triage()",
				blobScanImports: "re.scanImports()",
				blobFindCrypto: "re.findCrypto()",
				blobFindCryptoNoReferences: "re.findCrypto({ references: false })",
			}),
		);
		if (canRunPython) {
			Object.assign(
				py,
				await answersPy(h.session, scratch, {
					blobTriage: "omp_re.triage()",
					blobScanImports: "omp_re.scan_imports()",
					blobFindCrypto: "omp_re.find_crypto()",
					blobFindCryptoNoReferences: "omp_re.find_crypto(references=False)",
				}),
			);
		}
	}, 180_000);

	afterAll(async () => {
		await h.shutdown();
	});


	test("a read cut at the size cap is read whole, not parsed cut", () => {
		// The premise: this binary's function list is past the cap, so the text of the call held none of its JSON.
		const record = binaryEvidence.find((entry) => entry.args.command === "aflj") as (EvidenceEntry & { artifactId?: string; summary?: string }) | undefined;
		expect(record?.artifactId).toEqual(expect.any(String));
		expect(record?.summary).toContain("[Output truncated: 0 of 1 lines");
		// And yet the report counts and lists the functions (the comparison below holds the count to the Lisp twin's, which reads rizin's pipe directly).
		expect(Number(/^Functions: (\d+);/m.exec(text(omp.triage))![1])).toBeGreaterThan(20);
		expect(text(omp.triage)).toMatch(/^ {2}… \d+ more functions not shown$/m);
	});

	test("a session with no artifact store reads the whole of a cut read all the same: the data comes beside the text, not through an artifact", async () => {
		// A session that is not on disk has nowhere to keep what the size cap cut from a text.
		const memory = await bootFileless();
		try {
			expect((await evalJs(memory.session, LOAD)).isError).toBe(false);
			expect((await evalJs(memory.session, `await re.open(${JSON.stringify(TEST_BINARY)})`)).isError).toBe(false);
			const report = text((await answers(memory.session, scratch, { triage: "re.triage()" })).triage);
			expect(withoutIds(report)).toBe(withoutIds(text(omp.triage)));
		} finally {
			await memory.shutdown();
		}
	}, 60_000);

	test("every id a recipe cites is a real re.evidence record of a rizin_command read, and the closing list names each read by its command", () => {
		const recorded = new Map(recordedEvidence(h.session).map((record) => [record.id.slice(0, 8), record]));
		for (const name of REPORTS) {
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
		const recorded = await evalJs(h.session, `await re.call("record_finding", { claim: "The file has no stack canary and its data pages are executable.", evidence: [${JSON.stringify(id)}], confidence: "likely" })`);
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

	test("scan_imports reads the function list once, and without callers makes the one read", () => {
		const scan = text(omp.scanImports);
		expect(scan).toMatch(/^ {6}called from \d+ places? \[evidence [0-9a-f]{8}\]: /m);
		// The function list is read the first time a caller has to be named, and not again.
		expect(evidenceTaken(scan).filter((entry) => entry.label === "aflj").length).toBe(1);
		expect(evidenceTaken(text(omp.scanImportsNoCallers)).map((entry) => entry.label)).toEqual(["iij"]);
	});

	test("find_comparisons pairs each compare with the branch that follows and where it goes", () => {
		expect(text(omp.findComparisons)).toMatch(/^ {2}0x[0-9a-f]+ {2}(?:cmp|test) .+ {2}-> {2}j\w+ .+, to 0x[0-9a-f]+, else 0x[0-9a-f]+$/m);
	});

	test("an address that is no function, or that could open another command, is refused in words", () => {
		expect(refusal(omp.inspectFunctionNone)).toBe('omp-re: inspect_function: no function at 0x1 — list them with await re.json("aflj"), or define one with define_function');
		// The engine's own gate on what may follow `@`: nothing of this reached rizin.
		expect(refusal(omp.inspectFunctionInvalid)).toBe('omp-re: invalid address or expression: "main;!id"');
		// rizin's own words for a read that failed, passed on as the recipe's refusal.
		expect(refusal(omp.findComparisonsNone)).toMatch(/^rizin> pdfj @ 0x1\n\(no output; rizin said:\)\n.*Cannot find function/);
		expect(binaryEvidence.some((record) => record.args.addr === "main;!id")).toBe(false);
	});

	test("find_crypto finds an AES S-box, SHA-256 constants and the ChaCha sigma where they lie, and reads what refers to each", () => {
		const crypto = text(omp.blobFindCryptoNoReferences);
		expect(crypto.split("\n")[0]).toBe("find_crypto: 3 constant hits");
		expect(crypto).toMatch(/^ {2}0x40 {2}AES — S-box \[evidence [0-9a-f]{8}\]$/m);
		expect(crypto).toMatch(/^ {2}0x80 {2}SHA-256 — .+ \[evidence [0-9a-f]{8}\]$/m);
		expect(crypto).toMatch(/^ {2}0xc0 {2}ChaCha \/ Salsa20 — .+ \[evidence [0-9a-f]{8}\]$/m);
		// One more read for each hit says what refers to it.
		expect(
			evidenceTaken(text(omp.blobFindCrypto))
				.map((entry) => entry.label)
				.filter((label) => label.startsWith("axtj @ ")),
		).toEqual(["axtj @ 0x40", "axtj @ 0x80", "axtj @ 0xc0"]);
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

	describe.skipIf(!canRunPython)("recipes.py, held to recipes.js in the same session", () => {
		test.each(REPORTS)("%s answers the same text as the JavaScript kernel's, line for line", (name) => {
			expect(withoutIds(text(py[name]))).toBe(withoutIds(text(omp[name])));
		});

		test("the refusals are the same words, raised as RuntimeError, each kernel naming its own call", () => {
			for (const name of ["inspectFunctionNone", "inspectFunctionInvalid", "findComparisonsNone"]) expect((py[name] as { kind?: string }).kind).toBe("RuntimeError");
			for (const name of ["inspectFunctionInvalid", "findComparisonsNone", "inspectFunctionNotAString", "findComparisonsNotAString"]) expect(refusal(py[name])).toBe(refusal(omp[name]));
			expect(refusal(py.inspectFunctionNone)).toBe('omp-re: inspect_function: no function at 0x1 — list them with omp_re.json("aflj"), or define one with define_function');
			expect(refusal(py.inspectFunctionNone).replace('omp_re.json("aflj")', 'await re.json("aflj")')).toBe(refusal(omp.inspectFunctionNone));
		});

		test("a read cut at the size cap is read whole by the Python kernel too, not parsed cut", () => {
			// The same premise as the JavaScript test above (this binary's `aflj` is past the cap), and the same count as JavaScript read.
			const functions = Number(/^Functions: (\d+);/m.exec(text(py.triage))![1]);
			expect(functions).toBeGreaterThan(20);
			expect(functions).toBe(Number(/^Functions: (\d+);/m.exec(text(omp.triage))![1]));
			expect(text(py.triage)).toMatch(/^ {2}… \d+ more functions not shown$/m);
		});

		test("in a session with no artifact store the Python recipe reads the whole of a cut read as well", async () => {
			const memory = await bootFileless();
			try {
				expect((await evalPy(memory.session, LOAD_PY)).isError).toBe(false);
				expect((await evalPy(memory.session, `omp_re.open(${JSON.stringify(TEST_BINARY)})\nprint("opened")`)).text).toBe("opened");
				const report = text((await answersPy(memory.session, scratch, { triage: "omp_re.triage()" })).triage);
				expect(withoutIds(report)).toBe(withoutIds(text(omp.triage)));
			} finally {
				await memory.shutdown();
			}
		}, 60_000);

		test("every id a Python recipe cites is a real re.evidence record of a rizin_command read, named in the closing list by its command", () => {
			const recorded = new Map(recordedEvidence(h.session).map((record) => [record.id.slice(0, 8), record]));
			for (const name of REPORTS) {
				const report = text(py[name]);
				const taken = evidenceTaken(report);
				expect(taken.length).toBeGreaterThan(0);
				for (const { id, label } of taken) {
					const record = recorded.get(id);
					expect(record).toBeDefined();
					expect(record!.tool).toBe("rizin_command");
					expect(label).toBe(record!.args.addr ? `${record!.args.command} @ ${record!.args.addr}` : record!.args.command);
				}
				const listed = new Set(taken.map((entry) => entry.id));
				for (const id of citedIds(report)) expect(listed.has(id)).toBe(true);
			}
			expect(evidenceTaken(text(py.triage)).map((entry) => entry.label)).toEqual(["ij", "iIj", "iSj entropy", "iij", "izj", "aflj", "iej"]);
		});

		test("a finding citing what a Python recipe read passes record_finding", async () => {
			// The blob is open now; cite its triage, since a finding is bound to the open binary.
			const id = evidenceTaken(text(py.blobTriage)).find((entry) => entry.label === "iIj")!.id;
			const recorded = await evalPy(
				h.session,
				`print(omp_re.call("record_finding", claim="The file is not position-independent: it loads at a fixed address.", evidence=[${JSON.stringify(id)}], confidence="likely"))`,
			);
			expect(recorded.isError).toBe(false);
			expect(recorded.text).toMatch(/^record_finding: recorded [0-9a-f]{8}\n/);
		});

		test("an address past 2^53 is the one rizin printed, in both kernels: the blob mapped where a kernel image lies", async () => {
			// Last in this group: it opens the blob again, mapped high, and what is open afterwards is that.
			// rizin prints an address as a decimal integer; 0xffffffff80000040 is not a value a double holds, so a parse through one prints …000 instead.
			expect((await evalJs(h.session, `await re.open(${JSON.stringify(blob)}, { arch: "x86", bits: 64, format: "any", map: "0xffffffff80000000" })`)).isError).toBe(false);
			const js = text((await answers(h.session, scratch, { high: "re.findCrypto({ references: false })" })).high);
			const python = text((await answersPy(h.session, scratch, { high: "omp_re.find_crypto(references=False)" })).high);
			expect(python).toMatch(/^ {2}0xffffffff80000040 {2}AES — S-box \[evidence [0-9a-f]{8}\]$/m);
			expect(python).toMatch(/^ {2}0xffffffff80000080 {2}SHA-256 — /m);
			expect(python).toMatch(/^ {2}0xffffffff800000c0 {2}ChaCha \/ Salsa20 — /m);
			expect(withoutIds(python)).toBe(withoutIds(js));
		}, 60_000);
	});

	describe.skipIf(!canRunLisp)("held to the Lisp twin (nodecode/recipes.lisp)", () => {
		let lisp: Answers;

		beforeAll(async () => {
			const out = join(scratch, "lisp.json");
			const run = Bun.spawnSync(["sbcl", "--non-interactive", "--load", join(ROOT, "test", "nodecode", "recipes-out.lisp"), TEST_BINARY, blob, out], { stdout: "pipe", stderr: "pipe" });
			if (run.exitCode !== 0) throw new Error(`recipes-out.lisp failed:\n${run.stdout.toString().slice(-2000)}\n${run.stderr.toString().slice(-2000)}`);
			lisp = JSON.parse(await readFile(out, "utf8")) as Answers;
		}, 180_000);

		// Whole reports: the three hosts take the same reads in the same order, so nothing is set aside but the ids.
		test.each(REPORTS)("%s answers the same report, line for line, the list of reads included", (name) => {
			expect(withoutIds(text(lisp[name]))).toBe(withoutIds(text(omp[name])));
		});

		test("the refusals are the same words, each host naming its own call", () => {
			// The engine's own refusal of what may follow `@`, rizin's own words for a read that failed, and the recipes' refusal of a name that is no string.
			for (const name of ["inspectFunctionInvalid", "findComparisonsNone", "inspectFunctionNotAString", "findComparisonsNotAString"]) expect(refusal(lisp[name])).toBe(refusal(omp[name]));
			expect(refusal(omp.inspectFunctionNone).replace('await re.json("aflj")', '(re:json "aflj")')).toBe(refusal(lisp.inspectFunctionNone));
		});
	});
});

describe.skipIf(!canRunRizin)("a long read through omp's eval is cut once", () => {
	let h: Harness;

	beforeAll(async () => {
		h = await bootOwn();
		await h.session.sessionManager.ensureOnDisk();
		expect((await evalJs(h.session, LOAD)).isError).toBe(false);
		expect((await evalJs(h.session, `await re.open(${JSON.stringify(TEST_BINARY)})`)).isError).toBe(false);
	}, 120_000);

	afterAll(async () => {
		await h.shutdown();
	});

	test("the engine's own cut stays under omp's limit, so a cell that prints a long read has no second hole cut in it", async () => {
		// Regression: a body cut to exactly omp's 50 KB limit on what a cell shows, plus the header line, the truncation note
		// and the evidence tag, landed just over it. omp then elided the middle of what the engine had kept and named a second
		// artifact holding the already-cut text. The engine leaves headroom (engine/util.lisp, +MAX-OCTETS+); docs/omp-eval.md has the mechanism.
		const out = await evalJs(
			h.session,
			'const text = await re.cmd("pd 3000", "entry0"); print(text); print("NOTES=" + (text.match(/\\[Output truncated/g) || []).length + " BYTES=" + new TextEncoder().encode(text).length + " TAG=" + /\\[evidence [0-9a-f]{8}/.test(text.split("\\n").at(-1)));',
		);
		expect(out.isError).toBe(false);
		expect(out.text).toContain("NOTES=1 ");
		expect(out.text).toContain("TAG=true");
		expect(out.text).toStartWith("rizin> pd 3000 @ entry0\n");
		expect(out.text).not.toMatch(/elided|\[Showing lines/);
		expect(out.text.match(/\[Output truncated/g)).toHaveLength(1);
		expect(Number(/BYTES=(\d+)/.exec(out.text)![1])).toBeLessThanOrEqual(50 * 1024);
	});
});
