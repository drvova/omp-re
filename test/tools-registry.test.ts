/**
 * Deterministic coverage for the read-tier tool wrappers registered by
 * registerReadTools() (tools-read.ts), executed through a stub ExtensionAPI
 * the same way omp calls them: execute(toolCallId, params, signal, onUpdate, ctx).
 *
 * "Valid argument" assertions are checked against ground truth fetched
 * independently (raw rz.cmd/cmdj calls in beforeAll, never by calling into
 * tools-read.ts), so a broken rizin command template inside a tool — not a
 * coincidence of this file mirroring it — is what makes a test fail. Ground
 * truth is picked from whatever the fixture contains (default /bin/ls), so any
 * ELF or PE with a `main` works as OMPRE_TEST_BINARY.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { DECOMPILER_EMPTY_PREFIX, DISASM_ONLY_PREFIX } from "../extensions/re/decompile.ts";
import { reRenderers } from "../extensions/re/render.ts";
import { addrOf, eaFromOffset, RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { attachSession, getState, shutdownState, switchBinary } from "../extensions/re/state.ts";
import { registerReadTools } from "../extensions/re/tools-read.ts";
import { canRunRizin, captureError, logSkip, makeHarness, rizinPath, splitHeaderBody, TEST_BINARY, textOf } from "./helpers.ts";

logSkip("tools-registry tests");

/** An address string that fails validateAddr's allowlist (the ';' makes command-injection intent obvious). */
const BAD_ADDR = "main;whoami";
const invalidAddrMessage = (addr: string) => `omp-re: invalid address or expression: ${JSON.stringify(addr)}`;

/** Mirrors tools-read.ts's own (unexported) pageHeader() so header assertions test real behavior without importing a private helper. */
function expectedPageHeader(label: string, pageLen: number, total: number, offset = 0): string {
	if (pageLen >= total) return `${pageLen} ${label}`;
	return `${pageLen} of ${total} ${label} (offset=${offset}; use offset/limit to page through the rest)`;
}

function mustFind<T>(items: T[], pred: (item: T) => boolean, label: string): T {
	const found = items.find(pred);
	if (!found) throw new Error(`tools-registry.test setup: fixture ${TEST_BINARY} is missing ${label}`);
	return found;
}

interface GroundFn {
	offset?: number;
	addr?: number;
	name: string;
	size: number;
	realsz?: number;
}

/** Bytes of code, the way the tools report a function's size: rizin's realsz, falling back to its linear span. */
const groundSize = (fn: GroundFn) => fn.realsz ?? fn.size;
interface GroundImport {
	name: string;
	plt?: number;
}
interface GroundString {
	vaddr?: number;
	string: string;
}
interface GroundSegment {
	name: string;
	perm: string;
	vaddr?: number;
}
interface GroundXref {
	from?: number;
	to?: number;
	type: string;
}
interface GroundPdf {
	ops: { offset?: number; addr?: number; type: string; disasm: string }[];
}

const harness = makeHarness("tools-registry-test-session");
const { ctx } = harness;
const tool = harness.tool;
const run = (name: string, params: Record<string, unknown>) => tool(name).execute(`t-${name}`, params, undefined, undefined, ctx);

let session: RzSession;
let groundFns: GroundFn[];
let mainFn: GroundFn;
let mainEa: string;
let callSite: number;
let groundImports: GroundImport[];
let pltImport: GroundImport;
let groundExports: unknown[];
let groundSymbols: unknown[];
let groundStrings: GroundString[];
let probeString: GroundString;
let groundSegments: GroundSegment[];
let execSegment: GroundSegment;
let groundAxt: GroundXref[];
let groundAxf: GroundXref[];
let groundPdf: GroundPdf;
let expectedDecompiler: "pdg" | "pdd" | null;

describe.skipIf(!canRunRizin)("registerReadTools (read-only rizin tool wrappers)", () => {
	beforeAll(async () => {
		const binaryPath = await resolveBinaryPath(TEST_BINARY);
		session = await RzSession.spawn(rizinPath, binaryPath);
		switchBinary(ctx, binaryPath);
		attachSession(ctx, session);
		registerReadTools(harness.pi);

		groundFns = JSON.parse((await session.cmd("aflj")).trim()) as GroundFn[];
		mainFn = mustFind(groundFns, (f) => f.name === "main", "a function named 'main'");
		mainEa = eaFromOffset(addrOf(mainFn)!);

		groundPdf = JSON.parse((await session.cmd(`pdfj @ ${mainEa}`)).trim()) as GroundPdf;
		callSite = addrOf(mustFind(groundPdf.ops, (op) => op.type === "call", "a call instruction in main"))!;

		groundImports = JSON.parse((await session.cmd("iij")).trim()) as GroundImport[];
		pltImport = mustFind(groundImports, (i) => typeof i.plt === "number" && i.plt > 0, "an import with a PLT stub");
		groundExports = JSON.parse((await session.cmd("iEj")).trim()) as unknown[];
		groundSymbols = JSON.parse((await session.cmd("isj")).trim()) as unknown[];

		groundStrings = JSON.parse((await session.cmd("izj")).trim()) as GroundString[];
		probeString = mustFind(
			groundStrings,
			(s) => s.string.length >= 12 && groundStrings.filter((o) => o.string.includes(s.string)).length === 1,
			"a unique string of at least 12 characters",
		);

		groundSegments = JSON.parse((await session.cmd("iSj")).trim()) as GroundSegment[];
		execSegment = mustFind(groundSegments, (s) => s.perm.includes("x") && s.name.length > 0, "an executable section");

		groundAxt = JSON.parse((await session.cmd(`axtj @ ${mainEa}`)).trim()) as GroundXref[];
		groundAxf = JSON.parse((await session.cmd(`axfj @ ${callSite}`)).trim()) as GroundXref[];
		if (groundAxf.length === 0) throw new Error("tools-registry.test setup: expected an outgoing xref from main's first call");

		const pdgHelp = (await session.cmd("pdg?")).trim();
		const pddHelp = (await session.cmd("pdd?")).trim();
		expectedDecompiler = pdgHelp.length > 0 ? "pdg" : pddHelp.length > 0 ? "pdd" : null;
	});

	afterAll(() => {
		shutdownState(ctx.sessionManager.getSessionId());
	});

	test("registers all read-tier analysis tools, each with read approval and renderers", () => {
		for (const name of [
			"list_functions",
			"search_functions",
			"get_function",
			"decompile_function",
			"disassemble_function",
			"get_xrefs_to",
			"get_xrefs_from",
			"list_imports",
			"list_exports",
			"list_symbols",
			"list_strings",
			"list_segments",
			"hash_binary",
			"get_graph",
		]) {
			const def = tool(name);
			expect(def.approval).toBe("read");
			expect(typeof def.renderCall).toBe("function");
			expect(typeof def.renderResult).toBe("function");
		}
	});

	describe("list_functions", () => {
		test("valid: limit=1 returns the first function page-shaped, with matching total and hex ea", async () => {
			const { header, body } = splitHeaderBody(textOf(await run("list_functions", { limit: 1 })));
			expect(header).toBe(expectedPageHeader("functions", 1, groundFns.length));
			const parsed = JSON.parse(body) as { ea: string; name: string; size: number; offset?: number; callrefs?: unknown }[];
			expect(parsed).toHaveLength(1);
			expect(parsed[0]?.name).toBe(groundFns[0]!.name);
			expect(parsed[0]?.ea).toBe(eaFromOffset(addrOf(groundFns[0]!)!));
			expect(parsed[0]?.size).toBe(groundSize(groundFns[0]!));
			// Rows are slimmed: no decimal offset, no per-function reference arrays.
			expect(parsed[0]?.offset).toBeUndefined();
			expect(parsed[0]?.callrefs).toBeUndefined();
		});

		test("valid: sort by size orders by bytes of code (realsz), and shows the linear span only when it differs", async () => {
			const { body } = splitHeaderBody(textOf(await run("list_functions", { sort: "size", limit: 5 })));
			const parsed = JSON.parse(body) as { name: string; size: number; span?: number }[];
			const expected = [...groundFns].sort((a, b) => groundSize(b) - groundSize(a)).slice(0, 5);
			expect(parsed.map((row) => row.size)).toEqual(expected.map(groundSize));
			for (const [i, row] of parsed.entries()) {
				const ground = expected[i]!;
				if (ground.size === groundSize(ground)) expect(row.span).toBeUndefined();
				else expect(row.span).toBe(ground.size);
			}
		});

		test("sort=callers orders by rizin's indegree, most-called first", async () => {
			const { header, body } = splitHeaderBody(textOf(await run("list_functions", { sort: "callers", limit: 5 })));
			expect(header.endsWith(`functions by callers (offset=0; use offset/limit to page through the rest)`)).toBe(true);
			const parsed = JSON.parse(body) as { callers: number }[];
			const most = Math.max(...groundFns.map((f) => (f as { indegree?: number }).indegree ?? 0));
			expect(parsed[0]?.callers).toBe(most);
			for (let i = 1; i < parsed.length; i++) expect(parsed[i - 1]!.callers).toBeGreaterThanOrEqual(parsed[i]!.callers);
		});

		test("list rows are one compact JSON object per line", async () => {
			const { body } = splitHeaderBody(textOf(await run("list_functions", { limit: 3 })));
			const lines = body.split("\n");
			expect(lines).toHaveLength(5);
			expect(lines[0]).toBe("[");
			expect(lines[4]).toBe("]");
		});

		test("invalid: non-numeric limit is rejected by the parameter schema", () => {
			const result = tool("list_functions").parameters.safeParse({ limit: "nope" });
			expect(result.success).toBe(false);
			if (!result.success) expect(result.error.issues[0]?.path).toEqual(["limit"]);
		});

		test("a page past the end is empty, says so, and is marked useless for compaction", async () => {
			const offset = groundFns.length + 10;
			const result = await run("list_functions", { offset });
			expect(splitHeaderBody(textOf(result)).header).toBe(expectedPageHeader("functions", 0, groundFns.length, offset));
			expect(result.useless).toBe(true);
		});
	});

	describe("search_functions", () => {
		test("valid: query 'main' returns only name-matching functions, page-shaped", async () => {
			const groundMatches = groundFns.filter((f) => f.name.includes("main"));
			const { header, body } = splitHeaderBody(textOf(await run("search_functions", { query: "main", limit: 5 })));
			const pageLen = Math.min(5, groundMatches.length);
			expect(header).toBe(expectedPageHeader(`functions matching ${JSON.stringify("main")}`, pageLen, groundMatches.length));
			const parsed = JSON.parse(body) as { name: string }[];
			expect(parsed.length).toBe(pageLen);
			for (const fn of parsed) expect(fn.name).toContain("main");
		});

		test("invalid: missing required query is rejected by the parameter schema", () => {
			const result = tool("search_functions").parameters.safeParse({});
			expect(result.success).toBe(false);
			if (!result.success) expect(result.error.issues[0]?.path).toEqual(["query"]);
		});
	});

	describe("get_function", () => {
		test("valid: target 'main' returns its name, size, and hex ea", async () => {
			const result = await run("get_function", { target: "main" });
			const text = textOf(result);
			expect(text.startsWith(`main at ${mainEa} (size ${groundSize(mainFn)})\n`)).toBe(true);
			const parsed = JSON.parse(splitHeaderBody(text).body) as {
				name: string;
				ea: string;
				signature?: string;
				calls: { ea: string; name?: string }[];
				refCounts: { calls: number };
				callrefs?: unknown;
			};
			expect(parsed.name).toBe("main");
			expect(parsed.ea).toBe(mainEa);
			expect(result.details?.ea).toBe(mainEa);
			// Raw reference arrays are summarized, never dumped.
			expect(parsed.callrefs).toBeUndefined();
			expect(parsed.refCounts.calls).toBeGreaterThan(0);
			// main's first call target is among the named, deduplicated call targets.
			const firstCallTarget = groundAxf.find((x) => x.type === "CALL")?.to;
			if (firstCallTarget !== undefined) expect(parsed.calls.map((c) => c.ea)).toContain(eaFromOffset(firstCallTarget));
			expect(new Set(parsed.calls.map((c) => c.ea)).size).toBe(parsed.calls.length);
			expect(parsed.calls.some((c) => typeof c.name === "string")).toBe(true);
		});

		test("invalid: a target containing forbidden characters throws validateAddr's exact message", async () => {
			expect((await captureError(run("get_function", { target: BAD_ADDR }))).message).toBe(invalidAddrMessage(BAD_ADDR));
		});

		test("an unknown name is a clear error, not an empty result", async () => {
			expect((await captureError(run("get_function", { target: "no_such_function_xyz" }))).message).toBe(
				"omp-re: function not found: no_such_function_xyz",
			);
		});
	});

	describe("decompile_function", () => {
		test("valid: 'main' is decompiled by the probed plugin, or labeled disassembly when there is none", async () => {
			const result = await run("decompile_function", { addr: "main" });
			const text = textOf(result);
			expect(result.details?.ea).toBe(mainEa);
			if (expectedDecompiler) {
				expect(result.details?.decompiler).toBe(expectedDecompiler);
				expect(text.startsWith(`decompiled ${mainEa} (${expectedDecompiler})\n`)).toBe(true);
				expect(text).toContain("main");
			} else {
				expect(result.details?.decompiler).toBe("disasm");
				expect(text.startsWith(`${DISASM_ONLY_PREFIX}disassembly of ${mainEa}\n`)).toBe(true);
			}
			expect(text.startsWith(DECOMPILER_EMPTY_PREFIX)).toBe(false);
		}, 30_000); // a real decompiler (rz-ghidra) loading its Sleigh specs cold can take longer than the default 5s

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			expect((await captureError(run("decompile_function", { addr: BAD_ADDR }))).message).toBe(invalidAddrMessage(BAD_ADDR));
		});

		test("an unresolvable name fails fast with a clear error", async () => {
			expect((await captureError(run("decompile_function", { addr: "no_such_function_xyz" }))).message).toBe(
				"omp-re: could not resolve address: no_such_function_xyz",
			);
		});
	});

	describe("disassemble_function", () => {
		test("valid: 'main' returns the real disassembly with matching instruction count and first line", async () => {
			const text = textOf(await run("disassemble_function", { addr: "main" }));
			const firstOp = groundPdf.ops[0]!;
			expect(text.startsWith(`${groundPdf.ops.length} instructions at ${mainEa}\n`)).toBe(true);
			expect(text).toContain(`${eaFromOffset(addrOf(firstOp)!)}  ${firstOp.disasm}`);
		});

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			expect((await captureError(run("disassemble_function", { addr: BAD_ADDR }))).message).toBe(invalidAddrMessage(BAD_ADDR));
		});
	});

	describe("get_xrefs_to", () => {
		test("valid: 'main' returns exactly rizin's xrefs with hex fromEa", async () => {
			const { header, body } = splitHeaderBody(textOf(await run("get_xrefs_to", { addr: "main" })));
			expect(header).toBe(expectedPageHeader("xrefs to main", groundAxt.length, groundAxt.length));
			const parsed = JSON.parse(body) as (GroundXref & { fromEa?: string })[];
			expect(parsed.length).toBe(groundAxt.length);
			for (const [i, row] of parsed.entries()) {
				expect(row.from).toBe(groundAxt[i]!.from);
				expect(row.fromEa).toBe(eaFromOffset(groundAxt[i]!.from!));
			}
		});

		test("invalid: an addr containing forbidden characters throws validateAddr's exact message", async () => {
			expect((await captureError(run("get_xrefs_to", { addr: BAD_ADDR }))).message).toBe(invalidAddrMessage(BAD_ADDR));
		});
	});

	describe("get_xrefs_from", () => {
		test("valid: a real call site returns its outgoing xref with matching hex toEa", async () => {
			const addr = eaFromOffset(callSite);
			const { header, body } = splitHeaderBody(textOf(await run("get_xrefs_from", { addr })));
			expect(header).toBe(expectedPageHeader(`xrefs from ${addr}`, groundAxf.length, groundAxf.length));
			const parsed = JSON.parse(body) as (GroundXref & { toEa?: string })[];
			expect(parsed[0]?.to).toBe(groundAxf[0]!.to);
			expect(parsed[0]?.toEa).toBe(eaFromOffset(groundAxf[0]!.to!));
		});
	});

	describe("list_imports", () => {
		test("valid: default page includes a real PLT-backed import with matching ea", async () => {
			const { header, body } = splitHeaderBody(textOf(await run("list_imports", {})));
			const pageLen = Math.min(200, groundImports.length);
			expect(header).toBe(expectedPageHeader("imports", pageLen, groundImports.length));
			const parsed = JSON.parse(body) as (GroundImport & { ea?: string })[];
			const found = mustFind(parsed, (i) => i.name === pltImport.name, `${pltImport.name} in tool output`);
			expect(found.ea).toBe(eaFromOffset(pltImport.plt!));
		});

		test("invalid: non-numeric offset is rejected by the parameter schema", () => {
			expect(tool("list_imports").parameters.safeParse({ offset: "nope" }).success).toBe(false);
		});
	});

	describe("list_exports", () => {
		test("valid: the default page matches rizin's export table size", async () => {
			const { header } = splitHeaderBody(textOf(await run("list_exports", {})));
			expect(header).toBe(expectedPageHeader("exports", Math.min(200, groundExports.length), groundExports.length));
		});
	});

	describe("list_symbols", () => {
		test("valid: the default page matches rizin's symbol table size (a superset of exports)", async () => {
			const { header } = splitHeaderBody(textOf(await run("list_symbols", {})));
			expect(header).toBe(expectedPageHeader("symbols", Math.min(200, groundSymbols.length), groundSymbols.length));
			expect(groundSymbols.length).toBeGreaterThanOrEqual(groundExports.length);
		});

		test("valid: a name filter narrows the table", async () => {
			// Derive the needle from a real symbol so the test is fixture-agnostic.
			const first = (groundSymbols as { name?: string }[]).find((s) => typeof s.name === "string" && s.name.length >= 4);
			const needle = first!.name!.slice(0, 4);
			const { body } = splitHeaderBody(textOf(await run("list_symbols", { filter: needle })));
			const parsed = JSON.parse(body) as { name: string }[];
			expect(parsed.length).toBeGreaterThan(0);
			expect(parsed.every((s) => s.name.includes(needle))).toBe(true);
		});
	});

	describe("list_strings", () => {
		test("valid: the default page is capped at 200 of the real total", async () => {
			const { header } = splitHeaderBody(textOf(await run("list_strings", {})));
			expect(header).toBe(expectedPageHeader("strings", Math.min(200, groundStrings.length), groundStrings.length));
		});

		test("valid: filtering for a unique string returns exactly that string with its ea", async () => {
			const { body } = splitHeaderBody(textOf(await run("list_strings", { filter: probeString.string })));
			const parsed = JSON.parse(body) as { string: string; ea?: string }[];
			expect(parsed).toHaveLength(1);
			expect(parsed[0]?.string).toBe(probeString.string);
			expect(parsed[0]?.ea).toBe(eaFromOffset(probeString.vaddr!));
		});

		test("invalid: non-string filter is rejected by the parameter schema", () => {
			expect(tool("list_strings").parameters.safeParse({ filter: 42 }).success).toBe(false);
		});
	});

	describe("list_segments", () => {
		test("valid: includes a real executable section with matching hex ea, and never prints rizin's UINT64_MAX sentinel", async () => {
			const text = textOf(await run("list_segments", {}));
			const parsed = JSON.parse(splitHeaderBody(text).body) as (GroundSegment & { ea?: string })[];
			expect(parsed.length).toBe(groundSegments.length);
			const found = mustFind(parsed, (s) => s.name === execSegment.name, `${execSegment.name} in tool output`);
			expect(found.ea).toBe(eaFromOffset(execSegment.vaddr!));
			expect(text).not.toContain("0x10000000000000000");
		});
	});

	describe("hash_binary", () => {
		test("returns the same digests as an independent hash of the file", async () => {
			const bytes = await Bun.file(getState(ctx).binaryPath!).arrayBuffer();
			const sha256 = new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
			const text = textOf(await run("hash_binary", {}));
			expect(text).toContain(`sha256=${sha256}`);
			expect(text).toContain(`size=${bytes.byteLength}`);
		});
	});

	describe("get_graph", () => {
		test("function_cfg returns basic-block nodes with addresses and resolved edges matching rizin's own graph", async () => {
			const ground = JSON.parse((await session.cmd(`agf json @ ${mainEa}`)).trim()) as { nodes: { id: number; offset: number; out_nodes?: number[] }[] };
			const { body } = splitHeaderBody(textOf(await run("get_graph", { kind: "function_cfg", addr: "main", limit: 1000 })));
			const rows = JSON.parse(body) as { ea: string; to: string[] }[];
			expect(rows.length).toBe(ground.nodes.length);
			// every node's address is hex and corresponds to a ground-truth block offset
			const groundEas = new Set(ground.nodes.map((n) => eaFromOffset(n.offset)));
			expect(rows.every((r) => groundEas.has(r.ea))).toBe(true);
			// edges resolve to addresses (not raw ids): the entry block's successors match ground truth
			const entry = ground.nodes[0]!;
			const expectedTo = (entry.out_nodes ?? []).map((id) => eaFromOffset(ground.nodes.find((n) => n.id === id)!.offset));
			expect(rows.find((r) => r.ea === eaFromOffset(entry.offset))?.to.sort()).toEqual(expectedTo.sort());
		});

		test("callgraph works and function_cfg without addr is rejected before rizin", async () => {
			expect(textOf(await run("get_graph", { kind: "callgraph", addr: "main" }))).toContain("graph: callgraph @ main");
			expect((await captureError(run("get_graph", { kind: "function_cfg" }))).message).toContain("needs addr");
		});
	});

	describe("long output", () => {
		test("get_function on a large function spills to a session artifact when truncated", async () => {
			const biggest = [...groundFns].sort((a, b) => b.size - a.size)[0]!;
			const result = await run("get_function", { target: eaFromOffset(addrOf(biggest)!) });
			if (result.details?.truncated) {
				expect(result.details.artifactId).toBeDefined();
				expect(textOf(result)).toContain(`artifact://${result.details.artifactId}`);
			} else {
				expect(result.details?.artifactId).toBeUndefined();
			}
		});
	});
});

describe("reRenderers", () => {
	const theme = {
		fg: (_color: string, text: string) => text,
		bold: (text: string) => text,
		styledSymbol: (key: string) => (key === "status.error" ? "x" : key === "status.success" ? "ok" : "*"),
		spinnerFrames: ["-", "\\"],
	} as never;
	const render = (component: { render(width: number): readonly string[] }) =>
		component
			.render(200)
			.map((line) => line.trimEnd())
			.join("\n");

	test("renderCall shows the title and the call's subject", () => {
		const { renderCall } = reRenderers({ title: "Decompile", subject: "addr", body: "code" });
		expect(render(renderCall({ addr: "main" }, { expanded: false, isPartial: false }, theme))).toContain("Decompile main");
	});

	test("renderResult shows the header and a collapsed text preview with a hidden-line count", () => {
		const { renderResult } = reRenderers({ title: "Disassemble", subject: "addr", body: "text" });
		const body = Array.from({ length: 20 }, (_, i) => `0x${i}  nop`).join("\n");
		const out = render(
			renderResult(
				{ content: [{ type: "text", text: `20 instructions at 0x0\n${body}` }], details: { header: "20 instructions at 0x0", summary: "" } },
				{ expanded: false, isPartial: false },
				theme,
				{ addr: "main" },
			),
		);
		expect(out).toContain("ok 20 instructions at 0x0");
		expect(out).toContain("0x0  nop");
		expect(out).toContain("14 more lines");
	});

	test("renderResult labels disassembly-only output and links a spilled artifact", () => {
		const { renderResult } = reRenderers({ title: "Decompile", subject: "addr", body: "code" });
		const out = render(
			renderResult(
				{
					content: [{ type: "text", text: `${DISASM_ONLY_PREFIX}disassembly of 0x10\n0x10  ret` }],
					details: { header: DISASM_ONLY_PREFIX.trim(), summary: "", decompiler: "disasm", truncated: true, artifactId: "3" },
				},
				{ expanded: true, isPartial: false },
				theme,
			),
		);
		expect(out).toContain("disassembly only");
		expect(out).toContain("artifact://3");
		expect(out).toContain("0x10  ret");
	});

	test("describeCall gives Tern a native head with the call's target", () => {
		const { describeCall } = reRenderers({ title: "Decompile", subject: "addr", body: "code" });
		expect(describeCall({ addr: "main" })).toEqual({ tool: { title: "Decompile", target: "main", meta: [] }, inline: true });
	});

	test("describeResult renders decompiler output as a C code node and labels the disassembly fallback", () => {
		const { describeResult } = reRenderers({ title: "Decompile", subject: "addr", body: "code" });
		const decompiled = describeResult(
			{
				content: [{ type: "text", text: "decompiled 0x10 (pdg)\nint main(void) { return 0; }" }],
				details: { header: "decompiled 0x10 (pdg)", summary: "", decompiler: "pdg" },
			},
			{ expanded: false, isPartial: false },
			{ addr: "main" },
		);
		expect(decompiled.tool?.meta).toEqual(["decompiled 0x10 (pdg)"]);
		expect(decompiled.body?.[0]).toMatchObject({ k: "code", p: { lang: "c", text: "int main(void) { return 0; }" } });

		const fallback = describeResult(
			{
				content: [{ type: "text", text: `${DISASM_ONLY_PREFIX}disassembly of 0x10\n0x10  ret` }],
				details: { header: DISASM_ONLY_PREFIX.trim(), summary: "", decompiler: "disasm", artifactId: "2" },
			},
			{ expanded: false, isPartial: false },
		);
		expect(fallback.tone).toBe("warning");
		expect(JSON.stringify(fallback.tool?.meta)).toContain("disassembly only");
		expect(JSON.stringify(fallback.tool?.meta)).toContain("artifact://2");
		expect((fallback.body?.[0] as { p?: { lang?: string } }).p?.lang).toBeUndefined();
	});

	test("describeResult shows progress while partial and a one-line error gist", () => {
		const { describeResult } = reRenderers({ title: "Open binary", subject: "path", body: "text" });
		const partial = describeResult({ content: [{ type: "text", text: "Analyzing ls with rizin… 3s" }] }, { expanded: false, isPartial: true }, { path: "/bin/ls" });
		expect(partial.tool?.target).toBe("/bin/ls");
		expect(JSON.stringify(partial.tool?.meta)).toContain("Analyzing ls with rizin… 3s");
		const failed = describeResult({ content: [{ type: "text", text: "omp-re: boom\nstack" }], isError: true }, { expanded: false, isPartial: false });
		expect(failed.tone).toBe("error");
		expect(JSON.stringify(failed.tool?.meta)).toContain("— omp-re: boom");
		expect(failed.body).toHaveLength(1);
	});

	test("renderResult shows partial progress and errors on one line", () => {
		const { renderResult } = reRenderers({ title: "Open binary", subject: "path", body: "text" });
		expect(render(renderResult({ content: [{ type: "text", text: "Analyzing ls with rizin… 3s" }] }, { expanded: false, isPartial: true, spinnerFrame: 1 }, theme))).toBe(
			"\\ Analyzing ls with rizin… 3s",
		);
		expect(render(renderResult({ content: [{ type: "text", text: "omp-re: boom\nstack" }], isError: true }, { expanded: false, isPartial: false }, theme))).toBe(
			"x omp-re: boom",
		);
	});
});
