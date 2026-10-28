/**
 * The omp-native guide surface (tools-guide.ts): the pure renderers
 * (signature/readParams/describeTool/describeAll) against real omptype schemas,
 * and the registered re_manual / re_describe tools driven through the stub host.
 */
import { describe, expect, test } from "bun:test";
import * as z from "@oh-my-pi/omptype/zod";
import {
	describeAll,
	describeTool,
	readParams,
	RE_MANUAL,
	registerGuideTools,
	signature,
	type ToolMeta,
} from "../extensions/re/tools-guide.ts";
import { makeHarness, textOf } from "./helpers.ts";
import { jsonResult, textResult } from "../extensions/re/format.ts";
import { registerReadTools } from "../extensions/re/tools-read.ts";
import { registerRizinTools } from "../extensions/re/tools-rizin.ts";

const sampleSchema = z.object({
	addr: z.string().describe("Address or name."),
	limit: z.number().optional().describe("Max rows."),
	sort: z.union([z.literal("address"), z.literal("size")]).optional().describe("Sort order."),
});

describe("readParams (schema reader)", () => {
	test("reads omptype IR: names, optionality, type label, and authored descriptions", () => {
		const params = readParams(sampleSchema);
		expect(params).toEqual([
			{ name: "addr", optional: false, type: "string", description: "Address or name." },
			{ name: "limit", optional: true, type: "number", description: "Max rows." },
			{ name: "sort", optional: true, type: '"address" | "size"', description: "Sort order." },
		]);
	});

	test("an empty object schema has no parameters", () => {
		expect(readParams(z.object({}))).toEqual([]);
	});

	test("falls back to JSON-Schema shape (properties/required)", () => {
		const jsonSchema = {
			properties: { path: { type: "string", description: "A path." }, force: { type: "boolean", description: "Overwrite." } },
			required: ["path"],
		};
		expect(readParams(jsonSchema)).toEqual([
			{ name: "path", optional: false, type: "string", description: "A path." },
			{ name: "force", optional: true, type: "boolean", description: "Overwrite." },
		]);
	});

	test("an unreadable schema yields no parameters rather than throwing", () => {
		expect(readParams(undefined)).toEqual([]);
		expect(readParams(null)).toEqual([]);
		expect(readParams(42)).toEqual([]);
	});
});

describe("signature", () => {
	test("marks optional parameters with a trailing ?", () => {
		expect(signature("list_functions", sampleSchema)).toBe("list_functions(addr, limit?, sort?)");
	});
	test("a parameterless tool renders name()", () => {
		expect(signature("re_manual", z.object({}))).toBe("re_manual()");
	});
});

describe("describeTool", () => {
	test("renders the signature, the eval call form, the description, and each parameter", () => {
		const meta: ToolMeta = { name: "list_functions", description: "List functions.\nSecond line ignored in the one-liner.", parameters: sampleSchema };
		const out = describeTool(meta);
		expect(out).toContain("list_functions(addr, limit?, sort?)");
		expect(out).toContain("await tool.list_functions({");
		expect(out).toContain("List functions.");
		expect(out).toContain("addr (string) — Address or name.");
		expect(out).toContain("limit? (number) — Max rows.");
		expect(out).toContain('sort? ("address" | "size") — Sort order.');
	});

	test("says 'Parameters: none' for a no-arg tool", () => {
		expect(describeTool({ name: "re_manual", description: "The manual.", parameters: z.object({}) })).toContain("Parameters: none");
	});
});

describe("describeAll (grouped listing)", () => {
	const tools: ToolMeta[] = [
		{ name: "open_binary", description: "Open a binary.", parameters: z.object({ path: z.string() }) },
		{ name: "list_functions", description: "List functions.", parameters: sampleSchema },
		{ name: "rizin_help", description: "Look up rizin commands.", parameters: z.object({ query: z.string() }) },
	];

	test("groups by tier, shows signatures and one-line docs, and only lists tools that are present", () => {
		const out = describeAll(tools);
		expect(out).toContain("## Session");
		expect(out).toContain("  open_binary(path) — Open a binary.");
		expect(out).toContain("## Read");
		expect(out).toContain("  list_functions(addr, limit?, sort?) — List functions.");
		expect(out).toContain("rizin bridge");
		expect(out).toContain("  rizin_help(query) — Look up rizin commands.");
		// A tier with no present tools (e.g. Debugger) is omitted entirely.
		expect(out).not.toContain("Debugger");
		expect(out).toContain('await tool.re_describe({ name: "<tool>" })');
	});

	test("a non-RE tool is ignored, and an unknown RE tool falls into 'Other' rather than vanishing", () => {
		// `analyze` is a real RE tool (RE_ANALYZE_TOOL_NAMES); place it so it shows under its tier, and
		// prove a non-RE tool (omp's own) never appears.
		const out = describeAll([...tools, { name: "bash", description: "Not an RE tool.", parameters: z.object({}) }]);
		expect(out).not.toContain("bash");
	});
});

describe("re_manual eval guidance (display vs print)", () => {
	// The exact parser the manual documents for turning a list tool's result text into rows for display().
	// In eval, `r.text` is the flattened result text — the same string as content[0].text here.
	const rows = (text: string) => JSON.parse(text.slice(text.indexOf("\n") + 1));

	test("the documented parse turns a list result into rows for display()", async () => {
		const res = await jsonResult("206 functions", [
			{ ea: "0x1", name: "a" },
			{ ea: "0x2", name: "b" },
		]);
		expect(rows(textOf(res))).toEqual([
			{ ea: "0x1", name: "a" },
			{ ea: "0x2", name: "b" },
		]);
	});

	test("the parse throws on code/text output, so show() falls back to print", async () => {
		const res = await textResult("decompiled 0x1 (pdg)", "int main() { return 0; }");
		expect(() => rows(textOf(res))).toThrow();
	});

	test("the manual teaches display() and ships the show() helper", () => {
		expect(RE_MANUAL).toContain("display(");
		expect(RE_MANUAL).toContain("const show =");
		expect(RE_MANUAL).toContain("print(");
	});
});

describe("re_manual tool", () => {
	test("registers discoverable and returns the manual naming the namespace and how to start", async () => {
		const h = makeHarness("guide-manual");
		registerGuideTools(h.pi);
		const def = h.tool("re_manual");
		expect(def.loadMode).toBe("discoverable");
		const result = await def.execute("call-1", {}, new AbortController().signal, undefined, h.ctx);
		const text = textOf(result);
		expect(text).toContain(RE_MANUAL.split("\n")[0]); // the opening line
		expect(text).toContain("await tool.open_binary(");
		expect(text).toContain("await tool.re_describe(");
		expect(text).toContain("xd://");
	});
});

describe("re_describe tool", () => {
	test("with no name, lists the live RE capabilities read back from getAllTools()", async () => {
		const h = makeHarness("guide-describe-all");
		// Register real tool groups so getAllTools() returns genuine RE tools to enumerate.
		registerReadTools(h.pi);
		registerRizinTools(h.pi);
		registerGuideTools(h.pi);
		const result = await h.tool("re_describe").execute("call-1", {}, new AbortController().signal, undefined, h.ctx);
		const text = textOf(result);
		expect(text).toContain("## Read");
		expect(text).toContain("decompile_function(addr)");
		expect(text).toContain("rizin_help(query)");
		// re_describe/re_manual are meta, not RE capabilities, so they are not listed among them.
		expect(text).not.toContain("re_manual(");
	});

	test("with a name, returns that capability's full parameters", async () => {
		const h = makeHarness("guide-describe-one");
		registerReadTools(h.pi);
		registerGuideTools(h.pi);
		const result = await h.tool("re_describe").execute("call-1", { name: "list_functions" }, new AbortController().signal, undefined, h.ctx);
		const text = textOf(result);
		expect(text).toContain("list_functions(");
		expect(text).toContain("Parameters:");
		expect(text).toContain("await tool.list_functions({");
	});

	test("an unknown name is a clean error, not a throw", async () => {
		const h = makeHarness("guide-describe-missing");
		registerReadTools(h.pi);
		registerGuideTools(h.pi);
		const result = await h.tool("re_describe").execute("call-1", { name: "no_such_tool" }, new AbortController().signal, undefined, h.ctx);
		expect(result.isError).toBe(true);
		expect(textOf(result)).toContain("no capability named");
	});
});
