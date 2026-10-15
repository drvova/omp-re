/**
 * The extensible decompiler selection (decompile.ts). The probe-order and
 * label logic is pure (no rizin); availability against a real rizin is checked
 * in tools-registry.test.ts via decompile_function.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { decompilerCommands, decompilerLabel } from "../extensions/re/decompile.ts";

const original = process.env.OMPRE_DECOMPILER;
afterEach(() => {
	if (original === undefined) delete process.env.OMPRE_DECOMPILER;
	else process.env.OMPRE_DECOMPILER = original;
});

describe("decompilerCommands", () => {
	test("defaults to rz-ghidra then jsdec", () => {
		delete process.env.OMPRE_DECOMPILER;
		expect(decompilerCommands()).toEqual(["pdg", "pdd"]);
	});

	test("OMPRE_DECOMPILER reorders, and the built-ins are kept as fallback", () => {
		process.env.OMPRE_DECOMPILER = "pdd";
		expect(decompilerCommands()).toEqual(["pdd", "pdg"]);
	});

	test("an unknown plugin command is probed first, built-ins still follow", () => {
		process.env.OMPRE_DECOMPILER = "pdx";
		expect(decompilerCommands()).toEqual(["pdx", "pdg", "pdd"]);
	});

	test("duplicates collapse and junk entries are dropped", () => {
		process.env.OMPRE_DECOMPILER = "pdg, pdg , bad!name, , pdd";
		expect(decompilerCommands()).toEqual(["pdg", "pdd"]);
	});
});

describe("decompilerLabel", () => {
	test("names the two known plugins and marks any other as a plugin", () => {
		expect(decompilerLabel("pdg")).toBe("rz-ghidra (pdg)");
		expect(decompilerLabel("pdd")).toBe("jsdec (pdd)");
		expect(decompilerLabel("pdx")).toBe("pdx (plugin)");
		expect(decompilerLabel(null)).toContain("none");
	});
});
