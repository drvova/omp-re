import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import type { SessionEntry } from "@oh-my-pi/pi-coding-agent";
import { annotationCommands, annotationFingerprint, liveAnnotations } from "../extensions/re/annotations.ts";
import { recordedAnalysisPasses, recordedSignatures } from "../extensions/re/entries.ts";
import { ANALYSIS_PASSES, isAnalysisPass } from "../extensions/re/passes.ts";
import { parseAppliedCount, signatureApplyCommand, validateSignaturePath } from "../extensions/re/signatures.ts";
import type { SessionEntry as Entry } from "@oh-my-pi/pi-coding-agent";
import { baseRizinFlags, buildLoadFlags, eaFromOffset, isExecutable, normalizeAddr, parseRizinVersionArch, readBinaryBits, resolveRizinPath, rzQuote, validateAddr, validateIdent, validateText, validateTypeLike } from "../extensions/re/rizin.ts";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

describe("validateAddr", () => {
	test("accepts hex addresses, flag names, and arithmetic", () => {
		expect(validateAddr("0x401d80")).toBe("0x401d80");
		expect(validateAddr("main")).toBe("main");
		expect(validateAddr("sym.imp.getenv")).toBe("sym.imp.getenv");
		expect(validateAddr("main+0x10")).toBe("main+0x10");
		expect(validateAddr("$$")).toBe("$$");
	});

	test("rejects a command-injection payload with a semicolon", () => {
		expect(() => validateAddr("0x401d80; rm -rf /")).toThrow("omp-re: invalid address or expression");
	});

	test("rejects backticks, newlines, and command substitution", () => {
		expect(() => validateAddr("`whoami`")).toThrow();
		expect(() => validateAddr("0x401d80\nrm -rf /")).toThrow();
		expect(() => validateAddr("$(whoami)")).toThrow();
	});

	test("rejects rizin's @@ foreach iterators, grep (~), and pipes", () => {
		expect(() => validateAddr("main@@f")).toThrow();
		expect(() => validateAddr("main@@c:afl")).toThrow();
		expect(() => validateAddr("main~{}")).toThrow();
		expect(() => validateAddr("main|cat")).toThrow();
		expect(() => validateAddr("'main'")).toThrow();
	});
});

describe("buildLoadFlags", () => {
	test("no options ⇒ no flags (header autodetection)", () => {
		expect(buildLoadFlags()).toEqual([]);
		expect(buildLoadFlags({})).toEqual([]);
	});

	test("maps arch/bits/base/map/format to rizin's own flags", () => {
		expect(buildLoadFlags({ arch: "x86", bits: 32 })).toEqual(["-a", "x86", "-b", "32"]);
		expect(buildLoadFlags({ base: "0x400000" })).toEqual(["-B", "0x400000"]);
		expect(buildLoadFlags({ map: "0x400000" })).toEqual(["-m", "0x400000"]);
		expect(buildLoadFlags({ format: "any" })).toEqual(["-F", "any"]);
	});

	test("rejects a bits value that isn't 8/16/32/64", () => {
		expect(() => buildLoadFlags({ bits: 7 as unknown as 8 })).toThrow("omp-re: load: invalid bits");
	});

	test("rejects a flag-shaped or injection-shaped arch/format", () => {
		expect(() => buildLoadFlags({ arch: "-rm" })).toThrow("omp-re: load: invalid arch");
		expect(() => buildLoadFlags({ format: "a b" })).toThrow("omp-re: load: invalid format");
		expect(() => buildLoadFlags({ base: "0x1; id" })).toThrow("omp-re: invalid address");
	});
});

describe("rzQuote", () => {
	test("wraps a value in single quotes", () => {
		expect(rzQuote("hello world")).toBe("'hello world'");
	});

	test("escapes embedded single quotes and backslashes", () => {
		expect(rzQuote("it's")).toBe("'it\\'s'");
		expect(rzQuote("back\\slash")).toBe("'back\\\\slash'");
	});

	test("leaves rizin metacharacters literal inside the quotes", () => {
		expect(rzQuote("x; !id ~ @ | > `y` $(z) #")).toBe("'x; !id ~ @ | > `y` $(z) #'");
	});

	test("rejects line breaks and NUL, which would end the pipe line", () => {
		expect(() => rzQuote("a\nb")).toThrow();
		expect(() => rzQuote("a\rb")).toThrow();
		expect(() => rzQuote("a\0b")).toThrow();
	});
});

describe("normalizeAddr", () => {
	test("lowercases and zero-normalizes 0x-prefixed values consistently", () => {
		expect(normalizeAddr("0x1100")).toBe("0x1100");
		expect(normalizeAddr("0X01100")).toBe("0x1100");
		expect(normalizeAddr("0x1100 ")).toBe("0x1100");
		expect(normalizeAddr("0x001100")).toBe("0x1100");
	});

	test("preserves a single zero digit", () => {
		expect(normalizeAddr("0x0")).toBe("0x0");
		expect(normalizeAddr("0x00000")).toBe("0x0");
	});

	test("lowercases a non-0x-prefixed value unchanged otherwise", () => {
		expect(normalizeAddr("MAIN")).toBe("main");
	});
});

describe("validateIdent / validateTypeLike / validateText", () => {
	test("validateIdent passes ordinary identifiers", () => {
		expect(validateIdent("name", "sub_401000")).toBe("sub_401000");
		expect(validateIdent("name", "_leading")).toBe("_leading");
	});

	test("validateIdent rejects identifiers starting with a digit or containing spaces", () => {
		expect(() => validateIdent("name", "1abc")).toThrow();
		expect(() => validateIdent("name", "a b")).toThrow();
		expect(() => validateIdent("name", "a;b")).toThrow();
	});

	test("validateTypeLike passes ordinary type strings", () => {
		expect(validateTypeLike("type", "int *")).toBe("int *");
		expect(validateTypeLike("type", "struct Foo *")).toBe("struct Foo *");
	});

	test("validateTypeLike rejects each documented forbidden character", () => {
		for (const c of [";", "|", "&", "`", "$", "\n", "\0"]) {
			expect(() => validateTypeLike("type", `int${c}x`)).toThrow();
		}
	});

	test("validateText passes ordinary comment bodies, including rizin metacharacters", () => {
		expect(validateText("this looks like a decoder loop")).toBe("this looks like a decoder loop");
		expect(validateText("x; !id")).toBe("x; !id");
	});

	test("validateText rejects line breaks and NUL", () => {
		expect(() => validateText("line one\nline two")).toThrow();
		expect(() => validateText("carriage\rreturn")).toThrow();
		expect(() => validateText("has\0nul")).toThrow();
	});
});

describe("eaFromOffset", () => {
	test("formats to the 0x… form the evidence store keys on", () => {
		expect(eaFromOffset(0)).toBe("0x0");
		expect(eaFromOffset(4201856)).toBe("0x401d80");
	});
});

describe("annotationCommands", () => {
	test("quotes every value and addresses with @ ea", () => {
		expect(annotationCommands("rename_function", "0x4da0", "parse_args", "main")).toEqual(["afn 'parse_args' @ 0x4da0"]);
		expect(annotationCommands("rename_variable", "0x4da0", "counter", "var_10h")).toEqual(["afvn 'counter' 'var_10h' @ 0x4da0"]);
		expect(annotationCommands("set_prototype", "0x4da0", "int main(int argc, char **argv)", "")).toEqual([
			"afs 'int main(int argc, char **argv)' @ 0x4da0",
		]);
		expect(annotationCommands("set_variable_type", "0x4da0", "char *", "int", "buf")).toEqual(["afvt 'buf' 'char *' @ 0x4da0"]);
	});

	test("a comment is always clear-then-write, and an empty one only clears", () => {
		expect(annotationCommands("set_comment", "0x10", "decoder loop", "")).toEqual(["CC- @ 0x10", "CC 'decoder loop' @ 0x10"]);
		expect(annotationCommands("set_comment", "0x10", "", "old")).toEqual(["CC- @ 0x10"]);
	});

	test("a comment carrying a command separator and shell escape stays one quoted argument", () => {
		expect(annotationCommands("set_comment", "0x10", "x; !id", "")).toEqual(["CC- @ 0x10", "CC 'x; !id' @ 0x10"]);
	});

	test("define_function toggles af/af- on whether a function should exist", () => {
		// forward (to = non-empty sentinel) defines; undo (to = "") deletes.
		expect(annotationCommands("define_function", "0x4da0", "fcn.00004da0", "")).toEqual(["af @ 0x4da0"]);
		expect(annotationCommands("define_function", "0x4da0", "", "fcn.00004da0")).toEqual(["af- @ 0x4da0"]);
	});

	test("set_calling_convention just sets afc, both directions", () => {
		expect(annotationCommands("set_calling_convention", "0x4da0", "ms", "amd64")).toEqual(["afc ms @ 0x4da0"]);
		expect(annotationCommands("set_calling_convention", "0x4da0", "amd64", "ms")).toEqual(["afc amd64 @ 0x4da0"]);
		expect(() => annotationCommands("set_calling_convention", "0x4da0", "bad;id", "amd64")).toThrow("omp-re: invalid cc");
	});

	test("set_flag drops the old flag name and adds the new, either side maybe empty", () => {
		expect(annotationCommands("set_flag", "0x61000", "decrypt_key", "")).toEqual(["f decrypt_key @ 0x61000"]);
		expect(annotationCommands("set_flag", "0x61000", "", "decrypt_key")).toEqual(["f- decrypt_key"]);
		expect(annotationCommands("set_flag", "0x61000", "new.name", "old.name")).toEqual(["f- old.name", "f new.name @ 0x61000"]);
		expect(() => annotationCommands("set_flag", "0x61000", "bad name", "")).toThrow("omp-re: invalid flag");
	});

	test("set_arch_hint builds aha/ahb from the encoded value, and undo deletes both", () => {
		expect(annotationCommands("set_arch_hint", "0x1000", "arch=arm;bits=16", "")).toEqual(["aha arm @ 0x1000", "ahb 16 @ 0x1000"]);
		expect(annotationCommands("set_arch_hint", "0x1000", "bits=32", "")).toEqual(["ahb 32 @ 0x1000"]);
		expect(annotationCommands("set_arch_hint", "0x1000", "arch=mips", "")).toEqual(["aha mips @ 0x1000"]);
		expect(annotationCommands("set_arch_hint", "0x1000", "", "arch=arm;bits=16")).toEqual(["aha- @ 0x1000", "ahb- @ 0x1000"]);
		expect(() => annotationCommands("set_arch_hint", "0x1000", "bits=7", "")).toThrow("invalid arch hint bits");
		expect(() => annotationCommands("set_arch_hint", "0x1000", "flavor=spicy", "")).toThrow("invalid arch hint");
	});

	test("rejects invalid identifiers, addresses, and unknown kinds", () => {
		expect(() => annotationCommands("rename_function", "0x10", "1bad", "x")).toThrow("omp-re: invalid name");
		expect(() => annotationCommands("rename_function", "main;id", "ok", "x")).toThrow("omp-re: invalid address");
		expect(() => annotationCommands("bogus", "0x10", "a", "b")).toThrow("omp-re: unknown annotation kind");
	});

	test("restoring an empty prototype or type is a no-op rather than an invalid command", () => {
		expect(annotationCommands("set_prototype", "0x10", "", "int f(void)")).toEqual([]);
		expect(annotationCommands("set_variable_type", "0x10", "", "int", "v")).toEqual([]);
	});
});

describe("analysis passes", () => {
	test("every pass maps to an aa* command and isAnalysisPass recognizes exactly those names", () => {
		for (const [name, command] of Object.entries(ANALYSIS_PASSES)) {
			expect(command).toMatch(/^aa[a-z]+$/);
			expect(isAnalysisPass(name)).toBe(true);
		}
		expect(isAnalysisPass("not_a_pass")).toBe(false);
		expect(isAnalysisPass("aaa")).toBe(false);
	});
});

describe("signatures", () => {
	test("signatureApplyCommand quotes the path as a single Fs argument", () => {
		expect(signatureApplyCommand("/sigs/libc.sig")).toBe("Fs '/sigs/libc.sig'");
		expect(signatureApplyCommand("/my sigs/x.pat")).toBe("Fs '/my sigs/x.pat'");
	});

	test("validateSignaturePath rejects empty paths and pipe-breaking characters", () => {
		expect(() => validateSignaturePath("")).toThrow("empty path");
		expect(() => validateSignaturePath("a\nb")).toThrow("line break or NUL");
		expect(() => validateSignaturePath("a\0b")).toThrow("line break or NUL");
		expect(validateSignaturePath("/ok/path.sig")).toBe("/ok/path.sig");
	});

	test("parseAppliedCount reads rizin's `Found N FLIRT signatures` line", () => {
		expect(parseAppliedCount("Found 12 FLIRT signatures via /x.sig")).toBe(12);
		expect(parseAppliedCount("Found 1 FLIRT signature via /x.pat")).toBe(1);
		expect(parseAppliedCount("Found 0 FLIRT signatures via /x.sig")).toBe(0);
		expect(parseAppliedCount("nothing here")).toBeUndefined();
	});

	test("recordedAnalysisPasses scopes passes to the binary and de-duplicates them in order", () => {
		const entries = [
			{ type: "custom", id: "b1", customType: "re.binary", data: { path: "/bin/a" } },
			{ type: "custom", id: "a1", customType: "re.analysis", data: { pass: "preludes" } },
			{ type: "custom", id: "a2", customType: "re.analysis", data: { pass: "golang" } },
			{ type: "custom", id: "a3", customType: "re.analysis", data: { pass: "preludes" } }, // dup
			{ type: "custom", id: "b2", customType: "re.binary", data: { path: "/bin/b" } },
			{ type: "custom", id: "a4", customType: "re.analysis", data: { pass: "objc" } },
		] as unknown as Entry[];
		expect(recordedAnalysisPasses(entries, "/bin/a")).toEqual(["preludes", "golang"]);
		expect(recordedAnalysisPasses(entries, "/bin/b")).toEqual(["objc"]);
		expect(recordedAnalysisPasses(entries, "/bin/none")).toEqual([]);
	});

	test("recordedSignatures scopes applied files to the binary open when each was recorded", () => {
		const entries = [
			{ type: "custom", id: "b1", customType: "re.binary", data: { path: "/bin/a" } },
			{ type: "custom", id: "s1", customType: "re.signature", data: { path: "/sigs/one.sig" } },
			{ type: "custom", id: "b2", customType: "re.binary", data: { path: "/bin/b" } },
			{ type: "custom", id: "s2", customType: "re.signature", data: { path: "/sigs/two.sig" } },
			{ type: "custom", id: "s3", customType: "re.signature", data: { path: "/sigs/three.sig" } },
		] as unknown as Entry[];
		expect(recordedSignatures(entries, "/bin/a")).toEqual(["/sigs/one.sig"]);
		expect(recordedSignatures(entries, "/bin/b")).toEqual(["/sigs/two.sig", "/sigs/three.sig"]);
		expect(recordedSignatures(entries, "/bin/none")).toEqual([]);
	});
});

describe("liveAnnotations", () => {
	function custom(id: string, customType: string, data: unknown): SessionEntry {
		return { type: "custom", id, customType, data } as unknown as SessionEntry;
	}
	const ann = (ea: string, newValue: string) => ({ kind: "rename_function", ea, oldValue: "old", newValue });

	test("attributes each annotation to the binary opened before it", () => {
		const entries = [
			custom("b1", "re.binary", { path: "/bin/a" }),
			custom("a1", "re.annotation", ann("0x1", "fa")),
			custom("b2", "re.binary", { path: "/bin/b" }),
			custom("a2", "re.annotation", ann("0x2", "fb")),
			custom("b3", "re.binary", { path: "/bin/a" }),
			custom("a3", "re.annotation", ann("0x3", "fa2")),
		];
		expect(liveAnnotations(entries, "/bin/a").map((a) => a.entryId)).toEqual(["a1", "a3"]);
		expect(liveAnnotations(entries, "/bin/b").map((a) => a.entryId)).toEqual(["a2"]);
	});

	test("drops annotations an re.undo marker reversed", () => {
		const entries = [
			custom("b1", "re.binary", { path: "/bin/a" }),
			custom("a1", "re.annotation", ann("0x1", "one")),
			custom("a2", "re.annotation", ann("0x2", "two")),
			custom("u1", "re.undo", { undidEntryId: "a2" }),
		];
		const live = liveAnnotations(entries, "/bin/a");
		expect(live.map((a) => a.entryId)).toEqual(["a1"]);
		expect(annotationFingerprint(live)).toBe("a1");
	});

	test("ignores annotations recorded before any binary was opened", () => {
		expect(liveAnnotations([custom("a1", "re.annotation", ann("0x1", "x"))], "/bin/a")).toEqual([]);
	});
});

describe("baseRizinFlags", () => {
	const original = process.env.OMPRE_RIZIN_LOAD_USER_CONFIG;
	const restore = () => {
		if (original === undefined) delete process.env.OMPRE_RIZIN_LOAD_USER_CONFIG;
		else process.env.OMPRE_RIZIN_LOAD_USER_CONFIG = original;
	};

	test("is the NUL-framed pipe protocol with colors/utf8 off and user config skipped", () => {
		delete process.env.OMPRE_RIZIN_LOAD_USER_CONFIG;
		expect(baseRizinFlags()).toEqual(["-q0", "-e", "scr.color=0", "-e", "scr.utf8=false", "-N"]);
		restore();
	});

	test("OMPRE_RIZIN_LOAD_USER_CONFIG drops -N so the user's rizinrc loads", () => {
		process.env.OMPRE_RIZIN_LOAD_USER_CONFIG = "1";
		expect(baseRizinFlags()).not.toContain("-N");
		expect(baseRizinFlags()[0]).toBe("-q0");
		restore();
	});
});

describe("isExecutable", () => {
	test("a Windows sibling tool resolved without its extension still counts as executable", async () => {
		// regressions: availableRzCliTools silently dropped every rz-* tool (and
		// assertRizinAvailable false-negatived) when OMPRE_RIZIN_PATH pointed at
		// "…/bin/rizin" — the sibling is rz-hash.exe, which access() cannot see.
		if (process.platform !== "win32") return;
		expect(await isExecutable("C:/Windows/System32/where.exe")).toBe(true);
		expect(await isExecutable("C:/Windows/System32/where")).toBe(true); // extensionless form
		expect(await isExecutable("C:/Windows/System32/no-such-tool-here")).toBe(false);
	});
});

describe("parseRizinVersionArch", () => {
	test("parses the -v arch suffix and common legacy spellings", () => {
		expect(parseRizinVersionArch("rizin 0.9.1 @ windows-x86-64")).toBe(64);
		expect(parseRizinVersionArch("rizin 0.9.1 @ windows-x86-32")).toBe(32);
		expect(parseRizinVersionArch("rizin 0.9.1 @ linux-x86-64")).toBe(64);
		expect(parseRizinVersionArch("rizin 0.9.1 @ macos-arm64")).toBe(64);
		expect(parseRizinVersionArch("rizin 0.9.1 @ linux-x86")).toBe(32);
		expect(parseRizinVersionArch("rizin 0.9.1 @ linux-x86_64")).toBe(64);
		expect(parseRizinVersionArch("rizin 0.9.1 @ somewhere-else")).toBeUndefined();
	});
});

describe("readBinaryBits", () => {
	let dir: string;
	const write = (name: string, bytes: number[]): string => {
		const p = `${dir}/${name}`;
		writeFileSync(p, Buffer.from(bytes));
		return p;
	};
	const pe = (machine: number): number[] => {
		const b = Array.from({ length: 0x48 }, () => 0);
		b[0] = 0x4d; b[1] = 0x5a; // MZ
		b[0x3c] = 0x40; // e_lfanew = 0x40
		b[0x40] = 0x50; b[0x41] = 0x45; // PE\0\0
		b[0x44] = machine & 0xff; b[0x45] = machine >> 8;
		return b;
	};
	const elf = (cls: number): number[] => [0x7f, 0x45, 0x4c, 0x46, cls, 0, 0, 0];

	beforeAll(() => { dir = mkdtempSync(`${tmpdir()}/omp-re-bits-`); });
	afterAll(() => rmSync(dir, { recursive: true, force: true }));

	test("classifies PE, ELF, and Mach-O headers", () => {
		expect(readBinaryBits(write("pe64.bin", pe(0x8664)))).toBe(64);
		expect(readBinaryBits(write("peArm64.bin", pe(0xaa64)))).toBe(64);
		expect(readBinaryBits(write("pe32.bin", pe(0x014c)))).toBe(32);
		expect(readBinaryBits(write("peArm.bin", pe(0x01c0)))).toBe(32);
		expect(readBinaryBits(write("peBad.bin", pe(0xffff)))).toBeUndefined();
		expect(readBinaryBits(write("elf64.bin", elf(2)))).toBe(64);
		expect(readBinaryBits(write("elf32.bin", elf(1)))).toBe(32);
		expect(readBinaryBits(write("macho64.bin", [0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]))).toBe(64);
		expect(readBinaryBits(write("macho32.bin", [0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]))).toBe(32);
		expect(readBinaryBits(write("junk.bin", [1, 2, 3, 4]))).toBeUndefined();
		expect(readBinaryBits(`${dir}/does-not-exist.bin`)).toBeUndefined();
	});
});

describe("resolveRizinPath bits-aware precedence", () => {
	const saved: Record<string, string | undefined> = {};
	const KEYS = ["OMPRE_RIZIN_PATH", "OMPRE_RIZIN_PATH_64", "OMPRE_RIZIN_PATH_32"];
	afterEach(() => {
		for (const k of KEYS) {
			if (saved[k] === undefined) delete process.env[k];
			else process.env[k] = saved[k];
		}
	});
	const setEnv = (vars: Record<string, string | undefined>) => {
		for (const [k, v] of Object.entries(vars)) {
			saved[k] = process.env[k];
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
	};

	test("per-bits override wins for matching targets, general path otherwise", () => {
		setEnv({ OMPRE_RIZIN_PATH: "C:/base/rizin.exe", OMPRE_RIZIN_PATH_64: "C:/rz64/rizin.exe", OMPRE_RIZIN_PATH_32: undefined });
		expect(resolveRizinPath()).toBe("C:/base/rizin.exe");
		// A 64-bit PE picks the 64 build; a 32-bit PE with only the 64 override set falls back.
		const pe = (machine: number) => {
			const b = Array.from({ length: 0x48 }, () => 0);
			b[0] = 0x4d; b[1] = 0x5a; b[0x3c] = 0x40; b[0x40] = 0x50; b[0x41] = 0x45;
			b[0x44] = machine & 0xff; b[0x45] = machine >> 8;
			return Buffer.from(b);
		};
		const dir = mkdtempSync(`${tmpdir()}/omp-re-rz-`);
		const p64 = `${dir}/t64.exe`; writeFileSync(p64, pe(0x8664));
		const p32 = `${dir}/t32.exe`; writeFileSync(p32, pe(0x014c));
		expect(resolveRizinPath(p64)).toBe("C:/rz64/rizin.exe");
		expect(resolveRizinPath(p32)).toBe("C:/base/rizin.exe");
		setEnv({ OMPRE_RIZIN_PATH_32: "C:/rz32/rizin.exe" });
		expect(resolveRizinPath(p32)).toBe("C:/rz32/rizin.exe");
		rmSync(dir, { recursive: true, force: true });
	});
});
