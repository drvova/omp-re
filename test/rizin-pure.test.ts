import { describe, expect, test } from "bun:test";
import type { SessionEntry } from "@oh-my-pi/pi-coding-agent";
import { annotationCommands, annotationFingerprint, liveAnnotations } from "../extensions/re/annotations.ts";
import { eaFromOffset, normalizeAddr, rzQuote, validateAddr, validateIdent, validateText, validateTypeLike } from "../extensions/re/rizin.ts";

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
