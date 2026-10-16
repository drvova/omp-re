import { describe, expect, test } from "bun:test";
import { scopedSearch, searchCommand, searchGadgets } from "../extensions/re/tools-search.ts";
import { castMemory, defineTypeLines, listTypeRows } from "../extensions/re/tools-types.ts";
import { listSyscallRows, syscallLookupText } from "../extensions/re/tools-syscalls.ts";
import type { RzSession } from "../extensions/re/rizin.ts";

/** Stub session replaying canned replies; records every command for assertions. */
function stubRz(replies: Record<string, string>) {
	const ran: string[] = [];
	const cmd = (command: string) => {
		ran.push(command);
		return Promise.resolve(replies[command] ?? "");
	};
	const cmdj = <T,>(command: string) => {
		ran.push(command);
		const raw = (replies[command] ?? "").trim();
		return Promise.resolve(raw ? (JSON.parse(raw) as T) : null);
	};
	const cmdWithStderr = (command: string) => {
		ran.push(command);
		const reply = replies[command];
		return Promise.resolve(reply === undefined ? { output: "", stderr: "" } : { output: reply, stderr: "" });
	};
	return { rz: { cmd, cmdj, cmdWithStderr } as unknown as RzSession, ran };
}

describe("searchCommand", () => {
	test("maps /xj hit rows to ea/size/flag rows", async () => {
		const { rz } = stubRz({ "/xj 686173683a": JSON.stringify([{ address: 5368737792, size: 5, flag: "hit.bytes.0" }]) });
		const result = await searchCommand(rz, "/xj 686173683a", 'hits for "hash:"', {});
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("1 hits");
		expect(text).toContain("0x140007000");
		expect(text).toContain("hit.bytes.0");
		expect(result.useless).toBeUndefined();
	});

	test("marks empty hit lists useless", async () => {
		const { rz } = stubRz({ "/xj dead": "[]" });
		const result = await searchCommand(rz, "/xj dead", "hits", {});
		expect(result.useless).toBe(true);
	});

	test("paginates hit lists with a total in the header", async () => {
		const hits = Array.from({ length: 5 }, (_, i) => ({ address: 0x140000000 + i * 8, size: 4, flag: `hit${i}` }));
		const { rz } = stubRz({ "/xj 90": JSON.stringify(hits) });
		const result = await searchCommand(rz, "/xj 90", "hits", { offset: 2, limit: 2 });
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("2 of 5 hits (offset=2");
	});
});

describe("scopedSearch", () => {
	test("scopes a search to a function's bounds and restores the prior scope", async () => {
		const { rz, ran } = stubRz({
			"afij @ main": JSON.stringify([{ name: "main", minbound: 0x1000, maxbound: 0x1200 }]),
			"e search.in": "io.maps",
			"e search.from": "0",
			"e search.to": "0",
			"/xj 90": JSON.stringify([{ address: 0x1100, size: 1, flag: "hit" }]),
		});
		const result = await scopedSearch(rz, "/xj 90", "hits", { in_function: "main" });
		// scope set to the resolved [minbound, maxbound) range, then put back
		expect(ran).toContain("e search.in=range");
		expect(ran).toContain("e search.from=4096");
		expect(ran).toContain("e search.to=4608");
		expect(ran).toContain("e search.in=io.maps");
		expect(ran).toContain("e search.from=0");
		expect(ran).toContain("e search.to=0");
		// the search ran within the scope window and the label names the function
		expect(ran).toContain("/xj 90");
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("in main");
	});

	test("restores the scope even when the search throws", async () => {
		const ran: string[] = [];
		const cmd = (command: string) => {
			ran.push(command);
			if (command === "e search.in") return Promise.resolve("io.maps");
			return Promise.resolve("0");
		};
		const cmdj = (command: string) => {
			ran.push(command);
			if (command === "afij @ main") return Promise.resolve([{ name: "main", minbound: 0x1000, maxbound: 0x1200 }] as never);
			throw new Error("boom");
		};
		const rz = { cmd, cmdj } as unknown as RzSession;
		await expect(scopedSearch(rz, "/xj 90", "hits", { in_function: "main" })).rejects.toThrow("boom");
		expect(ran).toContain("e search.in=io.maps"); // restored in the finally
	});

	test("without in_function, runs the bare search and touches no scope config", async () => {
		const { rz, ran } = stubRz({ "/xj 90": "[]" });
		await scopedSearch(rz, "/xj 90", "hits", {});
		expect(ran).toEqual(["/xj 90"]);
	});

	test("a function that can't be resolved is reported, not silently unscoped", async () => {
		const { rz } = stubRz({ "afij @ nope": "[]" });
		await expect(scopedSearch(rz, "/xj 90", "hits", { in_function: "nope" })).rejects.toThrow("no function at");
	});
});

describe("listTypeRows", () => {
	test("filters struct names case-insensitively", async () => {
		const { rz } = stubRz({ tsj: JSON.stringify([{ name: "tagBITMAPINFO", members: {} }, { name: "config_entry", members: {} }]) });
		const result = await listTypeRows(rz, { kind: "struct", filter: "CONFIG" });
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("config_entry");
		expect(text).not.toContain("tagBITMAPINFO");
	});
});

describe("defineTypeLines", () => {
	test("sends one td per definition and reports silence", async () => {
		const { rz, ran } = stubRz({});
		const result = await defineTypeLines(rz, ["struct cfg { int v; };", "typedef struct cfg cfg_t;"]);
		expect(ran.filter((c) => c.startsWith("td "))).toEqual(["td struct cfg { int v; };", "td typedef struct cfg cfg_t;"]);
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("2 definition(s) accepted silently");
	});

	test("surfaces rizin stderr for rejected definitions", async () => {
		const { rz } = stubRz({ "td bogus;": "" });
		// The stub replies by exact command; emulate stderr via a rejected parse: use output channel only here.
		const result = await defineTypeLines({ cmd: () => Promise.resolve(""), cmdj: () => Promise.resolve(null), cmdWithStderr: () => Promise.resolve({ output: "", stderr: "ERROR: syntax error" }) } as unknown as RzSession, ["bogus;"]);
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("ERROR: syntax error");
	});
});

describe("castMemory", () => {
	test("resolves the address then casts with tp", async () => {
		const { rz, ran } = stubRz({ "%v sym.main": "0x1400014c9", "tp struct cfg @ 5368714441": "int v = 3" });
		const result = await castMemory(rz, "sym.main", "struct cfg");
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(ran.some((c) => c.startsWith("%v "))).toBe(true);
		expect(ran.some((c) => c === "tp struct cfg @ 5368714441")).toBe(true);
		expect(text).toContain("int v = 3");
	});
});

describe("listSyscallRows", () => {
	test("filters and paginates aslj rows", async () => {
		const rows = [{ name: "NtOpenProcess", swi: 46, num: 190 }, { name: "NtOpenTransaction", swi: 46, num: 202 }];
		const { rz } = stubRz({ aslj: JSON.stringify(rows) });
		const result = await listSyscallRows(rz, { filter: "ntopen", offset: 0, limit: 10 });
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("NtOpenProcess");
		expect(text).toContain("NtOpenTransaction");
	});
});

describe("syscallLookupText", () => {
	test("resolves by name via asn and by number via asr", async () => {
		const { rz, ran } = stubRz({ "asn NtOpenProcess": "NtOpenProcess = 0x2e.be (190)" });
		const result = await syscallLookupText(rz, { name: "NtOpenProcess" });
		expect(ran).toContain("asn NtOpenProcess");
		const text = result.content[0].type === "text" ? result.content[0].text : "";
		expect(text).toContain("190");

		const { rz: rz2, ran: ran2 } = stubRz({ "asr 190": "NtOpenProcess = 0x2e.be (190)" });
		await syscallLookupText(rz2, { number: 190 });
		expect(ran2).toContain("asr 190");
	});

	test("rejects supplying both name and number", async () => {
		const { rz } = stubRz({});
		await expect(syscallLookupText(rz, { name: "NtOpenProcess", number: 190 })).rejects.toThrow("exactly one");
	});
});

describe("search_asm", () => {
	test("assembles text and runs /aj", async () => {
		const { rz } = stubRz({ "/aj push rbp": JSON.stringify([{ address: 5368713524, size: 1, flag: "hit.asm_text.0" }]) });
		const result = await searchCommand(rz, "/aj push rbp", "asm hits", {});
		const t = result.content[0].type === "text" ? result.content[0].text : "";
		expect(t).toContain("hit.asm_text.0");
	});
});

describe("searchGadgets", () => {
	test("primes the gadget cache, then takes native /Rj JSON rows", async () => {
		const ran: string[] = [];
		const nativeJson = JSON.stringify([
			{ opcodes: [{ offset: 5368713216, size: 1, opcode: "ret", type: "ret" }], retaddr: 5368713216, size: 1 },
			{ opcodes: [{ offset: 5368713220, size: 2, opcode: "pop rdi; ret", type: "pop" }], retaddr: 5368713220, size: 2 },
		]);
		const rz = {
			cmd: (c: string) => {
				ran.push(c);
				return Promise.resolve("");
			},
			cmdj: (c: string) => {
				ran.push(c);
				return Promise.resolve(c === "/Rj" ? JSON.parse(nativeJson) : null);
			},
			cmdWithStderr: () => Promise.resolve({ output: "", stderr: "" }),
		} as unknown as RzSession;
		const result = await searchGadgets(rz, "rop", undefined, {});
		expect(ran).toEqual(["/R", "/Rj"]);
		const t = result.content[0].type === "text" ? result.content[0].text : "";
		expect(t).toContain("2 ROP gadgets");
		expect(t).toContain("0x140001000");
	});

	test("passes the filter to both native commands", async () => {
		const ran: string[] = [];
		const rz = {
			cmd: (c: string) => {
				ran.push(c);
				return Promise.resolve("");
			},
			cmdj: (c: string) => {
				ran.push(c);
				return Promise.resolve([]);
			},
			cmdWithStderr: () => Promise.resolve({ output: "", stderr: "" }),
		} as unknown as RzSession;
		await searchGadgets(rz, "rop", "pop rdi", {});
		expect(ran).toEqual(["/R pop rdi", "/Rj pop rdi"]);
	});
});
