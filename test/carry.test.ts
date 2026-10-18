/**
 * `/re carry`: replay a report's verification manifest against another build.
 *
 * The parsing, legacy-line splitting, line diff, and claim roll-up need no rizin
 * and always run. The live carry compiles two builds of the sample fixture — v2
 * changes `checksum`'s multiplier (drift) and renames `fib` (a broken anchor) —
 * records evidence on v1 exactly as `rizin_command` does, then carries the
 * manifest onto v2. Gated on rizin plus a C compiler.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type CarryEvidenceRow, type CarryManifest, carryManifest, entryRequest, lineDiff, type ManifestEntry, parseManifest, rollUpClaims } from "../extensions/re/carry.ts";
import { canonicalExcerpt, canonicalHash } from "../extensions/re/format.ts";
import { RzSession, resolveRizinPath } from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { sha256File } from "../extensions/re/verify.ts";
import { makeHarness, rizinAvailable, rmDirSafe } from "./helpers.ts";

const CC = Bun.which("cc") ?? Bun.which("gcc") ?? Bun.which("clang");
const canCarryLive = rizinAvailable && CC !== null && process.platform !== "win32";
if (!canCarryLive) console.log("omp-re: skipping carry (live) tests — needs rizin and a C compiler");

const entry = (over: Partial<ManifestEntry>): ManifestEntry => ({ evidenceId: "ev", tool: "rizin_command", claims: [], ...over });

beforeEach(() => {
	process.exitCode = 0;
});
afterEach(() => {
	process.exitCode = 0;
});

describe("parseManifest (no rizin needed)", () => {
	test("rejects non-JSON and non-manifests with a clear error", () => {
		expect(() => parseManifest("{nope")).toThrow("not valid JSON");
		expect(() => parseManifest(JSON.stringify({ claims: [] }))).toThrow("not a verification manifest");
	});

	test("tolerates missing optional fields and drops malformed entries", () => {
		const m = parseManifest(JSON.stringify({ binarySha256: "a".repeat(64), entries: [{ evidenceId: "e1", tool: "rizin_command", claims: ["c"] }, { tool: "x" }, null] }));
		expect(m.binarySha256).toBe("a".repeat(64));
		expect(m.entries).toHaveLength(1);
		expect(m.entries[0]).toMatchObject({ evidenceId: "e1", args: null, reproHash: null, claims: ["c"] });
	});
});

describe("entryRequest (no rizin needed)", () => {
	test("prefers structured args", () => {
		expect(entryRequest(entry({ args: { command: "pdf", addr: "sym.main" }, commands: ["ignored"] }))).toEqual({ command: "pdf", addr: "sym.main" });
	});
	test("splits a legacy recorded line on its trailing ` @ addr`", () => {
		expect(entryRequest(entry({ commands: ["pdf @ sym.main"] }))).toEqual({ command: "pdf", addr: "sym.main" });
		expect(entryRequest(entry({ command: "iHj" }))).toEqual({ command: "iHj" });
	});
	test("keeps `@!<blocksize>` as part of the command, not a seek", () => {
		expect(entryRequest(entry({ commands: ["ph sha256 @!32"] }))).toEqual({ command: "ph sha256 @!32" });
	});
});

describe("lineDiff (no rizin needed)", () => {
	test("marks removed and added lines around the common ones", () => {
		expect(lineDiff("a\nb\nc", "a\nB\nc")).toEqual(["  a", "- b", "+ B", "  c"]);
		expect(lineDiff("", "x")).toEqual(["+ x"]);
		expect(lineDiff("x", "")).toEqual(["- x"]);
	});
});

describe("rollUpClaims (no rizin needed)", () => {
	test("a claim takes its worst checked evidence status; all-unchecked stays unchecked", () => {
		const manifest: CarryManifest = {
			binarySha256: null,
			entries: [entry({ evidenceId: "e1", claims: ["A", "B"] }), entry({ evidenceId: "e2", claims: ["A"] }), entry({ evidenceId: "e3", claims: ["C"] })],
		};
		const rows: CarryEvidenceRow[] = [
			{ evidenceId: "e1", tool: "rizin_command", status: "holds", detail: "" },
			{ evidenceId: "e2", tool: "rizin_command", status: "broken", detail: "" },
			{ evidenceId: "e3", tool: "get_function", status: "unchecked", detail: "" },
		];
		const claims = rollUpClaims(manifest, rows);
		expect(claims.map((c) => [c.text, c.status])).toEqual([
			["A", "broken"],
			["B", "holds"],
			["C", "unchecked"],
		]);
	});
});

describe.skipIf(!canCarryLive)("carryManifest against a rebuilt binary (real rizin)", () => {
	let dir: string;
	let v1: string;
	let v2: string;
	let manifestPath: string;
	let originalLog: typeof console.log;
	let originalError: typeof console.error;

	beforeAll(async () => {
		dir = await mkdtemp(join(tmpdir(), "omp-re-carry-"));
		const src = await readFile(join(import.meta.dir, "fixtures", "sample.c"), "utf8");
		const v2src = src.replace("h * 33u", "h * 31u").replace(/\bfib\b/g, "fibonacci");
		await writeFile(join(dir, "v1.c"), src);
		await writeFile(join(dir, "v2.c"), v2src);
		v1 = join(dir, "v1");
		v2 = join(dir, "v2");
		for (const [out, file] of [
			[v1, "v1.c"],
			[v2, "v2.c"],
		] as const) {
			const proc = Bun.spawn([CC!, "-O0", "-o", out, join(dir, file)], { stdout: "pipe", stderr: "pipe" });
			if ((await proc.exited) !== 0) throw new Error(`carry test: compiling ${file} failed: ${await new Response(proc.stderr).text()}`);
		}

		// Record evidence on v1 exactly the way rizin_command does (reproHash over raw output, path-redacted).
		const v1Sha = await sha256File(v1);
		const requests = [
			{ id: "ev-arch", command: "e asm.arch", claim: "The binary targets x86." },
			{ id: "ev-clamp", command: "pdf", addr: "sym.clamp", claim: "clamp bounds its input to [lo, hi]." },
			{ id: "ev-checksum", command: "pdf", addr: "sym.checksum", claim: "checksum is a djb2 hash (h * 33 + c)." },
			{ id: "ev-fib", command: "pdf", addr: "sym.fib", claim: "fib computes Fibonacci numbers iteratively." },
		];
		const rz = await RzSession.spawn(resolveRizinPath(v1), v1);
		const entries = [];
		try {
			for (const r of requests) {
				const line = r.addr ? `${r.command} @ ${r.addr}` : r.command;
				const { output } = await rz.cmdWithStderr(line);
				entries.push({
					evidenceId: r.id,
					tool: "rizin_command",
					args: r.addr ? { command: r.command, addr: r.addr } : { command: r.command },
					command: line,
					commands: [line],
					reproHash: canonicalHash(output, v1),
					canonicalExcerpt: canonicalExcerpt(output, v1),
					binarySha256: v1Sha,
					status: "reproducible",
					claims: [r.claim],
				});
			}
		} finally {
			rz.close();
		}
		entries.push({ evidenceId: "ev-prov", tool: "get_function", args: null, command: "afij @ sym.main", commands: ["afij @ sym.main"], reproHash: null, canonicalExcerpt: null, binarySha256: v1Sha, status: "provenance-only", claims: ["main calls transform."] } as never);
		manifestPath = join(dir, "report.md.manifest.json");
		await writeFile(manifestPath, JSON.stringify({ binarySha256: v1Sha, entries }, null, 2));
	}, 60_000);

	afterAll(() => rmDirSafe(dir));

	beforeEach(() => {
		originalLog = console.log;
		originalError = console.error;
		console.log = () => {};
		console.error = () => {};
	});
	afterEach(() => {
		console.log = originalLog;
		console.error = originalError;
	});

	test("on the same build every reproducible claim holds and nothing fails", async () => {
		const h = makeHarness("carry-same");
		getState(h.ctx).binaryPath = v1;
		const result = await carryManifest(h.ctx, manifestPath);
		const byId = new Map(result.evidence.map((r) => [r.evidenceId, r.status]));
		expect([byId.get("ev-arch"), byId.get("ev-clamp"), byId.get("ev-checksum"), byId.get("ev-fib")]).toEqual(["holds", "holds", "holds", "holds"]);
		expect(byId.get("ev-prov")).toBe("unchecked");
		expect(process.exitCode).not.toBe(1);
		shutdownState("carry-same");
	}, 60_000);

	test("on the rebuilt binary: unchanged code holds, the edited function drifts with a diff, the renamed one is broken", async () => {
		const h = makeHarness("carry-v2");
		getState(h.ctx).binaryPath = v2;
		const out = join(dir, "carry.md");
		const result = await carryManifest(h.ctx, manifestPath, { out });
		const row = (id: string) => result.evidence.find((r) => r.evidenceId === id)!;

		expect(row("ev-arch").status).toBe("holds");
		expect(row("ev-clamp").status).toBe("holds");
		expect(row("ev-checksum").status).toBe("drifted");
		expect(row("ev-checksum").diff?.some((l) => l.startsWith("- ") || l.startsWith("+ "))).toBe(true);
		expect(row("ev-fib").status).toBe("broken");
		expect(row("ev-fib").detail).toContain("sym.fib");
		expect(row("ev-prov").status).toBe("unchecked");

		const claim = (text: string) => result.claims.find((c) => c.text.startsWith(text))?.status;
		expect(claim("checksum")).toBe("drifted");
		expect(claim("fib")).toBe("broken");
		expect(claim("main calls")).toBe("unchecked");

		// A broken claim fails a headless run — the report is a regression test for the next build.
		expect(process.exitCode).toBe(1);

		const markdown = await readFile(out, "utf8");
		expect(markdown).toContain("# Carry Report");
		expect(markdown).toContain("```diff");
		const sidecar = JSON.parse(await readFile(`${out}.json`, "utf8")) as { claims: unknown[] };
		expect(sidecar.claims).toHaveLength(5);
		shutdownState("carry-v2");
	}, 60_000);

	test("drift alone passes by default but fails under --strict", async () => {
		const driftOnly = JSON.parse(await readFile(manifestPath, "utf8")) as { entries: { evidenceId: string }[] };
		driftOnly.entries = driftOnly.entries.filter((e) => e.evidenceId === "ev-arch" || e.evidenceId === "ev-checksum");
		const path = join(dir, "drift.manifest.json");
		await writeFile(path, JSON.stringify(driftOnly));

		const h = makeHarness("carry-strict");
		getState(h.ctx).binaryPath = v2;
		await carryManifest(h.ctx, path);
		expect(process.exitCode).not.toBe(1);
		await carryManifest(h.ctx, path, { strict: true });
		expect(process.exitCode).toBe(1);
		shutdownState("carry-strict");
	}, 60_000);
});
