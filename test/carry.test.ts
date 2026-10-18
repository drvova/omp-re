/**
 * `/re carry`: replay a report's verification manifest against another build.
 *
 * The parsing, legacy-line splitting, line diff, address masking, sequence
 * similarity, and claim roll-up need no rizin and always run. The live carry
 * compiles two builds of the sample fixture — v2 changes `checksum`'s multiplier
 * (drift), renames `fib` (relocated by fingerprint, or broken without one), and
 * thereby shifts every later function (holds apart from addresses; a numeric
 * anchor that relocates) — records evidence on v1 exactly as `rizin_command` and
 * the report manifest do, then carries the manifest onto v2. Gated on rizin plus
 * a C compiler.
 */
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import {
  fingerprintAnchor,
  sequenceSimilarity,
} from "../extensions/re/anchor.ts";
import {
  carryManifest,
  compactDiff,
  entryRequest,
  lineDiff,
  parseManifest,
  rollUpClaims,
} from "../extensions/re/carry.ts";
import type {
  CarryEvidenceRow,
  CarryManifest,
  ManifestEntry,
} from "../extensions/re/carry.ts";
import {
  canonicalExcerpt,
  canonicalHash,
  maskAddresses,
  shiftHash,
} from "../extensions/re/format.ts";
import { writeReport } from "../extensions/re/report.ts";
import { RzSession, resolveRizinPath } from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { sha256File } from "../extensions/re/verify.ts";
import { makeHarness, rizinAvailable, rmDirSafe } from "./helpers.ts";

const CC = Bun.which("cc") ?? Bun.which("gcc") ?? Bun.which("clang");
const canCarryLive =
  rizinAvailable && CC !== null && process.platform !== "win32";
if (!canCarryLive) {
  console.log(
    "omp-re: skipping carry (live) tests — needs rizin and a C compiler"
  );
}

const entry = (over: Partial<ManifestEntry>): ManifestEntry => ({
  claims: [],
  evidenceId: "ev",
  tool: "rizin_command",
  ...over,
});

beforeEach(() => {
  process.exitCode = 0;
});
afterEach(() => {
  process.exitCode = 0;
});

describe("parseManifest (no rizin needed)", () => {
  test("rejects non-JSON and non-manifests with a clear error", () => {
    expect(() => parseManifest("{nope")).toThrow("not valid JSON");
    expect(() => parseManifest(JSON.stringify({ claims: [] }))).toThrow(
      "not a verification manifest"
    );
  });

  test("tolerates missing optional fields and drops malformed entries", () => {
    const m = parseManifest(
      JSON.stringify({
        binarySha256: "a".repeat(64),
        entries: [
          { claims: ["c"], evidenceId: "e1", tool: "rizin_command" },
          { tool: "x" },
          null,
        ],
      })
    );
    expect(m.binarySha256).toBe("a".repeat(64));
    expect(m.entries).toHaveLength(1);
    expect(m.entries[0]).toMatchObject({
      anchor: null,
      args: null,
      claims: ["c"],
      evidenceId: "e1",
      reproHash: null,
    });
  });

  test("keeps a well-formed anchor fingerprint and drops a malformed one", () => {
    const good = {
      anchor: "sym.f",
      delta: 0,
      function: "sym.f",
      mnemonics: ["push", "ret"],
      nbbs: 1,
      offset: "0x10",
      size: 8,
    };
    const m = parseManifest(
      JSON.stringify({
        entries: [
          { anchor: good, claims: [], evidenceId: "e1" },
          { anchor: { ...good, delta: -4 }, claims: [], evidenceId: "e2" },
        ],
      })
    );
    expect(m.entries[0]?.anchor).toEqual(good);
    expect(m.entries[1]?.anchor).toBeNull();
  });
});

describe("entryRequest (no rizin needed)", () => {
  test("prefers structured args", () => {
    expect(
      entryRequest(
        entry({
          args: { addr: "sym.main", command: "pdf" },
          commands: ["ignored"],
        })
      )
    ).toEqual({ addr: "sym.main", command: "pdf" });
  });
  test("splits a legacy recorded line on its trailing ` @ addr`", () => {
    expect(entryRequest(entry({ commands: ["pdf @ sym.main"] }))).toEqual({
      addr: "sym.main",
      command: "pdf",
    });
    expect(entryRequest(entry({ command: "iHj" }))).toEqual({ command: "iHj" });
  });
  test("keeps `@!<blocksize>` as part of the command, not a seek", () => {
    expect(entryRequest(entry({ commands: ["ph sha256 @!32"] }))).toEqual({
      command: "ph sha256 @!32",
    });
  });
});

describe("maskAddresses / sequenceSimilarity (no rizin needed)", () => {
  test("masks positional addresses but keeps immediates", () => {
    const v1 = [
      "            ; CALL XREF from main @ 0x1324",
      "|           0x00001262      jmp   0x1282",
      "|           0x000012a4      and   eax, 0x0f",
      "|           0x000012a9      call  fcn.000011fd",
      "|           0x00001300      lea   rdi, [rip + 0x2cfd]  ; 0x4004",
    ].join("\n");
    const v2 = [
      "            ; CALL XREF from main @ 0x1326",
      "|           0x00001264      jmp   0x1284",
      "|           0x000012a6      and   eax, 0x0f",
      "|           0x000012ab      call  fcn.000011ff",
      "|           0x00001302      lea   rdi, [rip + 0x2cfb]  ; 0x4004",
    ].join("\n");
    expect(maskAddresses(v1)).toBe(maskAddresses(v2));
    expect(maskAddresses(v1)).toContain("and   eax, 0x0f");
    // a changed constant is not an address: it still differs
    expect(maskAddresses(v1.replace("0x0f", "0x1f"))).not.toBe(
      maskAddresses(v2)
    );
  });
  test("sequenceSimilarity is 1 for identical, lower as sequences diverge", () => {
    expect(
      sequenceSimilarity(["push", "mov", "ret"], ["push", "mov", "ret"])
    ).toBe(1);
    expect(
      sequenceSimilarity(
        ["push", "mov", "add", "ret"],
        ["push", "mov", "sub", "ret"]
      )
    ).toBe(0.75);
    expect(sequenceSimilarity(["a"], ["b"])).toBe(0);
  });
});

describe("lineDiff (no rizin needed)", () => {
  test("marks removed and added lines around the common ones", () => {
    expect(lineDiff("a\nb\nc", "a\nB\nc")).toEqual([
      "  a",
      "- b",
      "+ B",
      "  c",
    ]);
    expect(lineDiff("", "x")).toEqual(["+ x"]);
    expect(lineDiff("x", "")).toEqual(["- x"]);
  });
  test("compactDiff keeps changes with their context and elides the rest", () => {
    const diff = [
      "  a",
      "  b",
      "  c",
      "- d",
      "+ D",
      "  e",
      "  f",
      "  g",
      "  h",
    ];
    expect(compactDiff(diff, 1)).toEqual([
      "  …",
      "  c",
      "- d",
      "+ D",
      "  e",
      "  …",
    ]);
  });
  test("with an address mask, a line that only moved is unchanged (shown in its new form)", () => {
    expect(
      lineDiff(
        "0x10 jmp 0x20\n0x12 add",
        "0x14 jmp 0x24\n0x16 sub",
        maskAddresses
      )
    ).toEqual(["  0x14 jmp 0x24", "- 0x12 add", "+ 0x16 sub"]);
  });
});

describe("rollUpClaims (no rizin needed)", () => {
  test("a claim takes its worst checked evidence status; all-unchecked stays unchecked", () => {
    const manifest: CarryManifest = {
      binarySha256: null,
      entries: [
        entry({ claims: ["A", "B"], evidenceId: "e1" }),
        entry({ claims: ["A"], evidenceId: "e2" }),
        entry({ claims: ["C"], evidenceId: "e3" }),
      ],
      findings: [],
    };
    const rows: CarryEvidenceRow[] = [
      { detail: "", evidenceId: "e1", status: "holds", tool: "rizin_command" },
      { detail: "", evidenceId: "e2", status: "broken", tool: "rizin_command" },
      {
        detail: "",
        evidenceId: "e3",
        status: "unchecked",
        tool: "get_function",
      },
    ];
    const claims = rollUpClaims(manifest, rows);
    expect(claims.map((c) => [c.text, c.status])).toEqual([
      ["A", "broken"],
      ["B", "holds"],
      ["C", "unchecked"],
    ]);
  });
});

describe.skipIf(!canCarryLive)(
  "carryManifest against a rebuilt binary (real rizin)",
  () => {
    let dir: string;
    let v1: string;
    let v2: string;
    let manifestPath: string;
    let originalLog: typeof console.log;
    let originalError: typeof console.error;

    beforeAll(async () => {
      dir = await mkdtemp(nodePath.join(tmpdir(), "omp-re-carry-"));
      const src = await readFile(
        nodePath.join(import.meta.dir, "fixtures", "sample.c"),
        "utf-8"
      );
      const v2src = src
        .replace("h * 33u", "h * 31u")
        .replaceAll(/\bfib\b/gu, "fibonacci");
      await writeFile(nodePath.join(dir, "v1.c"), src);
      await writeFile(nodePath.join(dir, "v2.c"), v2src);
      v1 = nodePath.join(dir, "v1");
      v2 = nodePath.join(dir, "v2");
      for (const [out, file] of [
        [v1, "v1.c"],
        [v2, "v2.c"],
      ] as const) {
        const proc = Bun.spawn(
          [CC!, "-O0", "-o", out, nodePath.join(dir, file)],
          {
            stderr: "pipe",
            stdout: "pipe",
          }
        );
        if ((await proc.exited) !== 0) {
          throw new Error(
            `carry test: compiling ${file} failed: ${await new Response(proc.stderr).text()}`
          );
        }
      }

      // Record evidence on v1 exactly the way rizin_command does (reproHash over raw output, path-redacted).
      const v1Sha = await sha256File(v1);
      const requests = [
        {
          claim: "The binary targets x86.",
          command: "e asm.arch",
          id: "ev-arch",
        },
        {
          addr: "sym.clamp",
          claim: "clamp bounds its input to [lo, hi].",
          command: "pdf",
          id: "ev-clamp",
        },
        {
          addr: "sym.checksum",
          claim: "checksum is a djb2 hash (h * 33 + c).",
          command: "pdf",
          id: "ev-checksum",
        },
        {
          addr: "sym.fib",
          claim: "fib computes Fibonacci numbers iteratively.",
          command: "pdf",
          id: "ev-fib",
        },
        {
          addr: "sym.fib",
          claim: "fib is called once per transform.",
          command: "pdf",
          id: "ev-fib-nofp",
          noFingerprint: true,
        },
        {
          addr: "sym.square",
          claim: "square multiplies its argument by itself.",
          command: "pdf",
          id: "ev-square",
        },
        {
          addr: "",
          claim: "transform combines fib, mix and square.",
          command: "pdf",
          id: "ev-transform",
        },
      ];
      const rz = await RzSession.spawn(resolveRizinPath(v1), v1);
      const entries = [];
      try {
        // The numeric anchor: transform's v1 start address, which moves in v2.
        const transform = (
          JSON.parse(await rz.cmd("afij @ sym.transform")) as {
            offset: number;
          }[]
        )[0]!.offset;
        requests.find((r) => r.id === "ev-transform")!.addr =
          `0x${transform.toString(16)}`;
        for (const r of requests) {
          const line = r.addr ? `${r.command} @ ${r.addr}` : r.command;
          const { output } = await rz.cmdWithStderr(line);
          entries.push({
            anchor:
              r.addr && !("noFingerprint" in r)
                ? ((await fingerprintAnchor(rz, r.addr)) ?? null)
                : null,
            args: r.addr
              ? { addr: r.addr, command: r.command }
              : { command: r.command },
            binarySha256: v1Sha,
            canonicalExcerpt: canonicalExcerpt(output, v1),
            claims: [r.claim],
            command: line,
            commands: [line],
            evidenceId: r.id,
            reproHash: canonicalHash(output, v1),
            shiftHash: shiftHash(output, v1),
            status: "reproducible",
            tool: "rizin_command",
          });
        }
      } finally {
        rz.close();
      }
      entries.push({
        args: null,
        binarySha256: v1Sha,
        canonicalExcerpt: null,
        claims: ["main calls transform."],
        command: "afij @ sym.main",
        commands: ["afij @ sym.main"],
        evidenceId: "ev-prov",
        reproHash: null,
        status: "provenance-only",
        tool: "get_function",
      } as never);
      manifestPath = nodePath.join(dir, "report.md.manifest.json");
      await writeFile(
        manifestPath,
        JSON.stringify({ binarySha256: v1Sha, entries }, null, 2)
      );
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
      const byId = new Map(
        result.evidence.map((r) => [r.evidenceId, r.status])
      );
      for (const id of [
        "ev-arch",
        "ev-clamp",
        "ev-checksum",
        "ev-fib",
        "ev-fib-nofp",
        "ev-square",
        "ev-transform",
      ]) {
        expect([id, byId.get(id)]).toEqual([id, "holds"]);
      }
      expect(byId.get("ev-prov")).toBe("unchecked");
      expect(process.exitCode).not.toBe(1);
      shutdownState("carry-same");
    }, 60_000);

    test("on the rebuilt binary: unchanged code holds, shifted code holds, edited code drifts, renamed code relocates (or breaks without a fingerprint)", async () => {
      const h = makeHarness("carry-v2");
      getState(h.ctx).binaryPath = v2;
      const out = nodePath.join(dir, "carry.md");
      const result = await carryManifest(h.ctx, manifestPath, { out });
      const row = (id: string) =>
        result.evidence.find((r) => r.evidenceId === id)!;

      expect(row("ev-arch").status).toBe("holds");
      expect(row("ev-clamp").status).toBe("holds");
      expect(row("ev-checksum").status).toBe("drifted");
      expect(
        row("ev-checksum").diff?.some(
          (l) => l.startsWith("- ") || l.startsWith("+ ")
        )
      ).toBe(true);
      // renamed: found again by fingerprint, same code
      expect(row("ev-fib").status).toBe("relocated");
      expect(row("ev-fib").relocation?.to).toContain("sym.fibonacci");
      expect(row("ev-fib").relocation?.similarity).toBe(1);
      // the same anchor without a fingerprint can only be broken
      expect(row("ev-fib-nofp").status).toBe("broken");
      expect(row("ev-fib-nofp").detail).toContain("sym.fib");
      // square's code is unchanged; only its caller's address moved
      expect(row("ev-square").status).toBe("holds");
      expect(row("ev-square").detail).toContain("shifted addresses");
      // numeric anchor: transform moved, relocated by fingerprint; its body now calls sym.fibonacci, so it drifted
      expect(row("ev-transform").relocation?.to).toContain("sym.transform");
      expect(row("ev-transform").status).toBe("drifted");
      expect(
        row("ev-transform").diff?.some((l) => l.includes("fibonacci"))
      ).toBe(true);
      expect(row("ev-prov").status).toBe("unchecked");

      const claim = (text: string) =>
        result.claims.find((c) => c.text.startsWith(text))?.status;
      expect(claim("checksum")).toBe("drifted");
      expect(claim("fib computes")).toBe("relocated");
      expect(claim("fib is called")).toBe("broken");
      expect(claim("square")).toBe("holds");
      expect(claim("main calls")).toBe("unchecked");

      // A broken claim fails a headless run — the report is a regression test for the next build.
      expect(process.exitCode).toBe(1);

      const markdown = await readFile(out, "utf-8");
      expect(markdown).toContain("# Carry Report");
      expect(markdown).toContain("```diff");
      const sidecar = JSON.parse(await readFile(`${out}.json`, "utf-8")) as {
        claims: unknown[];
      };
      expect(sidecar.claims).toHaveLength(8);
      shutdownState("carry-v2");
    }, 60_000);

    test("/re report fingerprints an address-pinned rizin_command's anchor into the manifest while its binary is open", async () => {
      const h = makeHarness("carry-report-anchor");
      const state = getState(h.ctx);
      const sha = await sha256File(v1);
      state.binaryPath = v1;
      state.binarySha256 = sha;
      h.entries.push(
        {
          customType: "re.binary",
          data: { path: v1, sha256: sha },
          id: "b1",
          type: "custom",
        },
        {
          customType: "re.evidence",
          data: {
            id: "ev-anchored",
            tool: "rizin_command",
            args: { addr: "sym.fib", command: "pdf" },
            commands: ["pdf @ sym.fib"],
            reproHash: "b".repeat(64),
            binarySha256: sha,
            // an IOC in the summary makes this a grounded claim that cites ev-anchored
            summary: "found string: http://185.220.101.99/beacon",
          },
          id: "e1",
          type: "custom",
        }
      );
      const out = nodePath.join(dir, "anchored.md");
      await writeReport(h.ctx, out, { audit: "off" });
      const manifest = JSON.parse(
        await readFile(`${out}.manifest.json`, "utf-8")
      ) as {
        entries: {
          evidenceId: string;
          anchor: {
            function: string;
            delta: number;
            mnemonics: string[];
          } | null;
        }[];
      };
      const anchor = manifest.entries.find(
        (e) => e.evidenceId === "ev-anchored"
      )?.anchor;
      expect(anchor?.function).toBe("sym.fib");
      expect(anchor?.delta).toBe(0);
      expect(anchor?.mnemonics.length).toBeGreaterThan(5);
      shutdownState("carry-report-anchor");
    }, 60_000);

    test("drift alone passes by default but fails under --strict", async () => {
      const driftOnly = JSON.parse(await readFile(manifestPath, "utf-8")) as {
        entries: { evidenceId: string }[];
      };
      driftOnly.entries = driftOnly.entries.filter(
        (e) => e.evidenceId === "ev-arch" || e.evidenceId === "ev-checksum"
      );
      const path = nodePath.join(dir, "drift.manifest.json");
      await writeFile(path, JSON.stringify(driftOnly));

      const h = makeHarness("carry-strict");
      getState(h.ctx).binaryPath = v2;
      await carryManifest(h.ctx, path);
      expect(process.exitCode).not.toBe(1);
      await carryManifest(h.ctx, path, { strict: true });
      expect(process.exitCode).toBe(1);
      shutdownState("carry-strict");
    }, 60_000);
  }
);
