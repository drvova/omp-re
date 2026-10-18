/**
 * First-class findings: `record_finding` / `retract_finding`, the report's
 * Findings section and manifest block, and `/re carry --inherit`.
 *
 * The gates (existence, binding, support audit with override), supersede and
 * retract, and the report wiring need no rizin and use an injected judge. The
 * live suite runs the whole loop on two builds of the sample fixture: record
 * findings on v1 from real `rizin_command` evidence, write the report, then carry
 * it onto v2 with --inherit — the finding about the renamed `fib` is re-proven
 * and follows the rename, the one about the unchanged `clamp` is re-proven, and
 * the one about the edited `checksum` lands on the agenda with its diff.
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
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ClaimAudit, ClaimJudge } from "../extensions/re/audit-claims.ts";
import { carryManifest } from "../extensions/re/carry.ts";
import { collectEvidence } from "../extensions/re/entries.ts";
import { recordEvidence } from "../extensions/re/evidence.ts";
import {
  collectFindings,
  registerFindingTools,
} from "../extensions/re/findings.ts";
import { writeReport } from "../extensions/re/report.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { runRizinCommand } from "../extensions/re/tools-rizin.ts";
import { sha256File } from "../extensions/re/verify.ts";
import { makeHarness, rizinAvailable, rmDirSafe, textOf } from "./helpers.ts";

const CC = Bun.which("cc") ?? Bun.which("gcc") ?? Bun.which("clang");
const canRunLive =
  rizinAvailable && CC !== null && process.platform !== "win32";
if (!canRunLive) {
  console.log(
    "omp-re: skipping findings (live) tests — needs rizin and a C compiler"
  );
}

const SHA_A = "a".repeat(64);
const judgeSaying =
  (verdict: ClaimAudit["verdict"], reason = "because"): ClaimJudge =>
  async (items) =>
    items.map((i) => ({ index: i.index, reason, verdict }));

let originalLog: typeof console.log;
let originalError: typeof console.error;
beforeEach(() => {
  process.exitCode = 0;
  originalLog = console.log;
  originalError = console.error;
  console.log = () => {};
  console.error = () => {};
});
afterEach(() => {
  console.log = originalLog;
  console.error = originalError;
  process.exitCode = 0;
});

/** A harness with the finding tools registered, the open binary bound to SHA_A, and one reproducible evidence record. */
const setup = (sessionId: string, judge: ClaimJudge | null) => {
  const h = makeHarness(sessionId);
  registerFindingTools(h.pi, { judge: () => judge });
  getState(h.ctx).binarySha256 = SHA_A;
  h.entries.push(
    {
      customType: "re.binary",
      data: { path: "/bin/sample", sha256: SHA_A },
      id: "b",
      type: "custom",
    },
    {
      customType: "re.evidence",
      data: {
        args: { addr: "sym.f", command: "pdf" },
        binarySha256: SHA_A,
        commands: ["pdf @ sym.f"],
        id: "11111111-aaaa-bbbb-cccc-000000000001",
        reproHash: "b".repeat(64),
        summary: "imul eax, eax, 0x21",
        tool: "rizin_command",
      },
      id: "e1",
      type: "custom",
    }
  );
  const run = (name: string, params: Record<string, unknown>) =>
    h.tool(name).execute("call", params, undefined, undefined, h.ctx);
  return { h, run };
};

describe("record_finding gates (no rizin needed)", () => {
  test("records a supported finding citing an evidence prefix, and reports it carryable", async () => {
    const { h, run } = setup("find-ok", judgeSaying("supported"));
    const result = await run("record_finding", {
      addr: "sym.f",
      claim: "f multiplies by 33.",
      confidence: "confirmed",
      evidence: ["11111111"],
    });
    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toContain("will carry to the next build");
    const [finding] = collectFindings(h.entries);
    expect(finding).toMatchObject({
      addr: "sym.f",
      audit: { verdict: "supported" },
      binarySha256: SHA_A,
      claim: "f multiplies by 33.",
      confidence: "confirmed",
    });
    expect(finding?.evidenceIds).toEqual([
      "11111111-aaaa-bbbb-cccc-000000000001",
    ]);
    shutdownState("find-ok");
  });

  test("refuses an unknown or too-short evidence id", async () => {
    const { h, run } = setup("find-missing", judgeSaying("supported"));
    await expect(
      run("record_finding", { claim: "x", evidence: ["deadbeef"] })
    ).rejects.toThrow("evidence not found");
    await expect(
      run("record_finding", { claim: "x", evidence: ["111"] })
    ).rejects.toThrow("too short");
    expect(collectFindings(h.entries)).toHaveLength(0);
    shutdownState("find-missing");
  });

  test("refuses evidence taken against a different binary", async () => {
    const { h, run } = setup("find-foreign", judgeSaying("supported"));
    getState(h.ctx).binarySha256 = "c".repeat(64);
    await expect(
      run("record_finding", { claim: "x", evidence: ["11111111"] })
    ).rejects.toThrow("different binary");
    shutdownState("find-foreign");
  });

  test("an overreaching claim is refused with the auditor's reason, and recorded only with a written override", async () => {
    const { h, run } = setup(
      "find-overreach",
      judgeSaying("overreach", "shows a multiply, not a hash")
    );
    const refused = await run("record_finding", {
      claim: "f is the djb2 hash of the C2 key.",
      evidence: ["11111111"],
    });
    expect(refused.isError).toBe(true);
    expect(textOf(refused)).toContain("shows a multiply, not a hash");
    expect(collectFindings(h.entries)).toHaveLength(0);

    await run("record_finding", {
      claim: "f is the djb2 hash of the C2 key.",
      evidence: ["11111111"],
      override_audit: "the constant 33 plus the loop is djb2",
    });
    expect(collectFindings(h.entries)[0]?.audit).toEqual({
      override: "the constant 33 plus the loop is djb2",
      reason: "shows a multiply, not a hash",
      verdict: "overreach",
    });
    shutdownState("find-overreach");
  });

  test("with no auditor available the finding is recorded as unaudited (fails open)", async () => {
    const { h, run } = setup("find-unaudited", null);
    await run("record_finding", {
      claim: "f multiplies by 33.",
      evidence: ["11111111"],
    });
    expect(collectFindings(h.entries)[0]?.audit?.verdict).toBe("unaudited");
    shutdownState("find-unaudited");
  });

  test("supersedes replaces a finding; retract_finding withdraws one", async () => {
    const { h, run } = setup("find-revise", judgeSaying("supported"));
    await run("record_finding", { claim: "first", evidence: ["11111111"] });
    const firstId = collectFindings(h.entries)[0]!.id;
    await run("record_finding", {
      claim: "second",
      evidence: ["11111111"],
      supersedes: firstId.slice(0, 8),
    });
    expect(collectFindings(h.entries).map((f) => f.claim)).toEqual(["second"]);
    await run("retract_finding", {
      id: collectFindings(h.entries)[0]!.id,
      reason: "wrong function",
    });
    expect(collectFindings(h.entries)).toHaveLength(0);
    shutdownState("find-revise");
  });
});

describe("findings in the report (no rizin needed)", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "omp-re-findings-report-"));
  });
  afterAll(async () => {
    await rm(dir, { force: true, recursive: true });
  });

  test("live findings form a gated Findings section with their provenance, and the manifest lists them", async () => {
    const { h, run } = setup("find-report", judgeSaying("supported"));
    await run("record_finding", {
      addr: "sym.f",
      claim: "f multiplies by 33.",
      confidence: "confirmed",
      evidence: ["11111111"],
    });
    const out = join(dir, "r.md");
    await writeReport(h.ctx, out, { audit: "off" });
    expect(process.exitCode).not.toBe(1);
    const md = await readFile(out, "utf-8");
    expect(md).toContain("## Findings");
    expect(md).toContain("- f multiplies by 33.");
    expect(md).toContain("confidence: confirmed");
    expect(md).toContain(
      "[rizin_command:11111111-aaaa-bbbb-cccc-000000000001]"
    );
    const manifest = JSON.parse(
      await readFile(`${out}.manifest.json`, "utf-8")
    ) as {
      findings: { claim: string; addr: string; confidence: string }[];
      entries: { claims: string[] }[];
    };
    expect(manifest.findings).toEqual([
      expect.objectContaining({
        addr: "sym.f",
        claim: "f multiplies by 33.",
        confidence: "confirmed",
      }),
    ]);
    expect(manifest.entries[0]?.claims).toContain("f multiplies by 33.");
    shutdownState("find-report");
  });
});

describe.skipIf(!canRunLive)(
  "record → report → carry --inherit across two builds (real rizin)",
  () => {
    let dir: string;
    let v1: string;
    let v2: string;

    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), "omp-re-inherit-"));
      const src = await readFile(
        join(import.meta.dir, "fixtures", "sample.c"),
        "utf-8"
      );
      await writeFile(join(dir, "v1.c"), src);
      await writeFile(
        join(dir, "v2.c"),
        src.replace("h * 33u", "h * 31u").replaceAll(/\bfib\b/gu, "fibonacci")
      );
      v1 = join(dir, "v1");
      v2 = join(dir, "v2");
      for (const [out, file] of [
        [v1, "v1.c"],
        [v2, "v2.c"],
      ] as const) {
        const proc = Bun.spawn([CC!, "-O0", "-o", out, join(dir, file)], {
          stderr: "pipe",
          stdout: "pipe",
        });
        if ((await proc.exited) !== 0) {
          throw new Error(`inherit test: compiling ${file} failed`);
        }
      }
    }, 60_000);
    afterAll(() => rmDirSafe(dir));

    test("adopt_finding re-proves a subagent finding in this session: re-runs its commands, records evidence here, gates the claim", async () => {
      const h = makeHarness("adopt-live");
      let verdict: ClaimAudit["verdict"] = "supported";
      registerFindingTools(h.pi, {
        judge: () => async (items) =>
          items.map((i) => ({
            index: i.index,
            reason: verdict === "supported" ? "shown" : "a loop, not a hash",
            verdict,
          })),
      });
      const v1Sha = await sha256File(v1);
      getState(h.ctx).binaryPath = v1;
      getState(h.ctx).binarySha256 = v1Sha;
      const adopt = (params: Record<string, unknown>) =>
        h
          .tool("adopt_finding")
          .execute("c", params, undefined, undefined, h.ctx);
      // What re-analyst hands back: claim + reproduce lines + its sha256 + confidence "possible".
      const subagentFinding = {
        addr: "sym.fib",
        claim: "fib computes Fibonacci numbers iteratively.",
        commands: [{ addr: "sym.fib", command: "pdf" }],
        confidence: "possible",
        expect_sha256: v1Sha,
        source: "re-analyst",
      };

      // A different binary open → refused before anything runs.
      await expect(
        adopt({ ...subagentFinding, expect_sha256: "e".repeat(64) })
      ).rejects.toThrow("open the same binary first");
      // A command that doesn't reproduce here → refused.
      await expect(
        adopt({
          ...subagentFinding,
          commands: [{ addr: "sym.no_such_function", command: "pdf" }],
        })
      ).rejects.toThrow("failed here");
      expect(collectFindings(h.entries)).toHaveLength(0);

      const result = await adopt(subagentFinding);
      expect(result.isError).toBeFalsy();
      expect(textOf(result)).toContain(
        "adopted from re-analyst: re-proven in this session"
      );
      const [finding] = collectFindings(h.entries);
      expect(finding).toMatchObject({
        addr: "sym.fib",
        adoptedFrom: "re-analyst",
        binarySha256: v1Sha,
        confidence: "speculative",
      });
      const ev = collectEvidence(h.entries).find(
        (e) => e.id === finding!.evidenceIds[0]
      );
      expect(ev).toMatchObject({
        args: { addr: "sym.fib", command: "pdf" },
        binarySha256: v1Sha,
        tool: "rizin_command",
      });
      expect(ev?.reproHash).toBeDefined();

      // The auditor still gates adopted claims; the re-run evidence stays recorded for a narrower claim.
      verdict = "overreach";
      const before = collectEvidence(h.entries).length;
      const refused = await adopt({
        ...subagentFinding,
        claim: "fib is the C2 key derivation.",
      });
      expect(refused.isError).toBe(true);
      expect(textOf(refused)).toContain("cite it in record_finding");
      expect(collectEvidence(h.entries).length).toBe(before + 1);
      expect(collectFindings(h.entries)).toHaveLength(1);
      shutdownState("adopt-live");
    }, 60_000);

    test("findings that hold are re-proven on v2 with fresh evidence; the one that drifted becomes the agenda", async () => {
      // ── Session A: analyse v1 and record findings on real rizin_command evidence.
      const a = makeHarness("inherit-v1");
      registerFindingTools(a.pi, { judge: () => judgeSaying("supported") });
      const v1Sha = await sha256File(v1);
      getState(a.ctx).binaryPath = v1;
      getState(a.ctx).binarySha256 = v1Sha;
      a.entries.push({
        customType: "re.binary",
        data: { path: v1, sha256: v1Sha },
        id: "b",
        type: "custom",
        // what /re open writes
      });
      const evidenceFor = async (command: string, addr: string) => {
        const res = await runRizinCommand(a.ctx, command, addr);
        return recordEvidence(
          a.pi,
          a.ctx,
          "rizin_command",
          { addr, command },
          res.content,
          res.details
        );
      };
      const evFib = await evidenceFor("pdf", "sym.fib");
      const evClamp = await evidenceFor("pdf", "sym.clamp");
      const evChecksum = await evidenceFor("pdf", "sym.checksum");
      const record = (claim: string, evidence: string, addr: string) =>
        a
          .tool("record_finding")
          .execute(
            "c",
            { addr, claim, confidence: "confirmed", evidence: [evidence] },
            undefined,
            undefined,
            a.ctx
          );
      await record(
        "fib computes Fibonacci numbers iteratively.",
        evFib,
        "sym.fib"
      );
      await record("clamp bounds its input to [lo, hi].", evClamp, "sym.clamp");
      await record(
        "checksum is a djb2 hash (h * 33 + c).",
        evChecksum,
        "sym.checksum"
      );
      const reportPath = join(dir, "v1.md");
      await writeReport(a.ctx, reportPath, { audit: "off" });
      shutdownState("inherit-v1");

      // ── Session B: carry onto v2 and inherit.
      const b = makeHarness("inherit-v2");
      const v2Sha = await sha256File(v2);
      getState(b.ctx).binaryPath = v2;
      getState(b.ctx).binarySha256 = v2Sha;
      b.entries.push({
        customType: "re.binary",
        data: { path: v2, sha256: v2Sha },
        id: "b",
        type: "custom",
      });
      const result = await carryManifest(b.ctx, `${reportPath}.manifest.json`, {
        inherit: b.pi,
      });
      const inh = result.inheritance!;
      expect(
        inh.inherited.map((i) => [i.claim.split(" ")[0], i.status]).toSorted()
      ).toEqual([
        ["clamp", "holds"],
        ["fib", "relocated"],
      ]);
      expect(inh.agenda.map((i) => [i.claim.split(" ")[0], i.status])).toEqual([
        ["checksum", "drifted"],
      ]);
      expect(inh.agenda[0]?.rows[0]?.diff?.some((l) => l.includes("sub"))).toBe(
        true
      );

      // Inherited findings cite NEW evidence, recorded on v2 — never the manifest's.
      const findings = collectFindings(b.entries);
      const evidenceB = collectEvidence(b.entries);
      const fib = findings.find((f) => f.claim.startsWith("fib"))!;
      expect(fib.addr).toBe("sym.fibonacci");
      expect(fib.inherited).toMatchObject({
        carryStatus: "relocated",
        fromBinarySha256: v1Sha,
      });
      for (const id of fib.evidenceIds) {
        const ev = evidenceB.find((e) => e.id === id);
        expect(ev?.binarySha256).toBe(v2Sha);
        expect(ev?.reproHash).toBeDefined();
      }

      // The v2 report carries the inherited findings with their provenance.
      const v2Report = join(dir, "v2.md");
      await writeReport(b.ctx, v2Report, { audit: "off" });
      const md = await readFile(v2Report, "utf-8");
      expect(md).toContain("## Findings");
      expect(md).toContain(
        "re-verified on this build (relocated: sym.fib @ 0x11fd → sym.fibonacci @ 0x11fd)"
      );
      expect(md).not.toContain("checksum is a djb2");

      // --resolve hands the agenda to the model as a user turn instead of printing it.
      const sent: string[] = [];
      (
        b.pi as unknown as { sendUserMessage: (m: string) => void }
      ).sendUserMessage = (m) => sent.push(m);
      const resolved = await carryManifest(
        b.ctx,
        `${reportPath}.manifest.json`,
        { inherit: b.pi, resolve: true }
      );
      expect(resolved.inheritance?.agenda.map((i) => i.claim)).toEqual([
        "checksum is a djb2 hash (h * 33 + c).",
      ]);
      expect(sent).toHaveLength(1);
      expect(sent[0]).toContain("[drifted] checksum is a djb2 hash");
      expect(sent[0]).toContain("+ |      :|   0x0000126c      sub   eax, edx");

      // Idempotent: inheriting again adds nothing.
      const again = await carryManifest(b.ctx, `${reportPath}.manifest.json`, {
        inherit: b.pi,
      });
      expect(again.inheritance?.inherited).toHaveLength(0);
      expect(again.inheritance?.alreadyPresent).toBe(2);
      shutdownState("inherit-v2");
    }, 120_000);
  }
);
