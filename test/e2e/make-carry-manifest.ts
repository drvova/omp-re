/**
 * Fixture builder for test/tui-carry.sh: record three findings on build v1 of
 * the sample fixture (real rizin_command evidence, the real record_finding tool
 * with a stand-in auditor — no model needed) and write the report + manifest.
 *
 *   bun test/e2e/make-carry-manifest.ts <v1-binary> <report.md>
 */
import { recordEvidence } from "../../extensions/re/evidence.ts";
import { registerFindingTools } from "../../extensions/re/findings.ts";
import { writeReport } from "../../extensions/re/report.ts";
import { getState, shutdownState } from "../../extensions/re/state.ts";
import { runRizinCommand } from "../../extensions/re/tools-rizin.ts";
import { sha256File } from "../../extensions/re/verify.ts";
import { makeHarness } from "../helpers.ts";

const [v1, reportPath] = process.argv.slice(2);
if (!v1 || !reportPath) {
  throw new Error(
    "usage: bun test/e2e/make-carry-manifest.ts <v1-binary> <report.md>"
  );
}

const h = makeHarness("tui-carry-fixture");
registerFindingTools(h.pi, {
  judge: () => async (items) =>
    items.map((i) => ({
      index: i.index,
      reason: "fixture",
      verdict: "supported" as const,
    })),
});
const sha = await sha256File(v1);
getState(h.ctx).binaryPath = v1;
getState(h.ctx).binarySha256 = sha;
h.entries.push({
  customType: "re.binary",
  data: { path: v1, sha256: sha },
  id: "b",
  type: "custom",
});
const findings: [string, string][] = [
  ["sym.fib", "fib computes Fibonacci numbers iteratively."],
  ["sym.clamp", "clamp bounds its input to [lo, hi]."],
  ["sym.checksum", "checksum is a djb2 hash (h * 33 + c)."],
];
for (const [fn, claim] of findings) {
  const res = await runRizinCommand(h.ctx, "pdf", fn);
  const id = await recordEvidence(
    h.pi,
    h.ctx,
    "rizin_command",
    { addr: fn, command: "pdf" },
    res.content,
    res.details
  );
  await h
    .tool("record_finding")
    .execute(
      "fixture",
      { addr: fn, claim, confidence: "confirmed", evidence: [id] },
      undefined,
      undefined,
      h.ctx
    );
}
await writeReport(h.ctx, reportPath, { audit: "off" });
shutdownState("tui-carry-fixture");
