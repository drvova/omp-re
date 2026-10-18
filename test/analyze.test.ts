/**
 * The `analyze` tool (re-running analysis passes) against real rizin, plus the
 * record-and-replay that keeps a pass's result after the rizin process dies.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import { recordedAnalysisPasses } from "../extensions/re/entries.ts";
import { RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { getState, shutdownState, spawnRizin } from "../extensions/re/state.ts";
import { registerAnalyzeTools } from "../extensions/re/tools-analyze.ts";
import {
  canRunRizin,
  logSkip,
  makeHarness,
  rizinPath,
  TEST_BINARY,
  textOf,
} from "./helpers.ts";

logSkip("analyze tests");

describe.skipIf(!canRunRizin)("analyze (chapter H)", () => {
  const harness = makeHarness("omp-re-analyze-test");
  const { pi, ctx, entries } = harness;
  const run = (pass: string) =>
    harness
      .tool("analyze")
      .execute("call-analyze", { pass }, undefined, undefined, ctx);
  let binaryPath: string;

  registerAnalyzeTools(pi);

  beforeAll(async () => {
    binaryPath = await resolveBinaryPath(TEST_BINARY);
    entries.push({
      customType: "re.binary",
      data: { path: binaryPath },
      id: "bin-0",
      type: "custom",
    });
    const rz = await RzSession.spawn(rizinPath, binaryPath);
    getState(ctx).binaryPath = binaryPath;
    getState(ctx).rz = rz;
  });

  afterAll(() => {
    shutdownState(ctx.sessionManager.getSessionId());
  });

  test("it is exec-tier and the reason says the analysis changes", () => {
    const approval = harness.tool("analyze").approval as (a: unknown) => {
      tier: string;
      reason: string;
    };
    expect(approval({ pass: "preludes" })).toEqual({
      reason: expect.stringContaining("changes the analysis"),
      tier: "exec",
    });
  });

  test("a pass reports the function count before and after", async () => {
    expect(textOf(await run("calls"))).toMatch(/aac: functions \d+ -> \d+/u);
  });

  test("a pass that doesn't apply surfaces rizin's own message and is not recorded for replay", async () => {
    // /bin/ls is not a Go binary, so `golang` (aalg) reports it can't recover and leaves nothing to replay.
    const out = textOf(await run("golang"));
    expect(out.toLowerCase()).toMatch(/cannot|no .*found|not a/u);
    expect(recordedAnalysisPasses(entries as never, binaryPath)).not.toContain(
      "golang"
    );
  });

  test("a recorded pass is re-run on respawn (computed from the branch, like signatures/annotations)", async () => {
    // Seed the pass as if the tool had recorded it, then respawn and confirm
    // it replays without error and the process is analyzed and usable.
    entries.push({
      customType: "re.analysis",
      data: { pass: "preludes" },
      id: "an-0",
      type: "custom",
    });
    expect(recordedAnalysisPasses(entries as never, binaryPath)).toContain(
      "preludes"
    );
    getState(ctx).rz?.close();
    const { rz, replayFailures } = await spawnRizin(ctx, binaryPath);
    expect(replayFailures).toEqual([]);
    expect(Number((await rz.cmd("aflc")).trim())).toBeGreaterThan(0);
  }, 30_000);
});
