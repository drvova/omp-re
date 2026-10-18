/**
 * export_project (tools-project.ts): save the live analysis — omp-re's
 * annotations included — to a rizin project that a fresh rizin can re-open.
 * Runs against a real rizin session and is skipped when rizin or the fixture
 * is missing.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { registerProjectTools } from "../extensions/re/tools-project.ts";
import {
  canRunRizin,
  captureError,
  logSkip,
  makeHarness,
  rizinPath,
  TEST_BINARY,
  textOf,
} from "./helpers.ts";

logSkip("export_project tests");

describe.skipIf(!canRunRizin)(
  "export_project against a real rizin session",
  () => {
    const harness = makeHarness("omp-re-project-test");
    const { pi, ctx } = harness;
    const run = (params: Record<string, unknown>) =>
      harness
        .tool("export_project")
        .execute("call-export", params, undefined, undefined, ctx);
    let rz: RzSession;
    let binaryPath: string;
    let outDir: string;

    registerProjectTools(pi);

    beforeAll(async () => {
      outDir = mkdtempSync(join(tmpdir(), "omp-re-proj-test-"));
      process.env.OMPRE_OUTPUT_DIR = outDir;
      binaryPath = await resolveBinaryPath(TEST_BINARY);
      rz = await RzSession.spawn(rizinPath, binaryPath); // spawn runs `aaa` on open
      const state = getState(ctx);
      state.binaryPath = binaryPath;
      state.rz = rz;
    });
    afterAll(() => {
      delete process.env.OMPRE_OUTPUT_DIR;
      shutdownState(ctx.sessionManager.getSessionId());
      rmSync(outDir, { force: true, recursive: true });
    });

    test("declares exec-tier with a reason that says the sample is unchanged", () => {
      const approval = harness.tool("export_project").approval as (
        a: unknown
      ) => { tier: string; reason: string };
      const a = approval({});
      expect(a.tier).toBe("exec");
      expect(a.reason).toMatch(/not modified|unchanged|output directory/);
    });

    test("writes a non-empty .rzdb to the output dir, and rizin -p re-opens it with an annotation intact", async () => {
      // Apply an annotation into the live session, then export — the project must carry it.
      await rz.cmd("afn omp_re_exported_main @ main");
      const result = textOf(await run({ file: "analysis" }));
      const path = join(outDir, "analysis.rzdb"); // `.rzdb` appended when missing
      expect(result).toContain(path);
      expect(existsSync(path)).toBe(true);

      // Re-open via the canonical project-open path (`rizin -p`) — a fresh rizin whose
      // whole analysis comes from the project — and confirm the rename is in it.
      const proc = Bun.spawn(
        [rizinPath, "-p", path, "-N", "-e", "scr.color=0", "-qc", "aflj"],
        { stderr: "ignore", stdin: "ignore", stdout: "pipe" }
      );
      const out = await new Response(proc.stdout).text();
      await proc.exited;
      const names = (
        JSON.parse(out.replaceAll(/\x1B\[[0-9;]*[A-Za-z]/g, "").trim()) as {
          name: string;
        }[]
      ).map((f) => f.name);
      expect(names).toContain("omp_re_exported_main");
    }, 30_000);

    test("derives a .rzdb name from the binary when no file is given", async () => {
      const result = textOf(await run({}));
      expect(result).toMatch(/\.rzdb \(\d+ bytes\)/);
    }, 30_000);

    test("refuses a traversing or separator-bearing filename before touching rizin", async () => {
      expect(
        (await captureError(run({ file: "../escape.rzdb" }))).message
      ).toContain("invalid output filename");
      expect(
        (await captureError(run({ file: "sub/proj.rzdb" }))).message
      ).toContain("invalid output filename");
    });
  }
);
