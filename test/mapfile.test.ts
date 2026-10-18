/**
 * map_file (tools-mapfile.ts): open an additional file into the live session
 * at a virtual address, recording it for respawn replay. Runs against a real
 * rizin session; skipped when rizin or the fixture is missing.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { recordedMapFiles } from "../extensions/re/entries.ts";
import { RzSession, resolveBinaryPath } from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import { registerMapFileTools } from "../extensions/re/tools-mapfile.ts";
import {
  canRunRizin,
  captureError,
  logSkip,
  makeHarness,
  rizinPath,
  rmDirSafe,
  TEST_BINARY,
  textOf,
} from "./helpers.ts";

logSkip("map_file tests");

describe.skipIf(!canRunRizin)("map_file against a real rizin session", () => {
  const harness = makeHarness("omp-re-mapfile-test");
  const { pi, ctx, entries } = harness;
  const run = (params: Record<string, unknown>) =>
    harness
      .tool("map_file")
      .execute("call-map", params, undefined, undefined, ctx);
  let rz: RzSession;
  let binaryPath: string;
  let dir: string;
  let blob: string;

  registerMapFileTools(pi);

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "omp-re-mapfile-"));
    blob = join(dir, "overlay.bin");
    writeFileSync(blob, "MAPFILETOOLDATA7"); // 16 bytes
    binaryPath = await resolveBinaryPath(TEST_BINARY);
    entries.push({
      customType: "re.binary",
      data: { path: binaryPath },
      id: "bin-0",
      type: "custom",
    });
    rz = await RzSession.spawn(rizinPath, binaryPath); // spawn runs `aaa`
    getState(ctx).binaryPath = binaryPath;
    getState(ctx).rz = rz;
  });
  afterAll(() => {
    shutdownState(ctx.sessionManager.getSessionId());
    rmDirSafe(dir);
  });

  test("declares exec-tier and says the file on disk is not modified", () => {
    const approval = harness.tool("map_file").approval as (a: unknown) => {
      tier: string;
      reason: string;
    };
    const a = approval({ addr: "0x50000", path: blob });
    expect(a.tier).toBe("exec");
    expect(a.reason).toMatch(/not modified|read-only/u);
  });

  test("maps the file, independently readable at the address, and records it for replay", async () => {
    const result = textOf(await run({ addr: "0x50000", path: blob }));
    expect(result).toContain(`@ 0x50000`);
    // independently verified: the blob's bytes are readable at the mapped address
    expect((await rz.cmd("p8 16 @ 0x50000")).trim().toLowerCase()).toBe(
      Buffer.from("MAPFILETOOLDATA7").toString("hex")
    );
    // recorded (by realpath) so a respawn re-maps it
    const recorded = recordedMapFiles(entries as never, binaryPath);
    expect(
      recorded.some(
        (m) => m.addr === "0x50000" && m.path.endsWith("overlay.bin")
      )
    ).toBe(true);
  }, 30_000);

  test("a nonexistent path is rejected with omp-re's own error, and a bad permission before rizin", async () => {
    expect(
      (
        await captureError(
          run({ addr: "0x60000", path: join(dir, "nope.bin") })
        )
      ).message
    ).toContain("no such binary");
    expect(
      (await captureError(run({ addr: "0x60000", path: blob, perm: "bad" })))
        .message
    ).toContain("invalid permission");
  });
});
