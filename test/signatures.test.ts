/**
 * apply_signatures (FLIRT) against real rizin, plus the custom-file replay.
 *
 * A minimal FLIRT `.pat` is built from the fixture's own `main` bytes so the
 * application matches exactly one function and creates the observable
 * `flirt.*` flag rizin uses — letting the test assert the apply landed and
 * that it is re-applied after the rizin process dies (resume/crash).
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import { recordedSignatures } from "../extensions/re/entries.ts";
import { rizinPathArg } from "../extensions/re/output.ts";
import {
  addrOf,
  eaFromOffset,
  RzSession,
  resolveBinaryPath,
} from "../extensions/re/rizin.ts";
import {
  ensureRizin,
  getState,
  shutdownState,
} from "../extensions/re/state.ts";
import { registerSignatureTools } from "../extensions/re/tools-signatures.ts";
import {
  canRunRizin,
  captureError,
  logSkip,
  makeHarness,
  rizinPath,
  TEST_BINARY,
  textOf,
  must,
} from "./helpers.ts";

logSkip("signatures tests");

describe.skipIf(!canRunRizin)("apply_signatures (chapter D)", () => {
  const harness = makeHarness("omp-re-signatures-test");
  const { pi, ctx, entries } = harness;
  const run = (params: Record<string, unknown>) =>
    harness
      .tool("apply_signatures")
      .execute("call-apply", params, undefined, undefined, ctx);
  let rz: RzSession;
  let binaryPath: string;
  let dir: string;
  let pat: string;
  let mainEa: string;

  const flirtFlagExists = async (): Promise<boolean> => {
    const flompresigmainOutput = await rz.cmd("fl~omp_re_sig_main");
    return flompresigmainOutput.trim() !== "";
  };

  registerSignatureTools(pi);

  beforeAll(async () => {
    binaryPath = await resolveBinaryPath(TEST_BINARY);
    entries.push({
      customType: "re.binary",
      data: { path: binaryPath },
      id: "bin-0",
      type: "custom",
    });
    rz = await RzSession.spawn(rizinPath, binaryPath);
    getState(ctx).binaryPath = binaryPath;
    getState(ctx).rz = rz;
    mainEa = eaFromOffset(
      must(
        addrOf(
          must(await rz.cmdj<{ offset: number }[]>("afij @ main"))[0] as never
        )
      )
    );

    // A minimal FLIRT .pat matching main's first 16 bytes: <32 nibbles> <crc-len> <crc16> <len> :<off> <name>.
    const rawBytes = await rz.cmd(`p8 32 @ ${mainEa}`);
    const bytes = rawBytes.trim().toUpperCase();
    dir = mkdtempSync(nodePath.join(tmpdir(), "omp-re-sig-"));
    pat = nodePath.join(dir, "fixture.pat");
    writeFileSync(
      pat,
      `${bytes.slice(0, 32)} 00 0000 0020 :0000 omp_re_sig_main\n---\n`
    );
  });

  afterAll(() => {
    shutdownState(ctx.sessionManager.getSessionId());
    rmSync(dir, { force: true, recursive: true });
  });

  test("source 'sigdb' re-applies the built-in database and reports the function count", async () => {
    const result = await run({ source: "sigdb" });
    expect(textOf(result)).toMatch(
      /Re-applied the built-in signature database\. Functions: \d+ before, \d+ after\./u
    );
  });

  test("source 'file' applies a custom .pat, is recorded, and creates rizin's flirt flag", async () => {
    const result = await run({ path: pat, source: "file" });
    expect(textOf(result)).toMatch(/Applied \d+ FLIRT signature\(s\)/u);
    expect(await flirtFlagExists()).toBe(true);
    // Recorded for replay, scoped to this binary.
    expect(recordedSignatures(entries as never, binaryPath)).toContain(pat);
  });

  test("source 'file' without a path is rejected", async () => {
    const captureErrorResult = await captureError(run({ source: "file" }));
    expect(captureErrorResult.message).toContain("needs a path");
  });

  test("the applied custom signature survives the rizin process dying: the respawn re-applies it", async () => {
    // The flag exists now; kill the process and let ensureRizin respawn + replay from the branch.
    expect(await flirtFlagExists()).toBe(true);
    rz.close();
    rz = await ensureRizin(ctx);
    expect(await flirtFlagExists()).toBe(true);
  });
});

describe.skipIf(!canRunRizin)("create_signature (FLIRT creation)", () => {
  const harness = makeHarness("omp-re-create-sig-test");
  const { pi, ctx } = harness;
  const run = (params: Record<string, unknown>) =>
    harness
      .tool("create_signature")
      .execute("call-create", params, undefined, undefined, ctx);
  let rz: RzSession;
  let binaryPath: string;
  let outDir: string;

  registerSignatureTools(pi);

  beforeAll(async () => {
    outDir = mkdtempSync(nodePath.join(tmpdir(), "omp-re-csig-"));
    process.env.OMPRE_OUTPUT_DIR = outDir;
    binaryPath = await resolveBinaryPath(TEST_BINARY);
    // spawn runs `aaa`, so there are functions to signature
    rz = await RzSession.spawn(rizinPath, binaryPath);
    getState(ctx).binaryPath = binaryPath;
    getState(ctx).rz = rz;
  });
  afterAll(() => {
    delete process.env.OMPRE_OUTPUT_DIR;
    shutdownState(ctx.sessionManager.getSessionId());
    rmSync(outDir, { force: true, recursive: true });
  });

  test("writes a non-empty FLIRT .pat the apply path can then consume", async () => {
    // `.pat` appended
    const result = textOf(await run({ file: "fixture" }));
    const path = nodePath.join(outDir, "fixture.pat");
    expect(result).toContain(path);
    expect(result).toMatch(/wrote \d+ function signature\(s\)/u);
    const made = readFileSync(path, "utf-8");
    expect(made.length).toBeGreaterThan(0);
    // The created file is a real FLIRT signature: applying it to the same binary matches (rizin loads it without error).
    const FsOutput = await rz.cmdWithStderr(`Fs ${rizinPathArg(path)}`);
    expect(FsOutput.stderr.trim()).toBe("");
  }, 30_000);

  test("derives a .pat name from the binary when no file is given, and refuses a traversing name", async () => {
    expect(textOf(await run({}))).toMatch(/\.pat \(\d+ bytes\)/u);
    const captureErrorResult2 = await captureError(
      run({ file: "../escape.pat" })
    );
    expect(captureErrorResult2.message).toContain("invalid output filename");
  }, 30_000);
});
