import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  outputDir,
  prepareOutputPath,
  rizinPathArg,
  safeBasename,
  toRizinPath,
} from "../extensions/re/output.ts";

describe("safeBasename", () => {
  test("accepts bare names of safe characters", () => {
    for (const name of ["dump.bin", "a_b-c.1", "payload", "x.0x4000.bin"]) {
      expect(safeBasename(name)).toBe(name);
    }
  });

  test("rejects separators, traversal, absolute paths, and empties", () => {
    for (const bad of [
      "../etc/passwd",
      "a/b",
      "a\\b",
      "/abs",
      "..",
      ".",
      "",
      "  ",
      "na me",
      "a;b",
      "`id`",
    ]) {
      expect(() => safeBasename(bad)).toThrow(/invalid output filename/);
    }
  });
});

describe("toRizinPath", () => {
  test("normalizes Windows separators to the forward slashes rizin accepts, and leaves POSIX paths alone", () => {
    expect(
      toRizinPath(
        "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\omp-re-out\\a.rzdb"
      )
    ).toBe("C:/Users/runneradmin/AppData/Local/Temp/omp-re-out/a.rzdb");
    expect(toRizinPath("/tmp/omp-re-out/a.rzdb")).toBe(
      "/tmp/omp-re-out/a.rzdb"
    );
    // A drive-colon path is what reaches rizin on Windows; it must survive normalization as safe characters only.
    expect(
      /^[A-Za-z0-9_.:/-]+$/.test(toRizinPath("C:\\Temp\\omp-re-out\\dump.bin"))
    ).toBe(true);
  });
});

describe("rizinPathArg", () => {
  test("single-quotes a forward-slashed path so rizin takes a ~ short-name, drive colon, or space literally", () => {
    // A Windows 8.3 temp path: raw, rizin would read `~` as its grep operator.
    expect(
      rizinPathArg(
        "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\omp-re-out\\a.rzdb"
      )
    ).toBe("'C:/Users/RUNNER~1/AppData/Local/Temp/omp-re-out/a.rzdb'");
    expect(rizinPathArg("/tmp/omp-re-out/a.rzdb")).toBe(
      "'/tmp/omp-re-out/a.rzdb'"
    );
  });
});

describe("prepareOutputPath", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "omp-re-out-test-"));
    process.env.OMPRE_OUTPUT_DIR = dir;
  });
  afterAll(() => {
    delete process.env.OMPRE_OUTPUT_DIR;
    rmSync(dir, { force: true, recursive: true });
  });

  test("honors OMPRE_OUTPUT_DIR and returns a path inside it, creating the dir", async () => {
    expect(outputDir()).toBe(dir);
    const path = await prepareOutputPath("dump.bin");
    expect(path).toBe(join(dir, "dump.bin"));
    expect(existsSync(dir)).toBe(true);
  });

  test("refuses a name that escapes the directory before any write", async () => {
    await expect(prepareOutputPath("../escape.bin")).rejects.toThrow(
      /invalid output filename/
    );
    await expect(prepareOutputPath("sub/escape.bin")).rejects.toThrow(
      /invalid output filename/
    );
  });
});
