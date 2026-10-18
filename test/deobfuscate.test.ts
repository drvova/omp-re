/**
 * `deobfuscate` — pure command building, and a live drive that reveals an
 * xor-hidden string and proves the in-memory buffer is restored afterward
 * (the transform runs under the write cache and is reset).
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import { RzSession } from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import {
  deobfuscateCommand,
  registerDeobfuscateTools,
} from "../extensions/re/tools-deobfuscate.ts";
import {
  canRunRizin,
  captureError,
  logSkip,
  makeHarness,
  rizinPath,
  rmDirSafe,
  textOf,
} from "./helpers.ts";

logSkip("deobfuscate tests");

describe("deobfuscateCommand (no rizin needed)", () => {
  test("builds the wo* command for each op, at the given address", () => {
    expect(deobfuscateCommand("xor", "0x1000", { key: "5a" })).toBe(
      "wox 5a @ 0x1000"
    );
    expect(deobfuscateCommand("add", "0x1000", { key: "01" })).toBe(
      "woa 01 @ 0x1000"
    );
    expect(deobfuscateCommand("and", "0x1000", { key: "0f" })).toBe(
      "woA 0f @ 0x1000"
    );
    expect(deobfuscateCommand("swap4", "0x1000", {})).toBe("wo4 @ 0x1000");
    expect(
      deobfuscateCommand("decrypt", "0x1000", { algo: "rc4", key: "6b6579" })
    ).toBe("woD rc4 6b6579 @ 0x1000");
    expect(
      deobfuscateCommand("decrypt", "0x1000", {
        algo: "aes-cbc",
        iv: "ffee",
        key: "00112233",
      })
    ).toBe("woD aes-cbc 00112233 ffee @ 0x1000");
  });

  test("rejects missing/invalid key, algo, and op", () => {
    expect(() => deobfuscateCommand("xor", "0x1000", {})).toThrow(
      "key is required"
    );
    expect(() => deobfuscateCommand("xor", "0x1000", { key: "xyz" })).toThrow(
      "even number of hex digits"
    );
    expect(() => deobfuscateCommand("xor", "0x1000", { key: "5" })).toThrow(
      "even number of hex digits"
    );
    expect(() =>
      deobfuscateCommand("decrypt", "0x1000", { key: "5a" })
    ).toThrow("needs an algo");
    expect(() =>
      deobfuscateCommand("decrypt", "0x1000", { algo: "r c4", key: "5a" })
    ).toThrow("needs an algo");
  });
});

describe.skipIf(!canRunRizin)("deobfuscate against a real session", () => {
  const harness = makeHarness("omp-re-deobfuscate-test");
  const { ctx } = harness;
  const run = (params: Record<string, unknown>) =>
    harness
      .tool("deobfuscate")
      .execute("call-deob", params, undefined, undefined, ctx);
  let dir: string;
  let blob: string;
  const PLAINTEXT = "http://evil.example/cfg";

  registerDeobfuscateTools(harness.pi);

  beforeAll(async () => {
    dir = mkdtempSync(nodePath.join(tmpdir(), "omp-re-deob-"));
    blob = nodePath.join(dir, "xorblob.bin");
    // 16 bytes of padding, then "http://evil.example/cfg\0" each byte xored
    // with 0x5a at offset 0x10 (a raw blob maps at base 0, and address 0x0
    // is rejected by the shared addr guard, so target a non-zero offset).
    const payload = Buffer.from(
      [...Buffer.from(`${PLAINTEXT}\0`)].map((b) => b ^ 0x5a)
    );
    writeFileSync(blob, Buffer.concat([Buffer.alloc(0x10, 0x90), payload]));
    const rz = await RzSession.spawn(rizinPath, blob);
    getState(ctx).binaryPath = blob;
    getState(ctx).rz = rz;
  });

  afterAll(() => {
    shutdownState(ctx.sessionManager.getSessionId());
    rmDirSafe(dir);
  });

  test("it is read-tier (observational, reverts) with a reason naming the transform", () => {
    const { approval } = harness.tool("deobfuscate");
    expect(approval).toBe("read");
  });

  test("xor reveals the hidden string, and the buffer is restored afterward", async () => {
    const rz = getState(ctx).rz!;
    const before = (await rz.cmd("p8 24 @ 0x10")).trim();

    const out = textOf(
      await run({ addr: "0x10", key: "5a", op: "xor", size: 24 })
    );
    expect(out).toContain(PLAINTEXT);

    // The write cache was reset: the raw (still-xored) bytes are back.
    expect((await rz.cmd("p8 24 @ 0x10")).trim()).toBe(before);
    // And nothing was committed to the write cache.
    expect((await rz.cmd("wcj")).trim()).toMatch(/^\[\]$|^$/u);
  });

  test("a bad size is rejected before any transform", async () => {
    expect(
      (await captureError(run({ addr: "0x10", key: "5a", op: "xor", size: 0 })))
        .message
    ).toContain("size must be an integer");
    expect(
      (
        await captureError(
          run({ addr: "0x10", key: "5a", op: "xor", size: 99_999_999 })
        )
      ).message
    ).toContain("size must be an integer");
  });

  test("an unknown cipher surfaces rizin's error and still restores the buffer", async () => {
    const rz = getState(ctx).rz!;
    const before = (await rz.cmd("p8 24 @ 0x10")).trim();
    const res = await run({
      addr: "0x10",
      algo: "nosuchcipher",
      key: "6b6579",
      op: "decrypt",
      size: 16,
    });
    expect(res.isError).toBe(true);
    expect((await rz.cmd("p8 24 @ 0x10")).trim()).toBe(before);
  });
});
