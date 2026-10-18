/**
 * Verifiable reports: the canonicalization that makes a reproHash stable, the
 * static recorded-status classifier the report manifest uses, and the live
 * `/re verify` re-run — reproducible, tampered, legacy, and binary-mismatch.
 *
 * The non-re-running classifications need no rizin and always run; the actual
 * re-run (reproducible / tamper) is gated on a real rizin + /bin/ls, like the
 * other integration suites.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import type { EvidenceRecord } from "../extensions/re/entries.ts";
import {
  canonicalHash,
  canonicalizeRizinOutput,
} from "../extensions/re/format.ts";
import {
  ensureRizin,
  getState,
  shutdownState,
} from "../extensions/re/state.ts";
import {
  recordedStatus,
  sha256File,
  verifyEvidence,
} from "../extensions/re/verify.ts";
import { canRunRizin, logSkip, makeHarness, TEST_BINARY } from "./helpers.ts";

logSkip("verify (live re-run) tests");

const HEX64 = (c: string) => c.repeat(64);

beforeEach(() => {
  process.exitCode = 0;
});
afterEach(() => {
  process.exitCode = 0;
});

describe("canonicalizeRizinOutput / canonicalHash (no rizin needed)", () => {
  test("ANSI escapes, CRLF, trailing whitespace, and trailing blank lines don't change the hash", () => {
    const clean = "section .text\nsection .data";
    const noisy = "\u001B[2Ksection .text  \r\nsection .data\t\n\n\n";
    expect(canonicalizeRizinOutput(noisy)).toBe(clean);
    expect(canonicalHash(noisy)).toBe(canonicalHash(clean));
  });

  test("the open binary's absolute path is redacted, so a path-bearing header is stable", () => {
    const withPath = canonicalHash("file /bin/ls loaded", "/bin/ls");
    const redacted = canonicalHash("file <BINARY> loaded", "/bin/ls");
    expect(withPath).toBe(redacted);
  });

  test("a byte-meaningful difference does change the hash", () => {
    expect(canonicalHash("imports: 3")).not.toBe(canonicalHash("imports: 4"));
  });
});

describe("recordedStatus (no rizin needed)", () => {
  const rec = (over: Partial<EvidenceRecord>): EvidenceRecord => ({
    id: "x",
    summary: "",
    tool: "rizin_command",
    ...over,
  });

  test("reproHash + binarySha256 => reproducible", () => {
    expect(
      recordedStatus(rec({ binarySha256: HEX64("b"), reproHash: HEX64("a") }))
    ).toBe("reproducible");
  });
  test("a command but no reproHash => provenance-only", () => {
    expect(
      recordedStatus(rec({ commands: ["afij @ 0x4da0"], tool: "get_function" }))
    ).toBe("provenance-only");
  });
  test("neither => unverifiable (legacy)", () => {
    expect(recordedStatus(rec({ tool: "list_imports" }))).toBe(
      "unverifiable (legacy)"
    );
  });
});

describe("verifyEvidence classification (no rizin needed)", () => {
  test("a legacy record (no reproHash) is unverifiable, does not fail by default, fails under --strict", async () => {
    const h = makeHarness("verify-legacy");
    h.entries.push({
      customType: "re.evidence",
      data: { id: "ev-legacy", summary: "old evidence", tool: "rizin_command" },
      id: "e1",
      type: "custom",
    });

    const rows = await verifyEvidence(h.ctx);
    expect(rows.find((r) => r.id === "ev-legacy")?.status).toBe("unverifiable");
    expect(process.exitCode).not.toBe(1);

    await verifyEvidence(h.ctx, { strict: true });
    expect(process.exitCode).toBe(1);
    shutdownState("verify-legacy");
  });

  test("evidence bound to a different binary is unverifiable (not a false pass or fail)", async () => {
    const h = makeHarness("verify-mismatch");
    const state = getState(h.ctx);
    state.binaryPath = "/does/not/matter"; // never read: binarySha256 is set, so no file hashing happens
    state.binarySha256 = HEX64("b");
    h.entries.push({
      customType: "re.evidence",
      data: {
        args: { command: "iHj" },
        binarySha256: HEX64("a"),
        id: "ev-other",
        reproHash: HEX64("a"),
        summary: "from another binary",
        tool: "rizin_command",
      },
      id: "e1",
      type: "custom",
    });

    const rows = await verifyEvidence(h.ctx);
    const row = rows.find((r) => r.id === "ev-other");
    expect(row?.status).toBe("unverifiable");
    expect(row?.detail).toContain("different binary");
    expect(process.exitCode).not.toBe(1);
    shutdownState("verify-mismatch");
  });
});

describe.skipIf(!canRunRizin)("verifyEvidence against real rizin", () => {
  test("a rizin_command record re-runs to the same hash (reproducible), and tampering makes it FAIL", async () => {
    const h = makeHarness("verify-live");
    const state = getState(h.ctx);
    state.binaryPath = TEST_BINARY;
    const sha = await sha256File(TEST_BINARY);
    state.binarySha256 = sha;

    // Record evidence the way rizin_command does: reproHash over the RAW output, canonicalized against the binary path.
    const rz = await ensureRizin(h.ctx);
    const { output } = await rz.cmdWithStderr("iHj");
    const reproHash = canonicalHash(output, TEST_BINARY);
    h.entries.push({
      customType: "re.evidence",
      data: {
        args: { command: "iHj" },
        binarySha256: sha,
        commands: ["iHj"],
        id: "ev-live",
        reproHash,
        summary: "headers",
        tool: "rizin_command",
      },
      id: "e1",
      type: "custom",
    });

    const rows = await verifyEvidence(h.ctx);
    expect(rows.find((r) => r.id === "ev-live")?.status).toBe("reproducible");
    expect(process.exitCode).not.toBe(1);

    // Tamper: a stored hash that no longer matches the real re-run must FAIL loudly (non-zero headless exit).
    (h.entries[0]!.data as { reproHash: string }).reproHash = HEX64("0");
    const tampered = await verifyEvidence(h.ctx);
    const row = tampered.find((r) => r.id === "ev-live");
    expect(row?.status).toBe("tampered");
    expect(process.exitCode).toBe(1);

    shutdownState("verify-live");
  }, 30_000);
});
