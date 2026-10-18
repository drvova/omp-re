import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import type { ClaimAudit, ClaimJudge } from "../extensions/re/audit-claims.ts";
import { writeReport } from "../extensions/re/report.ts";

interface StubEntry {
  id?: string;
  type: string;
  customType?: string;
  data?: unknown;
}

function makeCtx(
  entries: StubEntry[],
  notifications: { message: string; type?: string }[]
): ExtensionContext {
  return {
    hasUI: false,
    sessionManager: {
      getArtifactPath: async () => null,
      getBranch: () => entries,
      getSessionId: () => "test-session",
    },
    ui: {
      notify: (message: string, type?: string) => {
        notifications.push({ message, type });
      },
    },
  } as unknown as ExtensionContext;
}

let tempDir: string;
let consoleErrorCalls: unknown[][];
let consoleLogCalls: unknown[][];
let originalConsoleError: typeof console.error;
let originalConsoleLog: typeof console.log;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "omp-re-report-test-"));
  process.exitCode = 0;
  consoleErrorCalls = [];
  consoleLogCalls = [];
  originalConsoleError = console.error;
  originalConsoleLog = console.log;
  console.error = (...args: unknown[]) => {
    consoleErrorCalls.push(args);
  };
  console.log = (...args: unknown[]) => {
    consoleLogCalls.push(args);
  };
});

afterEach(async () => {
  console.error = originalConsoleError;
  console.log = originalConsoleLog;
  process.exitCode = 0;
  await rm(tempDir, { force: true, recursive: true });
});

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

describe("writeReport", () => {
  test("ungrounded: an IOC-shaped claim with no evidence id withholds the report", async () => {
    const entries: StubEntry[] = [
      {
        customType: "re.annotation",
        data: {
          ea: "0x401000",
          evidenceId: "",
          kind: "comment",
          newValue: "http://evil-test.example/payload",
          oldValue: "",
        },
        type: "custom",
      },
    ];
    const notifications: { message: string; type?: string }[] = [];
    const ctx = makeCtx(entries, notifications);
    const outputPath = join(tempDir, "withheld.md");

    await writeReport(ctx, outputPath);

    expect(process.exitCode).toBe(1);
    expect(await fileExists(outputPath)).toBe(false);

    const errorText = consoleErrorCalls
      .map((args) => args.join(" "))
      .join("\n");
    expect(errorText).toContain("omp-re: report withheld");
    expect(errorText).toContain("hxxp://evil-test[.]example/payload");
  });

  test("grounded: an evidence-backed IOC claim writes the report with an anchor", async () => {
    const entries: StubEntry[] = [
      {
        customType: "re.evidence",
        data: {
          id: "ev-1",
          summary:
            "found string: http://185.220.101.99/update.php in .data section",
          tool: "list_strings",
        },
        type: "custom",
      },
    ];
    const notifications: { message: string; type?: string }[] = [];
    const ctx = makeCtx(entries, notifications);
    const outputPath = join(tempDir, "grounded.md");

    await writeReport(ctx, outputPath);

    expect(process.exitCode).not.toBe(1);
    expect(await fileExists(outputPath)).toBe(true);

    const markdown = await readFile(outputPath, "utf-8");
    expect(markdown).toContain("ev-1");
    expect(markdown).toContain("hxxp://185[.]220[.]101[.]99/update[.]php");
  });

  test("undone: an annotation reversed by /re undo no longer contributes claims", async () => {
    const entries: StubEntry[] = [
      {
        customType: "re.annotation",
        data: {
          ea: "0x401000",
          evidenceId: "",
          kind: "set_comment",
          newValue: "http://evil-test.example/payload",
          oldValue: "",
        },
        id: "ann-1",
        type: "custom",
      },
      {
        customType: "re.undo",
        data: { undidEntryId: "ann-1" },
        id: "undo-1",
        type: "custom",
      },
    ];
    const outputPath = join(tempDir, "undone.md");

    await writeReport(makeCtx(entries, []), outputPath);

    expect(process.exitCode).not.toBe(1);
    expect(await readFile(outputPath, "utf-8")).not.toContain("evil-test");
  });

  test("empty: no entries writes a trivial report without tripping the gate", async () => {
    const notifications: { message: string; type?: string }[] = [];
    const ctx = makeCtx([], notifications);
    const outputPath = join(tempDir, "empty.md");

    await writeReport(ctx, outputPath);

    expect(process.exitCode).not.toBe(1);
    expect(await fileExists(outputPath)).toBe(true);
    const markdown = await readFile(outputPath, "utf-8");
    expect(markdown).toContain("Conclusion");
  });

  test("manifest: a reproducible record renders a Verification Manifest + sidecar JSON, and a legacy record never trips the gate", async () => {
    const entries: StubEntry[] = [
      {
        customType: "re.binary",
        data: { path: "/bin/sample", sha256: "a".repeat(64) },
        type: "custom",
      },
      {
        customType: "re.evidence",
        data: {
          id: "ev-repro",
          tool: "rizin_command",
          args: { command: "iz" },
          commands: ["iz"],
          reproHash: "b".repeat(64),
          binarySha256: "a".repeat(64),
          // an IOC in the summary makes this a grounded claim that cites ev-repro
          summary: "found string: http://185.220.101.99/beacon",
        },
        type: "custom",
      },
    ];
    const outputPath = join(tempDir, "manifest.md");

    await writeReport(makeCtx(entries, []), outputPath);

    expect(process.exitCode).not.toBe(1);
    const markdown = await readFile(outputPath, "utf-8");
    expect(markdown).toContain("## Verification Manifest");
    expect(markdown).toContain(`Binary SHA-256: \`${"a".repeat(64)}\``);
    expect(markdown).toContain("reproducible");
    expect(markdown).toContain("`iz`");

    const manifest = JSON.parse(
      await readFile(`${outputPath}.manifest.json`, "utf-8")
    ) as {
      binarySha256: string | null;
      entries: {
        evidenceId: string;
        reproHash: string | null;
        status: string;
        claims: string[];
      }[];
    };
    expect(manifest.binarySha256).toBe("a".repeat(64));
    const entry = manifest.entries.find((e) => e.evidenceId === "ev-repro");
    expect(entry?.reproHash).toBe("b".repeat(64));
    expect(entry?.status).toBe("reproducible");
    expect(entry?.claims.length).toBeGreaterThan(0);
    // the structured request /re carry re-runs against another build
    expect((entry as { args?: unknown } | undefined)?.args).toEqual({
      command: "iz",
    });
  });
});

describe("writeReport — claim↔evidence support audit", () => {
  // One grounded claim: the IOC in the summary produces a single grounded IOC claim (flat index 0).
  const groundedEntries = (): StubEntry[] => [
    {
      customType: "re.binary",
      data: { path: "/bin/sample", sha256: "a".repeat(64) },
      type: "custom",
    },
    {
      customType: "re.evidence",
      data: {
        args: { command: "iz" },
        binarySha256: "a".repeat(64),
        canonicalExcerpt: "0x1 str http://185.220.101.99/beacon",
        commands: ["iz"],
        id: "ev-a",
        reproHash: "b".repeat(64),
        summary: "found string: http://185.220.101.99/beacon",
        tool: "rizin_command",
      },
      type: "custom",
    },
  ];
  const supportedAll: ClaimJudge = async (items) =>
    items.map((it): ClaimAudit => ({
      index: it.index,
      reason: "ok",
      verdict: "supported",
    }));
  const unsupportedAll =
    (reason: string): ClaimJudge =>
    async (items) =>
      items.map((it): ClaimAudit => ({
        index: it.index,
        reason,
        verdict: "unsupported",
      }));

  test("no model / no judge: audit degrades to 'unaudited', report still written, exit 0", async () => {
    const outputPath = join(tempDir, "audit-degrade.md");
    // default advisory; makeCtx has no runEphemeralTurn/model
    await writeReport(makeCtx(groundedEntries(), []), outputPath);
    expect(process.exitCode).not.toBe(1);
    const md = await readFile(outputPath, "utf-8");
    expect(md).toContain("support unaudited");
    expect(md).toContain("hxxp://185[.]220[.]101[.]99/beacon");
  });

  test("advisory: all supported -> no inline flag, a summary note, exit 0", async () => {
    const outputPath = join(tempDir, "audit-ok.md");
    await writeReport(makeCtx(groundedEntries(), []), outputPath, {
      audit: "advisory",
      judge: supportedAll,
    });
    expect(process.exitCode).not.toBe(1);
    const md = await readFile(outputPath, "utf-8");
    expect(md).not.toContain("⚠ Support audit");
    expect(md).toContain("support audit:");
    expect(md).toContain("0 flagged");
  });

  test("advisory: an unsupported claim is flagged inline, report still written, exit 0", async () => {
    const outputPath = join(tempDir, "audit-flag.md");
    await writeReport(makeCtx(groundedEntries(), []), outputPath, {
      audit: "advisory",
      judge: unsupportedAll("evidence shows only an import"),
    });
    expect(process.exitCode).not.toBe(1);
    const md = await readFile(outputPath, "utf-8");
    expect(md).toContain("⚠ Support audit: unsupported");
    expect(md).toContain("evidence shows only an import");
  });

  test("strict: an unsupported claim withholds the whole report, exit 1", async () => {
    const outputPath = join(tempDir, "audit-strict.md");
    await writeReport(makeCtx(groundedEntries(), []), outputPath, {
      audit: "strict",
      judge: unsupportedAll("misattributed"),
    });
    expect(process.exitCode).toBe(1);
    expect(await fileExists(outputPath)).toBe(false);
    const err = consoleErrorCalls.map((a) => a.join(" ")).join("\n");
    expect(err).toContain("not supported by their cited evidence");
    expect(err).toContain("misattributed");
  });

  test("a throwing judge degrades to 'unaudited' and never blocks — even in strict (fails open)", async () => {
    const judge: ClaimJudge = async () => {
      throw new Error("no active model");
    };
    const advisoryPath = join(tempDir, "audit-throw-adv.md");
    await writeReport(makeCtx(groundedEntries(), []), advisoryPath, {
      audit: "advisory",
      judge,
    });
    expect(process.exitCode).not.toBe(1);
    expect(await readFile(advisoryPath, "utf-8")).toContain(
      "support unaudited"
    );

    const strictPath = join(tempDir, "audit-throw-strict.md");
    await writeReport(makeCtx(groundedEntries(), []), strictPath, {
      audit: "strict",
      judge,
    });
    // infra failure must not fail closed
    expect(process.exitCode).not.toBe(1);
    expect(await fileExists(strictPath)).toBe(true);
  });

  test("default judge: calls ctx.runEphemeralTurn with the right options and parses its JSON reply", async () => {
    const ctx = makeCtx(groundedEntries(), []);
    let captured:
      | {
          tools?: unknown;
          dedupeReply?: unknown;
          replyMaxBytes?: unknown;
          promptText?: string;
        }
      | undefined;
    (ctx as unknown as { model: unknown }).model = { id: "test-model" };
    (ctx as unknown as { runEphemeralTurn: unknown }).runEphemeralTurn = async (
      opts: typeof captured
    ) => {
      captured = opts;
      return {
        assistantMessage: {},
        replyText:
          '```json\n[{"index":0,"verdict":"overreach","reason":"too strong"}]\n```',
      };
    };
    const outputPath = join(tempDir, "audit-eph.md");
    await writeReport(ctx, outputPath, { audit: "advisory" });
    expect(captured?.tools).toBe(false);
    expect(captured?.dedupeReply).toBe(false);
    expect(captured?.replyMaxBytes).toBe(Number.POSITIVE_INFINITY);
    expect(captured?.promptText).toContain(
      "found string: http://185.220.101.99/beacon"
    );
    expect(process.exitCode).not.toBe(1);
    expect(await readFile(outputPath, "utf-8")).toContain(
      "⚠ Support audit: overreach"
    );
  });

  test("default judge: a transport that refuses `tools: false` is retried once with the catalog sent", async () => {
    const ctx = makeCtx(groundedEntries(), []);
    const calls: unknown[] = [];
    (ctx as unknown as { model: unknown }).model = { id: "test-model" };
    (ctx as unknown as { runEphemeralTurn: unknown }).runEphemeralTurn =
      async (opts: { tools?: unknown }) => {
        calls.push(opts.tools);
        if (opts.tools === false) {
          throw new Error(
            "Model x cannot support tools: false with historical tool calls."
          );
        }
        return {
          assistantMessage: {},
          replyText:
            '[{"index":0,"verdict":"overreach","reason":"too strong"}]',
        };
      };
    const outputPath = join(tempDir, "audit-retry.md");
    await writeReport(ctx, outputPath, { audit: "advisory" });
    expect(calls).toEqual([false, undefined]);
    expect(await readFile(outputPath, "utf-8")).toContain(
      "⚠ Support audit: overreach"
    );
  });

  test("default judge: any other side-turn error is not retried and degrades to unaudited", async () => {
    const ctx = makeCtx(groundedEntries(), []);
    let calls = 0;
    (ctx as unknown as { model: unknown }).model = { id: "test-model" };
    (ctx as unknown as { runEphemeralTurn: unknown }).runEphemeralTurn =
      async () => {
        calls += 1;
        throw new Error("provider overloaded");
      };
    const outputPath = join(tempDir, "audit-noretry.md");
    await writeReport(ctx, outputPath, { audit: "advisory" });
    expect(calls).toBe(1);
    expect(await readFile(outputPath, "utf-8")).toContain("support unaudited");
  });

  test("default judge: an unparseable reply degrades to 'unaudited' and fails open even in strict", async () => {
    const ctx = makeCtx(groundedEntries(), []);
    (ctx as unknown as { model: unknown }).model = { id: "test-model" };
    (ctx as unknown as { runEphemeralTurn: unknown }).runEphemeralTurn =
      async () => ({
        assistantMessage: {},
        replyText: "I cannot produce JSON, sorry.",
      });
    const outputPath = join(tempDir, "audit-badjson.md");
    await writeReport(ctx, outputPath, { audit: "strict" });
    expect(process.exitCode).not.toBe(1);
    expect(await fileExists(outputPath)).toBe(true);
    expect(await readFile(outputPath, "utf-8")).toContain("support unaudited");
  });

  test("the existence gate runs before the audit: an ungrounded claim withholds and the judge is never called", async () => {
    let calls = 0;
    const judge: ClaimJudge = async (items) => {
      calls += 1;
      return items.map((it): ClaimAudit => ({
        index: it.index,
        reason: "",
        verdict: "supported",
      }));
    };
    const entries: StubEntry[] = [
      {
        customType: "re.annotation",
        data: {
          ea: "0x401000",
          evidenceId: "",
          kind: "comment",
          newValue: "http://evil-test.example/x",
          oldValue: "",
        },
        type: "custom",
      },
    ];
    const outputPath = join(tempDir, "audit-order.md");
    await writeReport(makeCtx(entries, []), outputPath, {
      audit: "strict",
      judge,
    });
    expect(process.exitCode).toBe(1);
    expect(await fileExists(outputPath)).toBe(false);
    expect(calls).toBe(0);
  });
});
