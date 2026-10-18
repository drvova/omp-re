import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";

import {
  RE_ALL_TOOL_NAMES,
  RE_MUTATE_TOOL_NAMES,
  RE_DEBUG_TOOL_NAMES,
  RE_ANALYZE_TOOL_NAMES,
  RE_EMULATE_TOOL_NAMES,
  RE_EVIDENCE_TOOL_NAMES,
  RE_FINDING_TOOL_NAMES,
  RE_SIGNATURE_TOOL_NAMES,
  RE_READ_TOOL_NAMES,
  RE_RIZIN_TOOL_NAMES,
  RE_RZCLI_TOOL_NAMES,
  RE_SESSION_TOOL_NAMES,
  RE_TRIAGE_TOOL_NAMES,
  registerAuditLog,
} from "../extensions/re/audit.ts";

describe("RE_ALL_TOOL_NAMES", () => {
  test("contains exactly 64 names and is the union of read (31), mutate (15), rizin (2), rizin CLI (1), triage (4), debug (1), emulate (1), signature (2), analyze (1), session (3), and finding (3)", () => {
    expect(Object.keys(RE_READ_TOOL_NAMES)).toHaveLength(31);
    expect(Object.keys(RE_MUTATE_TOOL_NAMES)).toHaveLength(15);
    expect(Object.keys(RE_RIZIN_TOOL_NAMES)).toHaveLength(2);
    expect(Object.keys(RE_RZCLI_TOOL_NAMES)).toHaveLength(1);
    expect(Object.keys(RE_TRIAGE_TOOL_NAMES)).toHaveLength(4);
    expect(Object.keys(RE_DEBUG_TOOL_NAMES)).toHaveLength(1);
    expect(Object.keys(RE_EMULATE_TOOL_NAMES)).toHaveLength(1);
    expect(Object.keys(RE_SIGNATURE_TOOL_NAMES)).toHaveLength(2);
    expect(Object.keys(RE_ANALYZE_TOOL_NAMES)).toHaveLength(1);
    expect(Object.keys(RE_SESSION_TOOL_NAMES)).toHaveLength(3);
    expect(Object.keys(RE_FINDING_TOOL_NAMES)).toHaveLength(3);

    const allNames = Object.keys(RE_ALL_TOOL_NAMES);
    expect(allNames).toHaveLength(64);

    const expectedUnion = new Set([
      ...Object.keys(RE_READ_TOOL_NAMES),
      ...Object.keys(RE_MUTATE_TOOL_NAMES),
      ...Object.keys(RE_RIZIN_TOOL_NAMES),
      ...Object.keys(RE_RZCLI_TOOL_NAMES),
      ...Object.keys(RE_TRIAGE_TOOL_NAMES),
      ...Object.keys(RE_DEBUG_TOOL_NAMES),
      ...Object.keys(RE_EMULATE_TOOL_NAMES),
      ...Object.keys(RE_SIGNATURE_TOOL_NAMES),
      ...Object.keys(RE_ANALYZE_TOOL_NAMES),
      ...Object.keys(RE_SESSION_TOOL_NAMES),
      ...Object.keys(RE_FINDING_TOOL_NAMES),
    ]);
    expect(new Set(allNames)).toEqual(expectedUnion);
  });

  test("the search / types / syscall / binary-info read tools ground evidence (not just the original twelve)", () => {
    for (const name of [
      "search_bytes",
      "search_value",
      "search_gadgets",
      "list_types",
      "cast_memory",
      "list_syscalls",
      "get_binary_info",
      "list_flags",
      "list_classes",
    ]) {
      expect(RE_EVIDENCE_TOOL_NAMES[name]).toBe(true);
      expect(RE_ALL_TOOL_NAMES[name]).toBe(true);
    }
  });

  test("the emulator, debugger, signature-apply, and analyze tools are audited and toggled by /re off, but never recorded as evidence", () => {
    for (const name of [
      "rizin_emulate",
      "rizin_debug",
      "apply_signatures",
      "analyze",
    ]) {
      expect(RE_ALL_TOOL_NAMES[name]).toBe(true);
      expect(RE_EVIDENCE_TOOL_NAMES[name]).toBeUndefined();
    }
  });
});

type Handler = (
  event: Record<string, unknown>,
  ctx: ExtensionContext
) => Promise<void>;

/** Captures the handlers registerAuditLog installs, plus whatever it logs through pi.logger, without a real ExtensionAPI. */
const captureHandlers = (): {
  toolCall: Handler;
  approval: Handler;
  warnings: string[];
} => {
  const handlers = new Map<string, Handler>();
  const warnings: string[] = [];
  const fakePi = {
    logger: {
      error: (msg: string) => warnings.push(msg),
      warn: (msg: string) => warnings.push(msg),
    },
    on: (event: string, handler: Handler) => {
      handlers.set(event, handler);
    },
  } as unknown as ExtensionAPI;
  registerAuditLog(fakePi);
  const toolCall = handlers.get("tool_call");
  const approval = handlers.get("tool_approval_resolved");
  if (!toolCall || !approval) {
    throw new Error("registerAuditLog did not register its handlers");
  }
  return { approval, toolCall, warnings };
};

const makeCtx = (
  sessionId: string,
  notifications: { message: string; type?: string }[]
): ExtensionContext =>
  ({
    hasUI: false,
    sessionManager: {
      getSessionId: () => sessionId,
    },
    ui: {
      notify: (message: string, type?: string) => {
        notifications.push({ message, type });
      },
    },
  }) as unknown as ExtensionContext;

const readAuditLines = async (sessionId: string): Promise<string[]> => {
  const path = nodePath.join(getAgentDir(), "re", "audit", `${sessionId}.log`);
  const raw = await readFile(path, "utf-8");
  return raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
};

describe("audit log", () => {
  let tempDir: string;
  let originalAgentDir: string;
  const originalHmacKey = process.env.OMPRE_AUDIT_HMAC_KEY;

  beforeEach(async () => {
    originalAgentDir = getAgentDir();
    tempDir = await mkdtemp(nodePath.join(tmpdir(), "omp-re-audit-test-"));
    setAgentDir(tempDir);
  });

  afterEach(async () => {
    setAgentDir(originalAgentDir);
    await rm(tempDir, { force: true, recursive: true });
    if (originalHmacKey === undefined) {
      delete process.env.OMPRE_AUDIT_HMAC_KEY;
    } else {
      process.env.OMPRE_AUDIT_HMAC_KEY = originalHmacKey;
    }
  });

  test("with OMPRE_AUDIT_HMAC_KEY set, an appended line carries a non-empty hmac field that verifies", async () => {
    process.env.OMPRE_AUDIT_HMAC_KEY = "test-hmac-key";
    const sessionId = "audit-signed-session";
    const { toolCall: handler } = captureHandlers();
    const notifications: { message: string; type?: string }[] = [];
    const ctx = makeCtx(sessionId, notifications);

    await handler(
      {
        input: { path: "/tmp/x" },
        toolCallId: "call-1",
        toolName: "hash_binary",
        type: "tool_call",
      },
      ctx
    );

    const lines = await readAuditLines(sessionId);
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!) as {
      hmac?: string;
      [key: string]: unknown;
    };
    expect(typeof parsed.hmac).toBe("string");
    expect(parsed.hmac!.length).toBeGreaterThan(0);

    const { hmac, ...rest } = parsed;
    const expectedHmac = createHmac("sha256", "test-hmac-key")
      .update(JSON.stringify(rest))
      .digest("base64");
    expect(hmac).toBe(expectedHmac);
  });

  test("with the key unset, lines are still written and the warning fires exactly once per session", async () => {
    delete process.env.OMPRE_AUDIT_HMAC_KEY;
    const sessionId = "audit-unsigned-session";
    const { toolCall: handler, warnings } = captureHandlers();
    const notifications: { message: string; type?: string }[] = [];
    const ctx = makeCtx(sessionId, notifications);

    await handler(
      {
        input: {},
        toolCallId: "call-1",
        toolName: "hash_binary",
        type: "tool_call",
      },
      ctx
    );
    await handler(
      {
        input: {},
        toolCallId: "call-2",
        toolName: "list_functions",
        type: "tool_call",
      },
      ctx
    );
    await handler(
      {
        input: {},
        toolCallId: "call-3",
        toolName: "list_imports",
        type: "tool_call",
      },
      ctx
    );

    const lines = await readAuditLines(sessionId);
    expect(lines).toHaveLength(3);
    for (const line of lines) {
      const parsed = JSON.parse(line) as { hmac?: string };
      expect(parsed.hmac).toBeUndefined();
    }

    // Headless: the one-time warning goes to omp's log, not stdout/stderr.
    expect(
      warnings.filter((msg) =>
        msg.includes("OMPRE_AUDIT_HMAC_KEY not configured")
      )
    ).toHaveLength(1);
  });

  test("non-RE tool calls are not audited", async () => {
    const sessionId = "audit-non-re-session";
    const { toolCall: handler } = captureHandlers();
    const ctx = makeCtx(sessionId, []);
    await handler(
      {
        input: { command: "ls" },
        toolCallId: "call-1",
        toolName: "bash",
        type: "tool_call",
      },
      ctx
    );
    await handler(
      {
        input: {},
        toolCallId: "call-2",
        toolName: "hash_binary",
        type: "tool_call",
      },
      ctx
    );
    const readAuditLinesResult = await readAuditLines(sessionId);
    expect(
      readAuditLinesResult.map((l) => (JSON.parse(l) as { tool: string }).tool)
    ).toEqual(["hash_binary"]);
  });

  test("an approval decision for an RE tool is recorded next to its call", async () => {
    const sessionId = "audit-approval-session";
    const { approval } = captureHandlers();
    const ctx = makeCtx(sessionId, []);
    await approval(
      {
        approved: false,
        reason: "user denied",
        sessionId,
        toolCallId: "call-9",
        toolName: "rename_function",
        type: "tool_approval_resolved",
      },
      ctx
    );
    await approval(
      {
        approved: true,
        sessionId,
        toolCallId: "call-10",
        toolName: "bash",
        type: "tool_approval_resolved",
      },
      ctx
    );
    const rawLines = await readAuditLines(sessionId);
    const lines = rawLines.map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      approved: false,
      reason: "user denied",
      tool: "rename_function",
      toolCallId: "call-9",
    });
  });
});
