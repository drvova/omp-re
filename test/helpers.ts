/**
 * Shared test harness: fixture detection and a stub ExtensionAPI/context pair
 * that records registered tools and keeps an in-memory session branch and
 * artifact store, so tool definitions can be executed exactly as omp would
 * call them: execute(toolCallId, params, signal, onUpdate, ctx).
 */
import { existsSync, rmSync } from "node:fs";

// The schema builder omp 18 injects as `pi.zod` (see pi-coding-agent extensions/loader.ts).
import * as zod from "@oh-my-pi/omptype/zod";
import type {
  ExtensionAPI,
  ExtensionContext,
  ToolDefinition,
} from "@oh-my-pi/pi-coding-agent";

import { resolveRizinPath, resolveRizinTool } from "../extensions/re/rizin.ts";

/** Any readable binary works; /bin/ls exists on every Linux host and macOS. Override with OMPRE_TEST_BINARY. */
export const TEST_BINARY = process.env.OMPRE_TEST_BINARY ?? "/bin/ls";
export const rizinPath = resolveRizinPath();
export const rizinAvailable = rizinPath.includes("/")
  ? existsSync(rizinPath)
  : Bun.which(rizinPath) !== null;
export const binaryAvailable = existsSync(TEST_BINARY);
export const canRunRizin = rizinAvailable && binaryAvailable;

/** Whether a sibling rizin CLI tool (`rz-bin`, `rz-diff`, …) is present next to the configured rizin or on PATH. */
export function isRzToolAvailable(tool: string): boolean {
  const path = resolveRizinTool(tool);
  return path.includes("/") ? existsSync(path) : Bun.which(path) !== null;
}

export function logSkip(suite: string): void {
  if (canRunRizin) {
    return;
  }
  const reasons = [
    ...(rizinAvailable ? [] : [`rizin ("${rizinPath}") not on PATH`]),
    ...(binaryAvailable
      ? []
      : [`test binary not found at ${TEST_BINARY} (set OMPRE_TEST_BINARY)`]),
  ];
  console.log(`omp-re: skipping ${suite} — ${reasons.join("; ")}`);
}

/**
 * Remove a temp dir recursively, tolerating the Windows lag between killing a
 * rizin child that held a file open and the OS releasing the handle — until
 * then `rm` throws EBUSY. Node's own maxRetries/retryDelay back-off covers it;
 * on POSIX there is nothing to retry. It is only teardown, so a residual
 * failure is swallowed rather than failing an otherwise-green test.
 */
export function rmDirSafe(dir: string): void {
  try {
    rmSync(dir, {
      force: true,
      maxRetries: 15,
      recursive: true,
      retryDelay: 100,
    });
  } catch {
    // A temp dir the OS will reclaim; never worth failing a green run over.
  }
}

export interface StubEntry {
  type: "custom";
  id: string;
  customType: string;
  data: unknown;
}

export interface Harness {
  pi: ExtensionAPI;
  ctx: ExtensionContext;
  /** The session branch, root to leaf. Tests may splice it to simulate /tree navigation. */
  entries: StubEntry[];
  artifacts: Map<string, string>;
  notifications: { message: string; type?: string }[];
  tool: (name: string) => ToolDefinition<any, any>;
}

export function makeHarness(sessionId: string): Harness {
  const entries: StubEntry[] = [];
  const artifacts = new Map<string, string>();
  const notifications: { message: string; type?: string }[] = [];
  const tools = new Map<string, ToolDefinition<any, any>>();
  let counter = 0;

  const noop = () => {};
  const pi = {
    zod,
    logger: { debug: noop, error: noop, info: noop, warn: noop },
    registerTool: (def: ToolDefinition<any, any>) => {
      tools.set(def.name, def);
    },
    appendEntry: (customType: string, data?: unknown) => {
      const id = `entry-${counter}`;
      counter += 1;
      entries.push({ customType, data, id, type: "custom" });
    },
    on: noop,
    // A real argv exec (no shell), matching omp's pi.exec shape, so the rz-* CLI tools run against the actual binaries in tests.
    exec: async (
      bin: string,
      argv: string[],
      opts?: { signal?: AbortSignal }
    ) => {
      const proc = Bun.spawn([bin, ...argv], {
        signal: opts?.signal,
        stderr: "pipe",
        stdout: "pipe",
      });
      const [stdout, stderr] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
      const code = await proc.exited;
      return { code, stderr, stdout };
    },
  } as unknown as ExtensionAPI;

  const ctx = {
    hasUI: false,
    sessionManager: {
      getArtifactPath: async () => null,
      getBranch: () => entries,
      getEntries: () => entries,
      getSessionId: () => sessionId,
      saveArtifact: async (content: string) => {
        const id = String(artifacts.size);
        artifacts.set(id, content);
        return id;
      },
    },
    ui: {
      notify: (message: string, type?: string) => {
        notifications.push({ message, type });
      },
    },
  } as unknown as ExtensionContext;

  return {
    artifacts,
    ctx,
    entries,
    notifications,
    pi,
    tool(name: string) {
      const def = tools.get(name);
      if (!def) {
        throw new Error(
          `omp-re test setup: tool "${name}" was never registered`
        );
      }
      return def;
    },
  };
}

export function textOf(result: {
  content: { type: string; text?: string }[];
}): string {
  const [block] = result.content;
  if (!block || block.type !== "text" || typeof block.text !== "string") {
    throw new Error("expected a text content block");
  }
  return block.text;
}

/** Splits a tool result's text into its header line and the remaining body. */
export function splitHeaderBody(text: string): {
  header: string;
  body: string;
} {
  const nl = text.indexOf("\n");
  if (nl === -1) {
    return { body: "", header: text };
  }
  return { body: text.slice(nl + 1), header: text.slice(0, nl) };
}

/** Awaits a promise expected to reject and returns the rejection, for exact `.message` assertions. */
export async function captureError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
  throw new Error("expected the promise to reject, but it resolved");
}
