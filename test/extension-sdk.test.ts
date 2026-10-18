/**
 * Loads extensions/re through omp's real SDK and extension runner — the same
 * loader, tool wrappers (approval, tool_call/tool_result events), and command
 * dispatch an interactive session uses — instead of a stub ExtensionAPI.
 * Nothing here calls a model: slash commands are handled locally and tools
 * are executed straight from the session's tool registry.
 *
 * This is the suite that catches host API drift (e.g. omp 18 changing
 * getAllTools() from names to ToolInfo objects broke `/re on` while every
 * stub-based test stayed green). The rizin-free half runs in CI.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import type { AgentSession } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";

import {
  RE_ALL_TOOL_NAMES,
  RE_ANALYZE_TOOL_NAMES,
  RE_EMULATE_TOOL_NAMES,
  RE_MUTATE_TOOL_NAMES,
  RE_READ_TOOL_NAMES,
  RE_RIZIN_TOOL_NAMES,
  RE_SESSION_TOOL_NAMES,
  RE_SIGNATURE_TOOL_NAMES,
} from "../extensions/re/audit.ts";
import { REQUIRED_COMMANDS } from "../extensions/re/catalog.ts";
import { canRunRizin, logSkip, rmDirSafe, TEST_BINARY } from "./helpers.ts";

logSkip("extension-sdk rizin tests");

const EXTENSION = resolve(import.meta.dir, "../extensions/re");
/** The tools registered unconditionally in every session. Triage, rizin_cli, and debug are conditional (binary on PATH / env opt-in), so they are excluded here. */
const ALWAYS_REGISTERED = [
  ...Object.keys(RE_READ_TOOL_NAMES),
  ...Object.keys(RE_MUTATE_TOOL_NAMES),
  ...Object.keys(RE_RIZIN_TOOL_NAMES),
  ...Object.keys(RE_EMULATE_TOOL_NAMES),
  ...Object.keys(RE_SIGNATURE_TOOL_NAMES),
  ...Object.keys(RE_ANALYZE_TOOL_NAMES),
  ...Object.keys(RE_SESSION_TOOL_NAMES),
];

interface Harness {
  session: AgentSession;
  notes: string[];
  editor: () => string;
  shutdown: () => Promise<void>;
}

/** A minimal ExtensionUIContext: records what the extension tells the user, renders nothing. */
function makeUi(notes: string[], editor: { text: string }) {
  const noop = () => {};
  return {
    addAutocompleteProvider: noop,
    confirm: async () => true,
    custom: async () => {},
    editor: async () => {},
    getAllThemes: async () => [],
    getEditorText: () => editor.text,
    getTheme: async () => {},
    getToolsExpanded: () => false,
    input: async () => {},
    notify: (message: string, type?: string) =>
      notes.push(`[${type ?? "info"}] ${message}`),
    onTerminalInput: () => noop,
    pasteToEditor: noop,
    select: async () => {},
    setEditorComponent: noop,
    setEditorText: (text: string) => {
      editor.text = text;
    },
    setFooter: noop,
    setHeader: noop,
    setStatus: noop,
    setTheme: async () => ({ success: true }),
    setTitle: noop,
    setToolsExpanded: noop,
    setWidget: noop,
    setWorkingMessage: noop,
  };
}

async function boot(sessionManager: unknown): Promise<Harness> {
  const sdk = await import("@oh-my-pi/pi-coding-agent");
  const { initializeExtensions } =
    await import("@oh-my-pi/pi-coding-agent/modes/runtime-init");
  const notes: string[] = [];
  const editor = { text: "" };
  const ui = makeUi(notes, editor);
  const { session, extensionsResult, setToolUIContext } =
    await sdk.createAgentSession({
      additionalExtensionPaths: [EXTENSION],
      cwd: tmpdir(),
      disableExtensionDiscovery: true,
      sessionManager: sessionManager as never,
    });
  expect(extensionsResult.errors).toEqual([]);
  setToolUIContext(ui as never, false);
  await initializeExtensions(session, {
    reportRuntimeError: (error: { error: string }) =>
      notes.push(`[runtime] ${error.error}`),
    reportSendError: () => {},
    uiContext: ui as never,
  });
  return {
    editor: () => editor.text,
    notes,
    session,
    shutdown: () => session.dispose(),
  };
}

const activeRe = (session: AgentSession) =>
  session.getActiveToolNames().filter((name) => RE_ALL_TOOL_NAMES[name]);

let agentDir: string;
let originalAgentDir: string;

beforeAll(async () => {
  originalAgentDir = getAgentDir();
  agentDir = await mkdtemp(join(tmpdir(), "omp-re-sdk-test-"));
  setAgentDir(agentDir);
});

afterAll(async () => {
  setAgentDir(originalAgentDir);
  rmDirSafe(agentDir);
});

describe("loaded by omp's SDK (no rizin needed)", () => {
  let h: Harness;

  beforeAll(async () => {
    const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
    h = await boot(SessionManager.inMemory());
  });

  afterAll(async () => {
    await h.shutdown();
  });

  test("registers every non-triage RE tool, all active", () => {
    for (const name of ALWAYS_REGISTERED) {
      expect(h.session.getToolByName(name)).toBeDefined();
    }
    expect(activeRe(h.session).toSorted()).toEqual(
      expect.arrayContaining(ALWAYS_REGISTERED.toSorted())
    );
  });

  test("/re off deactivates every RE tool and /re on brings them all back", async () => {
    await h.session.prompt("/re off");
    expect(activeRe(h.session)).toEqual([]);
    await h.session.prompt("/re on");
    expect(activeRe(h.session).toSorted()).toEqual(
      expect.arrayContaining(ALWAYS_REGISTERED.toSorted())
    );
    expect(h.notes.at(-1)).toBe(
      "[info] omp-re: RE tools enabled for this session"
    );
  });

  test("/re completes subcommands", () => {
    const command = h.session.extensionRunner!.getCommand("re")!;
    expect(command.getArgumentCompletions!("st")).toEqual([
      expect.objectContaining({ label: "strings", value: "strings " }),
      expect.objectContaining({ label: "status", value: "status " }),
    ]);
  });

  test("bare /re shows help, an unknown subcommand is an error, and undo with nothing open says so", async () => {
    await h.session.prompt("/re");
    expect(h.notes.at(-1)).toContain("/re open <path>      open a binary");
    await h.session.prompt("/re bogus");
    expect(h.notes.at(-1)).toBe(
      '[error] omp-re: unknown /re subcommand "bogus" — try /re help'
    );
    await h.session.prompt("/re undo");
    expect(h.notes.at(-1)).toBe("[error] omp-re: no annotation left to undo");
  });

  test("a tool called with no binary open fails with omp-re's guidance", async () => {
    await expect(
      h.session.getToolByName("list_functions")!.execute("t-nobin", {})
    ).rejects.toThrow("omp-re: no binary open");
  });
});

describe.skipIf(!canRunRizin)("loaded by omp's SDK, against rizin", () => {
  // Opens the binary (full `aaa`) once, then replays into a freshly reopened
  // session (another `aaa`); on a cold CI/container host each analysis is a
  // few seconds, so the default 5s budget is too tight.
  test("open, annotate, and resume: the reopened session replays the annotation into a fresh rizin", async () => {
    const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
    const sessionDir = join(agentDir, "sessions");
    const first = await boot(SessionManager.create(tmpdir(), sessionDir));
    await first.session.sessionManager.ensureOnDisk();
    const run = (h: Harness, name: string, params: Record<string, unknown>) =>
      h.session.getToolByName(name)!.execute(`t-${name}`, params);

    await run(first, "open_binary", { path: TEST_BINARY });
    await run(first, "rename_function", {
      addr: "main",
      new: "omp_re_sdk_main",
    });
    const file = first.session.sessionManager.getSessionFile()!;
    await first.shutdown();

    const second = await boot(await SessionManager.open(file));
    try {
      const result = await run(second, "get_function", {
        target: "omp_re_sdk_main",
      });
      expect(
        result.content[0]?.type === "text" &&
          result.content[0].text.startsWith("omp_re_sdk_main at 0x")
      ).toBe(true);
      expect(second.notes.filter((n) => n.startsWith("[runtime]"))).toEqual([]);
    } finally {
      await second.shutdown();
    }
  }, 30_000);

  test("/re status reports the rizin compatibility check, and rizin_command runs through the host", async () => {
    const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
    const h = await boot(SessionManager.inMemory());
    try {
      await h.session
        .getToolByName("open_binary")!
        .execute("t-open", { path: TEST_BINARY });
      await h.session.prompt("/re status");
      // The count is REQUIRED_COMMANDS.length, which grows as tool families
      // are added; assert the shape, not a frozen number.
      expect(h.notes.at(-1)).toContain(
        `rizin commands: all ${REQUIRED_COMMANDS.length} omp-re sends are present`
      );
      const result = await h.session
        .getToolByName("rizin_command")!
        .execute("t-rz", { addr: "main", command: "pdsf" });
      expect(
        result.content[0]?.type === "text" &&
          result.content[0].text.startsWith("rizin> pdsf @ main\n")
      ).toBe(true);
      // rizin_cli registers through the real runner when the rz-* tools are present (they ship with rizin).
      expect(h.session.getToolByName("rizin_cli")).toBeDefined();
    } finally {
      await h.shutdown();
    }
  });

  test("the debugger registers through the real runner only when opted in, and its enum schema loads", async () => {
    const { SessionManager } = await import("@oh-my-pi/pi-coding-agent");
    const off = await boot(SessionManager.inMemory());
    try {
      expect(off.session.getToolByName("rizin_debug")).toBeUndefined();
    } finally {
      await off.shutdown();
    }

    const prev = process.env.OMPRE_ENABLE_DEBUGGER;
    process.env.OMPRE_ENABLE_DEBUGGER = "1";
    const on = await boot(SessionManager.inMemory());
    try {
      expect(on.session.getToolByName("rizin_debug")).toBeDefined();
      await on.session
        .getToolByName("open_binary")!
        .execute("t-open", { path: TEST_BINARY });
      const started = await on.session
        .getToolByName("rizin_debug")!
        .execute("t-dbg", { action: "start" });
      expect(
        started.content[0]?.type === "text" && started.content[0].text
      ).toContain("RUNNING under a debugger");
      await on.session
        .getToolByName("rizin_debug")!
        .execute("t-dbg-stop", { action: "stop" });
    } finally {
      await on.shutdown();
      if (prev === undefined) {
        delete process.env.OMPRE_ENABLE_DEBUGGER;
      } else {
        process.env.OMPRE_ENABLE_DEBUGGER = prev;
      }
    }
    // two full SDK boots plus a real launch; the default 5s is too tight
  }, 30_000);
});
