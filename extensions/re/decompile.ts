/**
 * Decompiler capability probing and invocation.
 *
 * rizin ships no decompiler of its own. Real decompilers are optional
 * plugins: rz-ghidra (`pdg`) and jsdec (`pdd`). When a plugin isn't loaded,
 * rizin answers its help form (`pdg?`/`pdd?`) with an empty frame and an
 * error on stderr — that is the "not available" signature probed for here.
 * Never assume a plugin exists; always probe at runtime and degrade honestly
 * to annotated disassembly, labeled as such.
 */
import { disassembleAt } from "./disasm.ts";
import type { RzSession } from "./rizin.ts";
import { firstInSequence, inSequence } from "./sequence.ts";

/**
 * A decompiler is identified by the rizin command that runs it. The two known
 * plugins have stable names (rz-ghidra `pdg`, jsdec `pdd`), kept as a type for
 * the display labels and tests; any other value is a user-configured plugin
 * command probed the same way.
 */
export type DecompilerKind = "pdg" | "pdd" | (string & {});

export interface DecompileOutcome {
  /** The decompiler that produced `code`, or "disasm" when none did. */
  kind: DecompilerKind | "disasm";
  code: string;
  /** For kind "disasm": the exact label the output carries (one of the *_PREFIX constants). */
  prefix?: string;
}

/** Exact formatting matters (em dash U+2014, one trailing space): the re-triage skill and WATCHDOG.md quote this literal so the model and an advisor can tell a fallback from a real decompile. */
export const DISASM_ONLY_PREFIX =
  "(disassembly only — no decompiler plugin available) ";

/** The other honest fallback: a decompiler is installed but produced nothing for this function. */
export const DECOMPILER_EMPTY_PREFIX =
  "(disassembly only — the decompiler produced no output for this function) ";

/** A real decompile (pdg especially — full Ghidra Sleigh analysis) can run far longer than a plain rizin command. */
const DECOMPILE_TIMEOUT_MS = 180_000;

/** The built-in probe order: rz-ghidra's `pdg` first, then jsdec's `pdd`. */
const DEFAULT_DECOMPILER_COMMANDS: readonly DecompilerKind[] = ["pdg", "pdd"];

/**
 * The decompiler commands to probe, in priority order. `OMPRE_DECOMPILER` is a
 * comma-separated list that overrides it — put a preferred plugin first, or
 * name a decompiler plugin omp-re doesn't know (any rizin plugin that adds a
 * `pdX`-style command works, since probing is generic). The two built-ins are
 * appended as a fallback unless already named, so setting it only ever adds or
 * reorders, never silently removes a working decompiler. A single bare word
 * (e.g. `pdg`) simply forces that one first.
 */
export const decompilerCommands = (): DecompilerKind[] => {
  const configured = (process.env.OMPRE_DECOMPILER ?? "")
    .split(",")
    .map((name) => name.trim())
    .filter((name) => /^[a-zA-Z][a-zA-Z0-9]*$/u.test(name));
  const ordered: DecompilerKind[] = [];
  for (const name of [...configured, ...DEFAULT_DECOMPILER_COMMANDS]) {
    if (!ordered.includes(name)) {
      ordered.push(name);
    }
  }
  return ordered;
};

/** A human label for a decompiler command (the two known plugins get their names; anything else is shown as its command). */
export const decompilerLabel = (kind: DecompilerKind | null): string => {
  if (kind === "pdg") {
    return "rz-ghidra (pdg)";
  }
  if (kind === "pdd") {
    return "jsdec (pdd)";
  }
  return kind
    ? `${kind} (plugin)`
    : "none — decompile_function returns labeled disassembly";
};

/** Never infer presence from anything short of the command's own help text. */
const isAvailableReply = (reply: string): boolean => {
  const trimmed = reply.trim();
  return (
    trimmed.length > 0 &&
    !trimmed.includes("does not exist") &&
    !trimmed.startsWith("ERROR")
  );
};

/** Every decompiler command whose plugin is actually loaded in this rizin, in priority order (for `/re status` and diagnostics). */
export const availableDecompilers = async (
  rz: RzSession,
  signal?: AbortSignal
): Promise<DecompilerKind[]> => {
  const found: DecompilerKind[] = [];
  await inSequence(decompilerCommands(), async (command) => {
    if (isAvailableReply(await rz.cmd(`${command}?`, { signal }))) {
      found.push(command);
    }
  });
  return found;
};

/**
 * Per-session decompiler tier. A WeakMap drops a closed session's entry for
 * free, and a fresh RzSession (e.g. after a respawn) always re-probes. Only a
 * definitive answer is cached: a probe that threw (timeout, abort, closed
 * process) leaves the cache empty so the next call probes again, rather than
 * pinning the whole session to the disassembly fallback over one bad moment.
 */
const kindBySession = new WeakMap<RzSession, DecompilerKind | null>();

export const resolveDecompiler = async (
  rz: RzSession,
  signal?: AbortSignal
): Promise<DecompilerKind | null> => {
  if (kindBySession.has(rz)) {
    return kindBySession.get(rz) ?? null;
  }
  // Probe in priority order and stop at the first plugin that answers.
  const found = await firstInSequence(decompilerCommands(), async (command) =>
    isAvailableReply(await rz.cmd(`${command}?`, { signal }))
      ? command
      : undefined
  );
  kindBySession.set(rz, found ?? null);
  return found ?? null;
};

/**
 * Decompile the function at `ea` with the best available plugin, falling back
 * to labeled annotated disassembly. Returns null when there is no function at
 * `ea` at all.
 */
export const decompileAt = async (
  rz: RzSession,
  ea: string,
  signal?: AbortSignal
): Promise<DecompileOutcome | null> => {
  const kind = await resolveDecompiler(rz, signal);
  if (kind) {
    const rawCode = await rz.cmd(`${kind} @ ${ea}`, {
      signal,
      timeoutMs: DECOMPILE_TIMEOUT_MS,
    });
    const code = rawCode.replaceAll("\r\n", "\n").replace(/^\n+/u, "");
    if (code.trim().length > 0) {
      return { code, kind };
    }
  }
  const disasm = await disassembleAt(rz, ea, signal);
  if (!disasm) {
    return null;
  }
  const prefix = kind ? DECOMPILER_EMPTY_PREFIX : DISASM_ONLY_PREFIX;
  return { code: disasm.lines.join("\n"), kind: "disasm", prefix };
};
