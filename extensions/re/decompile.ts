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

export type DecompilerKind = "pdg" | "pdd";

export interface DecompileOutcome {
	/** The decompiler that produced `code`, or "disasm" when none did. */
	kind: DecompilerKind | "disasm";
	code: string;
	/** For kind "disasm": the exact label the output carries (one of the *_PREFIX constants). */
	prefix?: string;
}

/** Exact formatting matters (em dash U+2014, one trailing space): the re-triage skill and WATCHDOG.md quote this literal so the model and an advisor can tell a fallback from a real decompile. */
export const DISASM_ONLY_PREFIX = "(disassembly only — no decompiler plugin available) ";

/** The other honest fallback: a decompiler is installed but produced nothing for this function. */
export const DECOMPILER_EMPTY_PREFIX = "(disassembly only — the decompiler produced no output for this function) ";

/** A real decompile (pdg especially — full Ghidra Sleigh analysis) can run far longer than a plain rizin command. */
const DECOMPILE_TIMEOUT_MS = 180_000;

/** Ordered probe table: rz-ghidra's `pdg` first, then jsdec's `pdd`. */
const DECOMPILER_PROBES: readonly { kind: DecompilerKind; helpCommand: string }[] = [
	{ kind: "pdg", helpCommand: "pdg?" },
	{ kind: "pdd", helpCommand: "pdd?" },
];

/** Never infer presence from anything short of the command's own help text. */
function isAvailableReply(reply: string): boolean {
	const trimmed = reply.trim();
	return trimmed.length > 0 && !trimmed.includes("does not exist") && !trimmed.startsWith("ERROR");
}

/**
 * Per-session decompiler tier. A WeakMap drops a closed session's entry for
 * free, and a fresh RzSession (e.g. after a respawn) always re-probes. Only a
 * definitive answer is cached: a probe that threw (timeout, abort, closed
 * process) leaves the cache empty so the next call probes again, rather than
 * pinning the whole session to the disassembly fallback over one bad moment.
 */
const kindBySession = new WeakMap<RzSession, DecompilerKind | null>();

export async function resolveDecompiler(rz: RzSession, signal?: AbortSignal): Promise<DecompilerKind | null> {
	if (kindBySession.has(rz)) return kindBySession.get(rz) ?? null;
	for (const probe of DECOMPILER_PROBES) {
		if (isAvailableReply(await rz.cmd(probe.helpCommand, { signal }))) {
			kindBySession.set(rz, probe.kind);
			return probe.kind;
		}
	}
	kindBySession.set(rz, null);
	return null;
}

/**
 * Decompile the function at `ea` with the best available plugin, falling back
 * to labeled annotated disassembly. Returns null when there is no function at
 * `ea` at all.
 */
export async function decompileAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<DecompileOutcome | null> {
	const kind = await resolveDecompiler(rz, signal);
	if (kind) {
		const code = (await rz.cmd(`${kind} @ ${ea}`, { timeoutMs: DECOMPILE_TIMEOUT_MS, signal })).replace(/^\n+/, "");
		if (code.trim().length > 0) return { kind, code };
	}
	const disasm = await disassembleAt(rz, ea, signal);
	if (!disasm) return null;
	const prefix = kind ? DECOMPILER_EMPTY_PREFIX : DISASM_ONLY_PREFIX;
	return { kind: "disasm", code: disasm.lines.join("\n"), prefix };
}
