/**
 * Mapping additional files into the session's address space (book:
 * basic_commands/mapping_files).
 *
 * `map_file` opens a second file — a memory dump, a shared library, a raw blob
 * — at a virtual address alongside the primary binary, so it can be analyzed
 * in the same session (overlay an unpacked region over the packed image, bring
 * in a library for cross-module xrefs). The map lives in the rizin process, so
 * — like analysis passes and signatures — it is recorded as a `re.mapfile`
 * entry and re-applied on every respawn/resume ({@link replayMapFiles} +
 * runtime.ts), before the analysis passes so they can see the mapped region.
 * It is not an undoable annotation: reopen the binary to return to the
 * baseline.
 *
 * The file is opened with `o` (never `o+`), so it is mapped read-only and the
 * file on disk is never written. The path is single-quoted so a path with odd
 * characters cannot inject a second command; the address and permission are
 * validated.
 */
import { rzQuote, validateAddr } from "./rizin.ts";
import type { RzSession } from "./rizin.ts";
import { inSequence } from "./sequence.ts";

export interface MapFile {
  path: string;
  addr: string;
  perm?: string;
}

/** Validate an IO-map permission string (`r`, `rw`, `rwx`, …) — the access the mapped VA region allows, not a file write mode. */
export const validateMapPerm = (perm: string): string => {
  if (!/^[rwx]+$/u.test(perm)) {
    throw new Error(
      `omp-re: map_file: invalid permission ${JSON.stringify(perm)} — use r, w, x characters (e.g. r, rw, rx)`
    );
  }
  return perm;
};

/** The `o <file> <addr> [<perm>]` command that maps `m`. `o` (not `o+`) keeps the file read-only on disk; the path is single-quoted and the address validated. */
export const mapFileCommand = (m: MapFile): string =>
  `o ${rzQuote(m.path)} ${validateAddr(m.addr)}${m.perm ? ` ${validateMapPerm(m.perm)}` : ""}`;

/** Re-apply `maps` to a freshly spawned process, in order. A map that no longer applies (the file moved since it was recorded) is reported rather than aborting the rest. */
export const replayMapFiles = async (
  rz: RzSession,
  maps: readonly MapFile[]
): Promise<string[]> => {
  const failures: string[] = [];
  await inSequence(maps, async (m) => {
    try {
      await rz.cmd(mapFileCommand(m));
    } catch (error) {
      failures.push(
        `map ${m.path} @ ${m.addr}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  });
  return failures;
};
