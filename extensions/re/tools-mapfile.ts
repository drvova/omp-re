/**
 * map_file — open an additional file into the session's address space (book:
 * basic_commands/mapping_files).
 *
 * The dominant "analyze a dump" workflow is covered by open_binary with load
 * options (open the dump as its own session). map_file is for the other case:
 * bringing a second file into the *current* session at a virtual address
 * without losing the primary binary's analysis — overlaying an unpacked region
 * over the packed image, or mapping a library for cross-module xrefs.
 *
 * The map lives in the rizin process, so it is recorded as a `re.mapfile`
 * entry and re-applied on respawn/resume (mapfiles.ts + runtime.ts), like
 * analysis passes and signatures. It is not an undoable annotation — reopen the
 * binary to return to the baseline. The file is opened read-only (`o`, never
 * `o+`), so it is never written on disk; reading a model-named file into the
 * session is the same trust boundary as open_binary.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { branchEntries, recordedMapFiles } from "./entries.ts";
import { textResult } from "./format.ts";
import { mapFileCommand, validateMapPerm } from "./mapfiles.ts";
import { reRenderers } from "./render.ts";
import { resolveBinaryPath, validateAddr } from "./rizin.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

export function registerMapFileTools(pi: ExtensionAPI): void {
  const z = pi.zod;
  const mapFileParams = z.object({
    addr: z
      .string()
      .describe(
        "Virtual address to map it at, e.g. 0x50000 — pick a range the primary binary doesn't already occupy."
      ),
    path: z
      .string()
      .describe(
        "Path to the file to map into the session (a memory dump, a library, a raw blob)."
      ),
    perm: z
      .string()
      .optional()
      .describe(
        "Map permissions as r/w/x characters (default rizin's own, usually r). The file stays read-only on disk regardless."
      ),
  });

  pi.registerTool({
    name: "map_file",
    label: "Map File",
    description:
      "Open an additional file into the current session at a virtual address (`o <file> <addr>`), alongside the primary binary — e.g. overlay a dumped/unpacked region over the packed image, or map a library for cross-module analysis. The file is mapped read-only (never written on disk) and the map is re-applied automatically on resume/respawn. To just analyze a dump on its own, use open_binary instead. Not an undoable annotation: reopen the binary to drop the map.",
    approval: (args) => {
      const record =
        args && typeof args === "object"
          ? (args as { path?: unknown; addr?: unknown })
          : {};
      const path =
        typeof record.path === "string"
          ? JSON.stringify(record.path)
          : "a file";
      const addr = typeof record.addr === "string" ? record.addr : "?";
      return {
        reason: `Map ${path} into the session's address space at ${addr} (read-only; re-applied on respawn). The file on disk is not modified.`,
        tier: "exec" as const,
      };
    },
    loadMode: "essential",
    parameters: mapFileParams,
    ...reRenderers({ body: "text", subject: "path", title: "Map file" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const binary = requireBinary(getState(ctx));
      const addr = validateAddr(params.addr);
      const perm =
        params.perm === undefined ? undefined : validateMapPerm(params.perm);
      const path = await resolveBinaryPath(params.path); // realpath + readability check, with omp-re's own error; absolute so rizin's cwd doesn't matter

      const before = ((await rz.cmdj<unknown[]>("omlj", { signal })) ?? [])
        .length;
      const { stderr } = await rz.cmdWithStderr(
        mapFileCommand({ addr, path, perm }),
        { signal }
      );
      if (stderr.trim()) {
        throw new Error(`omp-re: map_file: ${stderr.trim()}`);
      }
      const after = ((await rz.cmdj<unknown[]>("omlj", { signal })) ?? [])
        .length;
      if (after <= before) {
        throw new Error(
          `omp-re: map_file: no map was added for ${path} at ${addr} (unreadable or zero-length file?)`
        );
      }

      // Record for replay only once per path+addr on this binary's branch.
      const already = recordedMapFiles(branchEntries(ctx), binary);
      if (!already.some((m) => m.path === path && m.addr === addr)) {
        pi.appendEntry("re.mapfile", { path, addr, ...(perm ? { perm } : {}) });
      }

      const sample = (await rz.cmd(`p8 16 @ ${addr}`, { signal })).trim();
      return textResult(
        `map_file: ${path} @ ${addr}`,
        `mapped ${path} at ${addr}${perm ? ` (${perm})` : ""}; first bytes: ${sample || "(unreadable)"}\nRe-applied automatically on resume/respawn; reopen the binary to drop it.`,
        { ctx, tool: "map_file" }
      );
    },
  });
}
