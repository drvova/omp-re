/**
 * FLIRT signatures (book: analysis/signatures) — naming library functions
 * from a signature database.
 *
 * rizin's `aaa` already applies the built-in signature database on open
 * (`analysis.apply.signature`), so the common case needs no tool. This covers
 * the two things that doesn't: re-applying the built-in database on demand
 * (`Fa`), and applying a *custom* `.sig`/`.pat` file the analyst has (`Fs`),
 * which `rizin_command` can't do because it refuses file arguments.
 *
 * Applying signatures renames matched functions — it changes analysis — so
 * this is exec-tier. A custom-file application is recorded as an `re.signature`
 * entry and re-applied on every respawn/resume (signatures.ts + runtime.ts),
 * the same way annotations are replayed, so the names it produced survive. It
 * is not an undoable annotation: reopening and re-running `aaa` is how you
 * start clean.
 */
import { statSync } from "node:fs";
import { basename } from "node:path";

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { branchEntries, recordedSignatures } from "./entries.ts";
import { textResult } from "./format.ts";
import { rizinOutputPath, rizinPathArg } from "./output.ts";
import { reRenderers } from "./render.ts";
import {
  parseAppliedCount,
  signatureApplyCommand,
  validateSignaturePath,
} from "./signatures.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

export function registerSignatureTools(pi: ExtensionAPI): void {
  const z = pi.zod;
  const applyParams = z.object({
    path: z
      .string()
      .optional()
      .describe("Path to a .sig/.pat file, required when source is 'file'."),
    source: z
      .enum(["sigdb", "file"])
      .describe(
        "sigdb: re-apply rizin's built-in signature database. file: apply a custom FLIRT .sig/.pat file (path required)."
      ),
  });

  pi.registerTool({
    name: "apply_signatures",
    label: "Apply Signatures",
    description:
      "Name library functions from FLIRT signatures. source 'sigdb' re-applies rizin's built-in signature database (already applied once by open_binary's analysis); source 'file' applies a custom .sig/.pat file you provide, which open_binary can't know about. This renames matched functions (it changes analysis). A custom file is re-applied automatically on resume/respawn. List the built-in database with rizin_command Flt.",
    approval: (args) => {
      const record =
        args && typeof args === "object"
          ? (args as { source?: unknown; path?: unknown })
          : {};
      if (record.source === "file" && typeof record.path === "string") {
        return {
          reason: `Apply the FLIRT signature file ${JSON.stringify(record.path)} — this renames matched functions.`,
          tier: "exec" as const,
        };
      }
      return {
        reason:
          "Re-apply rizin's built-in signature database — this renames matched functions.",
        tier: "exec" as const,
      };
    },
    loadMode: "essential",
    parameters: applyParams,
    ...reRenderers({
      body: "text",
      subject: "source",
      title: "Apply signatures",
    }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const binary = requireBinary(getState(ctx));

      if (params.source === "sigdb") {
        const before = Number((await rz.cmd("aflc", { signal })).trim()) || 0;
        await rz.cmd("Fa", { signal });
        const after = Number((await rz.cmd("aflc", { signal })).trim()) || 0;
        return textResult(
          "apply_signatures: sigdb",
          `Re-applied the built-in signature database. Functions: ${before} before, ${after} after.`
        );
      }

      if (params.path === undefined) {
        throw new Error("omp-re: apply_signatures: source 'file' needs a path");
      }
      const path = validateSignaturePath(params.path);
      const out = (
        await rz.cmd(signatureApplyCommand(path), { signal })
      ).trim();
      const count = parseAppliedCount(out);
      // Record it for replay only when it actually applied signatures: a
      // zero-match or error application has nothing to reproduce on resume.
      if ((count ?? 0) > 0) {
        const already = recordedSignatures(branchEntries(ctx), binary);
        if (!already.includes(path)) {
          pi.appendEntry("re.signature", { path });
        }
      }
      return textResult(
        `apply_signatures: ${path}`,
        count === undefined
          ? out || "(applied)"
          : `Applied ${count} FLIRT signature(s) from ${path}.`
      );
    },
  });

  const createParams = z.object({
    file: z
      .string()
      .optional()
      .describe(
        "Output filename (a bare name, no path) written to omp-re's output directory; omit for one derived from the binary's name. End it `.pat` (text patterns, the default) or `.sig` (compiled)."
      ),
  });

  pi.registerTool({
    name: "create_signature",
    label: "Create Signature",
    description:
      "Build a FLIRT signature file (`Fc`) from the current binary's analyzed functions, to recognize those same functions in other samples (e.g. tracking a routine across a malware family). Written to omp-re's output directory as a `.pat` (text patterns) or `.sig` (compiled). Apply it elsewhere with apply_signatures (source 'file'). Reads the analysis and writes a file — it does not modify the analysis or the sample.",
    approval: () => ({
      reason:
        "Create a FLIRT signature file from the current analysis in omp-re's output directory — the analysis and the sample are not modified.",
      tier: "exec" as const,
    }),
    loadMode: "essential",
    parameters: createParams,
    ...reRenderers({
      body: "text",
      subject: "file",
      title: "create_signature",
    }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const binaryPath = requireBinary(getState(ctx));
      const requested = params.file ?? `${basename(binaryPath)}.pat`;
      const name = /\.(pat|sig)$/i.test(requested)
        ? requested
        : `${requested}.pat`;
      const path = await rizinOutputPath(name); // validates the basename and asserts a rizin-safe path, before touching rizin
      const { stderr } = await rz.cmdWithStderr(`Fc ${rizinPathArg(path)}`, {
        signal,
      });
      if (stderr.trim()) {
        throw new Error(`omp-re: create_signature: ${stderr.trim()}`);
      }
      let size = 0;
      try {
        size = statSync(path).size;
      } catch {
        throw new Error(
          `omp-re: create_signature: rizin reported no error but wrote no signature file at ${path} (are there analyzed functions? run analyze/open_binary first)`
        );
      }
      if (size === 0) {
        throw new Error(
          `omp-re: create_signature: the signature file at ${path} is empty (no functions to signature)`
        );
      }
      // Read it back (Fd dumps the file's signatures) to confirm it is a valid FLIRT file and count what it holds.
      const dumped = (
        await rz.cmdWithStderr(`Fd ${rizinPathArg(path)}`, { signal })
      ).output.trim();
      const sigCount = dumped
        ? dumped.split("\n").filter((l) => l.trim() !== "").length
        : 0;
      return textResult(
        `create_signature: ${name}`,
        `wrote ${sigCount} function signature(s) to ${path} (${size} bytes)\nApply it to another sample with apply_signatures (source 'file', path ${path}).`,
        { ctx, tool: "create_signature" }
      );
    },
  });
}
