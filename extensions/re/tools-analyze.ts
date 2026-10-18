/**
 * Re-running rizin's analysis passes (book: analysis/code_analysis).
 *
 * `open_binary`'s `aaa` is the baseline; this tool runs the deeper or
 * format-specific passes it skips — prelude scans (stripped code), Go and
 * Objective-C recovery, pointer analysis, recursive type matching, and
 * per-function ESIL emulation. Each pass only adds analysis (functions,
 * xrefs, names, types); none deletes. A pass is exec-tier because it changes
 * the analysis and can be slow, and it is recorded so a resume/respawn re-runs
 * it (passes.ts + runtime.ts) — it is not an undoable annotation, so to start
 * from the baseline again, reopen the binary.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { branchEntries, recordedAnalysisPasses } from "./entries.ts";
import { textResult } from "./format.ts";
import { ANALYSIS_PASSES } from "./passes.ts";
import type { AnalysisPass } from "./passes.ts";
import { reRenderers } from "./render.ts";
import { analysisTimeoutMs } from "./rizin.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

const PASS_NAMES = Object.keys(ANALYSIS_PASSES) as [
  AnalysisPass,
  ...AnalysisPass[],
];

export const registerAnalyzeTools = (pi: ExtensionAPI): void => {
  const z = pi.zod;
  const analyzeParams = z.object({
    pass: z
      .enum(PASS_NAMES)
      .describe(
        [
          "calls: analyze function calls. xrefs: cross-references. pointers: values that reference a section/map.",
          "preludes: recover functions by prologue byte patterns (finds code in stripped binaries aaa missed). all_functions: analyze all functions. data_refs: data references to code.",
          "autoname: name functions from the strings/calls they use. types: recursive type matching across functions. struct_offsets: rewrite immediates as linked struct-member offsets.",
          "golang: recover Go functions and strings. objc: recover Objective-C references from selector usage. rtti_classes: recover C++ classes from RTTI.",
          "emulate_functions: analyze references by emulating every function with ESIL (thorough but slow).",
        ].join("\n")
      ),
  });

  pi.registerTool({
    name: "analyze",
    label: "Analyze",
    description:
      "Re-run a rizin analysis pass to recover more than open_binary's baseline `aaa` found: prelude scans for stripped code, Go/Objective-C recovery, pointer and call/xref analysis, recursive type matching, or per-function emulation. Reports the function count before and after. The pass is re-run automatically on resume/respawn; it is not an undoable annotation (reopen the binary to return to the baseline). Some passes (emulate_functions) can be slow.",
    approval: (args) => {
      const pass =
        args && typeof args === "object"
          ? (args as { pass?: unknown }).pass
          : undefined;
      return {
        reason: `Run rizin analysis pass ${typeof pass === "string" ? JSON.stringify(pass) : "?"} — this changes the analysis (it adds functions, xrefs, names, or types).`,
        tier: "exec" as const,
      };
    },
    loadMode: "essential",
    parameters: analyzeParams,
    ...reRenderers({ body: "text", subject: "pass", title: "analyze" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const binary = requireBinary(getState(ctx));
      const command = ANALYSIS_PASSES[params.pass];
      const rawBefore = await rz.cmd("aflc", { signal });
      const before = Number(rawBefore.trim()) || 0;
      // Use cmdWithStderr: passes like `golang` report "cannot recover …" on stderr, which plain cmd() drops.
      const { output, stderr } = await rz.cmdWithStderr(command, {
        signal,
        timeoutMs: analysisTimeoutMs(),
      });
      const rawAfter = await rz.cmd("aflc", { signal });
      const after = Number(rawAfter.trim()) || 0;
      const out = output.trim();
      const err = stderr.trim();

      // Record for replay only when the pass did real work: a pass that
      // errored (e.g. `golang` on a non-Go binary) or found nothing has
      // nothing worth re-running on resume.
      const errored = err !== "";
      const delta = after - before;
      if (!errored && (delta !== 0 || out !== "")) {
        const already = recordedAnalysisPasses(branchEntries(ctx), binary);
        if (!already.includes(params.pass)) {
          pi.appendEntry("re.analysis", { pass: params.pass });
        }
      }

      const summary = errored
        ? `${command}: ${err}`
        : `${command}: functions ${before} -> ${after}${delta === 0 ? " (no change)" : ` (+${delta})`}.${out ? `\n${out}` : ""}`;
      const result = await textResult(`analyze: ${params.pass}`, summary, {
        ctx,
        tool: "analyze",
      });
      return errored ? { ...result, isError: true } : result;
    },
  });
};
