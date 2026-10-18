import { statSync } from "node:fs";
import { basename } from "node:path";

/**
 * Export the current analysis as a rizin project (book: projects).
 *
 * `Ps <file.rzdb>` serializes rizin's whole in-process analysis — functions,
 * names, comments, flags, types, the lot — to a project file that interactive
 * rizin or Cutter can open (`Po`). Because omp-re replays its annotations into
 * the live session, the export captures them too: the project is the analysis
 * as omp-re has shaped it, handed off to the GUI/CLI.
 *
 * Export only. Loading a project (`Po`) would replace the session's analysis
 * with state omp-re's entry log doesn't know about, so the next respawn would
 * replay omp-re's own (divergent) annotations over it — a second source of
 * truth. The project file is written to omp-re's confined output directory
 * (never the sample, never a model-chosen path); open it outside omp-re.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { textResult } from "./format.ts";
import { rizinOutputPath, rizinPathArg } from "./output.ts";
import { reRenderers } from "./render.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

export function registerProjectTools(pi: ExtensionAPI): void {
  const z = pi.zod;
  const exportProjectParams = z.object({
    file: z
      .string()
      .optional()
      .describe(
        "Project filename (a bare name, no path) written to omp-re's output directory; omit for one derived from the binary's name. `.rzdb` is appended if missing."
      ),
  });

  pi.registerTool({
    name: "export_project",
    label: "Export Project",
    description:
      "Save the current analysis as a rizin project (.rzdb) — functions, names, comments, flags, and types, including every annotation omp-re has applied — so it can be opened in interactive rizin or Cutter (`Po <file>`). Written to omp-re's output directory, never the sample. Export only: omp-re does not load projects (it manages analysis state through its own session log). Returns the file path and size.",
    approval: () => ({
      reason:
        "Write the current analysis to a rizin project file in omp-re's output directory — the sample and the analysis are not modified.",
      tier: "exec" as const,
    }),
    loadMode: "essential",
    parameters: exportProjectParams,
    ...reRenderers({ body: "text", subject: "file", title: "export_project" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const binaryPath = requireBinary(getState(ctx));
      const requested = params.file ?? `${basename(binaryPath)}.rzdb`;
      const name = /\.rzdb$/iu.test(requested)
        ? requested
        : `${requested}.rzdb`;
      // validates the basename and asserts a rizin-safe path, before touching rizin
      const path = await rizinOutputPath(name);
      const { stderr } = await rz.cmdWithStderr(`Ps ${rizinPathArg(path)}`, {
        signal,
      });
      if (stderr.trim()) {
        throw new Error(`omp-re: export_project: ${stderr.trim()}`);
      }
      let size = 0;
      try {
        ({ size } = statSync(path));
      } catch {
        throw new Error(
          `omp-re: export_project: rizin reported no error but wrote no project file at ${path}`
        );
      }
      if (size === 0) {
        throw new Error(
          `omp-re: export_project: the project file at ${path} is empty`
        );
      }
      return textResult(
        `export_project: ${name}`,
        `wrote the analysis to ${path} (${size} bytes)\nOpen it in rizin or Cutter with: Po ${path}`,
        { ctx, tool: "export_project" }
      );
    },
  });
}
