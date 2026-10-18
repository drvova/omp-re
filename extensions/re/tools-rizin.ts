/**
 * The bridge to the rest of rizin: `rizin_help` reads the installed rizin's
 * own command catalog (`?*j`), and `rizin_command` runs read-only commands
 * the dedicated tools don't cover — function summaries (`pdsf`), call graphs
 * (`agc`), hexdumps (`px`), entropy (`ph entropy`), byte and ROP searches
 * (`/x`, `/R`), ESIL (`aoe`), headers (`iH`), and the rest of rizin's ~700
 * read-only commands. See catalog.ts for the policy and its reasons.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import { checkRizinCommand, loadCatalog, searchCatalog } from "./catalog.ts";
import {
  canonicalExcerpt,
  canonicalHash,
  plainResult,
  shiftHash,
  textResult,
} from "./format.ts";
import type { ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { eaFromOffset, resolveNumericAddr } from "./rizin.ts";
import { ensureRizin, getState } from "./state.ts";

const RIZIN_COMMAND_TIMEOUT_MS = 120_000;

/**
 * rizin's stderr with terminal control sequences removed. Searches redraw a
 * progress line on stderr even with `scr.color=0` and leave a bare
 * clear-line escape (`ESC[2K`) behind when they find nothing; that is not an
 * error message.
 */
export function cleanStderr(stderr: string): string {
  return stderr
    .replaceAll(/\u001B\[[0-9;?]*[A-Za-z]/gu, "")
    .replaceAll("\r", "\n")
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line) => line.trim() !== "")
    .join("\n");
}

function describeCommand(args: unknown): string {
  const record =
    args && typeof args === "object" ? (args as Record<string, unknown>) : {};
  const command = typeof record.command === "string" ? record.command : "?";
  const addr =
    typeof record.addr === "string" && record.addr ? ` @ ${record.addr}` : "";
  const line = `${command}${addr}`;
  return JSON.stringify(line.length > 120 ? `${line.slice(0, 117)}...` : line);
}

export function registerRizinTools(pi: ExtensionAPI): void {
  // Named const schemas: see registerReadTools for why they stay outside registerTool({...}).
  const z = pi.zod;
  const helpParams = z.object({
    query: z
      .string()
      .describe(
        "A command or prefix (`pd`, `afv`, `/R`, `ph`) for its usage and arguments, or keywords (`entropy`, `rop gadgets`, `call graph`) to find commands."
      ),
  });
  const commandParams = z.object({
    addr: z
      .string()
      .optional()
      .describe("Address or name to run the command at (sent as `@ <addr>`)."),
    command: z
      .string()
      .describe(
        "One read-only rizin command with its arguments, e.g. `pdsf`, `agc ascii`, `px 64`, `/x 4889e5`, `ph entropy 4096`. No `;`, `|`, `>`, `@`, or `~`."
      ),
  });

  pi.registerTool({
    name: "rizin_help",
    label: "rizin help",
    description:
      "Look up rizin commands in the installed rizin's own help: the usage, typed arguments, and summary of a command or command family, or a keyword search across every command. Each entry says whether rizin_command can run it. Use before rizin_command when unsure of a command or its arguments.",
    approval: "read",
    loadMode: "essential",
    parameters: helpParams,
    ...reRenderers({ body: "text", subject: "query", title: "rizin help" }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const catalog = await loadCatalog();
      const { header, lines } = searchCatalog(catalog, params.query);
      return textResult(header, lines.join("\n"), { ctx, tool: "rizin_help" });
    },
  });

  pi.registerTool({
    name: "rizin_command",
    label: "rizin command",
    description:
      "Run one read-only rizin command against the open binary, for anything the dedicated tools don't cover: function summaries (pdsf), call and block graphs (agc, agf), hexdumps (px), entropy (ph entropy), byte/string/ROP searches (/x, /, /R), ESIL (aoe), headers (iH), and the rest of rizin's print, info, search, graph, and listing commands. Also reads config (e asm.arch, el, elj), analysis hints (ahl), metadata and strings (C, Csl), classes (acl, aci), address info (ai), unions and type cross-references (tu, tx), calling-convention lists (tcc), and plugin lists (Ll, La, LD). Commands that write, set config (e key=value), open files, run shell commands, or change analysis are refused; annotate with the dedicated tools instead. If rizin rejects the arguments, its own error and usage text are returned. Check syntax with rizin_help first.",
    approval: (args) => ({
      reason: `Run the rizin command ${describeCommand(args)} on the open binary.`,
      tier: "exec",
    }),
    loadMode: "essential",
    parameters: commandParams,
    ...reRenderers({ body: "text", subject: "command", title: "rizin" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      return runRizinCommand(ctx, params.command, params.addr, signal);
    },
  });
}

/**
 * The body of `rizin_command`: gate the line through the read-only catalog check,
 * run it, and build the result with its reproducibility fields (commands,
 * reproHash, canonicalExcerpt, shiftHash). Exported so `/re carry --inherit` can
 * re-run a carried command and record it exactly as the tool would.
 */
export async function runRizinCommand(
  ctx: ExtensionContext,
  command: string,
  addr: string | undefined,
  signal?: AbortSignal
): Promise<ReToolResult> {
  const catalog = await loadCatalog();
  const check = checkRizinCommand(catalog, command, addr);
  if (!check.ok) {
    throw new Error(check.reason);
  }
  const rz = await ensureRizin(ctx, { signal });
  // An address rizin can't resolve just leaves the result without an ea; the command still runs.
  let ea: string | undefined;
  if (addr) {
    try {
      ea = eaFromOffset(await resolveNumericAddr(rz, addr, signal));
    } catch {
      ea = undefined;
    }
  }
  const { output, stderr } = await rz.cmdWithStderr(check.line, {
    signal,
    timeoutMs: RIZIN_COMMAND_TIMEOUT_MS,
  });
  const header = `rizin> ${check.line}`;
  if (output.trim() === "") {
    const errors = cleanStderr(stderr);
    return errors
      ? {
          ...plainResult(`${header}\n(no output; rizin said:)\n${errors}`, ea),
          isError: true,
        }
      : plainResult(`${header}\n(no output)`, ea);
  }
  // reproHash is over the RAW output (pre-trim/pre-truncation), canonicalized and bound to the
  // open binary's path, so `/re verify` can re-run this exact line and hash-compare. The body
  // sent to the model is still the trimmed/truncated text; only the verification key sees raw.
  const binaryPath = getState(ctx).binaryPath ?? undefined;
  return textResult(header, output.replace(/\n+$/u, ""), {
    canonicalExcerpt: canonicalExcerpt(output, binaryPath),
    commands: [check.line],
    ctx,
    ea,
    reproHash: canonicalHash(output, binaryPath),
    shiftHash: shiftHash(output, binaryPath),
    tool: "rizin_command",
  });
}
