/**
 * The rest of rizin's command-line suite: the standalone `rz-*` tools that
 * ship beside `rizin`, exposed through one `rizin_cli` tool so the model can
 * use them with their own arguments.
 *
 * These are separate executables, invoked via argv through `pi.exec` (never a
 * shell), so there is no `;`/`|`/`$()` surface. What is gated instead is the
 * flags: the few that run a shell or rizin command (`rz-find -E`/`-R`,
 * `rz-diff -t command`), write to disk (`rz-bin -O`/`-o`/`-C`, `rz-asm -O`),
 * fetch over the network (`rz-bin -dd`/`-PP`), or open an interactive view
 * (`rz-diff -H`/`-S`) are refused before anything runs. Everything else —
 * headers and imports (`rz-bin`), binary/function diffing (`rz-diff`),
 * hashing and entropy (`rz-hash`), pattern search (`rz-find`),
 * (dis)assembly (`rz-asm`), and base conversion (`rz-ax`) — is read-only
 * analysis and passes through.
 *
 * Help is each tool's own: `rizin_cli` with `args: ["-h"]` returns it, so the
 * model learns the real flags of the installed version rather than a copy.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { plainResult, textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { isExecutable, resolveRizinTool } from "./rizin.ts";
import { getState, requireBinary } from "./state.ts";

const RZ_CLI_TIMEOUT_MS = 180_000;

/** The token the model may put in `args` to mean "the open binary"; also auto-appended for `target: "open"` tools when absent. */
export const BINARY_PLACEHOLDER = "@binary";

export interface RzCliToolDef {
  tool: string;
  summary: string;
  /** "open": run against the currently open binary (appended, or substituted for `@binary`); "args": the model supplies the file(s). */
  target: "open" | "args";
  /**
   * Short-flag letters refused anywhere in a `-xyz` cluster (case-sensitive,
   * matching getopt), each because it would run code, write a file, hit the
   * network, or open an interactive view.
   */
  deniedLetters: string;
  /** Whole tokens refused (long options like `--foo`). Short-flag clusters are handled letter-wise, not here. */
  deniedTokens?: readonly string[];
  /**
   * Letters that are safe once but escalate when repeated: rz-bin's `-d`
   * reads local DWARF but `-dd` downloads from debuginfod, `-P` reads a local
   * PDB but `-PP` downloads it. Refused when the letter occurs two or more
   * times across ALL short clusters — so `-dd`, `-d -d`, `-ddj`, and `-jdd`
   * are all caught, not just the exact doubled token.
   */
  deniedRepeatedLetters?: string;
  /**
   * A value-taking flag whose value is refused when it is one of `values`,
   * in EVERY getopt spelling: `-t command`, `-tcommand`, and `-Xtcommand`
   * (the value is the rest of the cluster after the flag letter, or the next
   * token when the flag ends the cluster). `rz-diff -t command` makes rz-diff
   * run a rizin command per file, and rizin `!` runs the shell — an RCE the
   * old `[flag, value]` pair check missed in the attached form.
   */
  deniedFlagValues?: readonly { flag: string; values: readonly string[] }[];
}

/**
 * The curated set. rz-gg (shellcode/egg generation), rz-run (launches a
 * process — that belongs to the debugger), rz-sign/rz-ar/rz-test are left out
 * as code-generation, execution, or rizin's own plumbing rather than analysis
 * of a sample.
 */
export const RZ_CLI_TOOLS: readonly RzCliToolDef[] = [
  {
    // -O/-o write/extract, -C creates a new binary, -x extracts sub-binaries to disk
    deniedLetters: "OoCx",
    // -dd downloads DWARF (debuginfod), -PP downloads the PDB; single -d/-P read locally and stay allowed
    deniedRepeatedLetters: "dP",
    summary:
      "Binary info without loading the whole core: headers (-H), imports (-i), exports (-E), symbols (-s), sections (-S), libraries (-l), strings (-z), classes (-c), entrypoint (-e), main (-M), checksums (-K), demangling (-D). JSON with -j.",
    target: "open",
    tool: "rz-bin",
  },
  {
    tool: "rz-diff",
    summary:
      "Compare two files: edit distance (-d myers|leven|ssdeep) or structural diff (-t bytes|functions|imports|symbols|sections|strings|entries|fields|graphs). Pass both paths; -A compares addresses, -B runs full analysis first. JSON with -j.",
    target: "args",
    // -H/-S open an interactive visual view that would hang
    deniedLetters: "HS",
    // Not blocking -e (sets config): its value is arbitrary and would need
    // value-aware parsing, and a letter-ban on `e` false-positives on any
    // clustered flag whose value contains an 'e' (e.g. `-tbytes`). rz-diff
    // runs on a throwaway process with no persistence or demonstrated exec.
    // -t command runs a rizin command per file (→ shell via `!`); refused in every spelling
    deniedFlagValues: [{ flag: "t", values: ["command", "commands"] }],
  },
  {
    deniedLetters: "",
    summary:
      "Hash, entropy, and checksums of a file or input: -a <algo[,algo]> (md5, sha256, entropy, …), -B per-block, -b <size>, -c <value> to compare, -s/-x for string/hex input. -L lists algorithms. JSON with -j.",
    target: "args",
    tool: "rz-hash",
  },
  {
    // -E runs a shell command per hit; -R runs a rizin command per hit
    deniedLetters: "ER",
    summary:
      "Search a file for bytes or strings: -x <hex>, -s <string>, -w <widestring>, -e <regex>, -S/-I for symbol/import names, -m magic carve, -i identify filetype. -X shows a hexdump of hits. JSON with -j.",
    target: "args",
    tool: "rz-find",
  },
  {
    // -O writes an output file (note: -o here is 'start address', allowed)
    deniedLetters: "O",
    summary:
      "Assemble or disassemble: `rz-asm -a x86 -b 64 'mov eax, 1'` assembles, `rz-asm -a x86 -b 64 -d 'b801000000'` disassembles hexpairs, -A shows analysis, -E ESIL, -I RzIL. -L lists arch plugins.",
    target: "args",
    tool: "rz-asm",
  },
  {
    deniedLetters: "",
    summary:
      "Base and format conversion: int/hex/bin/oct/float/base64/IP. `rz-ax 0xdead`, `rz-ax 10`, `rz-ax -E <b64>`, `rz-ax -s 414141` (hex→raw). A pure calculator; no file is touched.",
    target: "args",
    tool: "rz-ax",
  },
];

export type RzCliCheck = { ok: true } | { ok: false; reason: string };

const isShortCluster = (token: string): boolean =>
  // A single-dash run of letters (`-ij`, `-qO`); not `--long`, not a negative number, not a bare `-` (stdin).
  /^-[A-Za-z]+$/u.test(token);

/**
 * The value a short-flag `letter` receives, in each getopt spelling, scanned
 * across all tokens: the rest of the cluster after the letter (`-tcommand`,
 * `-Xtcommand`), or the next token when the letter ends its cluster (`-t
 * command`, `-Xt command`). Returns every value the flag is given.
 */
const flagValues = (args: readonly string[], letter: string): string[] => {
  const values: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]!;
    if (!isShortCluster(token)) {
      continue;
    }
    const idx = token.indexOf(letter, 1);
    if (idx === -1) {
      continue;
    }
    const attached = token.slice(idx + 1);
    if (attached !== "") {
      values.push(attached);
    } else if (i + 1 < args.length) {
      values.push(args[i + 1]!);
    }
  }
  return values;
};

/**
 * Validate the flags of one `rz-*` invocation. Pure: no binary substitution,
 * no execution. The denials are getopt-aware — a short flag is caught whether
 * it is written split (`-t x`), attached (`-tx`), or clustered (`-Xtx`), and a
 * repeat-escalation flag is caught however the repetition is spelled — so a
 * denied capability cannot be smuggled past by respelling the flag.
 */
export const checkRzCli = (
  def: RzCliToolDef,
  args: readonly string[]
): RzCliCheck => {
  const denied = new Set(def.deniedTokens);
  const letters = new Set(def.deniedLetters.split(""));
  const repeatCounts = new Map<string, number>();
  for (const token of args) {
    if (/[\n\r\0]/u.test(token)) {
      return {
        ok: false,
        reason: "omp-re: rizin_cli: an argument contains a line break or NUL",
      };
    }
    if (denied.has(token)) {
      return {
        ok: false,
        reason: `omp-re: rizin_cli: ${def.tool} ${token} is not allowed here (it writes, runs code, or fetches over the network)`,
      };
    }
    if (isShortCluster(token)) {
      for (const ch of token.slice(1)) {
        if (letters.has(ch)) {
          return {
            ok: false,
            reason: `omp-re: rizin_cli: ${def.tool} -${ch} is not allowed here (it writes a file, runs code, fetches over the network, or opens an interactive view)`,
          };
        }
        if ((def.deniedRepeatedLetters ?? "").includes(ch)) {
          repeatCounts.set(ch, (repeatCounts.get(ch) ?? 0) + 1);
        }
      }
    }
  }
  for (const [ch, count] of repeatCounts) {
    if (count >= 2) {
      return {
        ok: false,
        reason: `omp-re: rizin_cli: ${def.tool} -${ch} given ${count} times fetches over the network (a single -${ch} reads locally and is allowed)`,
      };
    }
  }
  for (const { flag, values } of def.deniedFlagValues ?? []) {
    const denylist = new Set(values);
    for (const value of flagValues(args, flag)) {
      if (denylist.has(value)) {
        return {
          ok: false,
          reason: `omp-re: rizin_cli: ${def.tool} -${flag} ${value} is not allowed here (it runs a command, which can reach the shell)`,
        };
      }
    }
  }
  return { ok: true };
};

/** Resolve which `rz-*` tools are actually installed beside rizin (they ship together, but a minimal build may lack some). */
export const availableRzCliTools = async (): Promise<RzCliToolDef[]> => {
  const checks = await Promise.all(
    RZ_CLI_TOOLS.map((def) => isExecutable(resolveRizinTool(def.tool)))
  );
  return RZ_CLI_TOOLS.filter((_, i) => checks[i]);
};

export const registerRzCliTools = async (pi: ExtensionAPI): Promise<void> => {
  const available = await availableRzCliTools();
  if (available.length === 0) {
    return;
    // no rz-* tools found — don't offer a tool that can't run
  }
  const byName = new Map(available.map((def) => [def.tool, def]));

  // Named const schemas: see registerReadTools for why they stay outside registerTool({...}).
  const z = pi.zod;
  const toolNames = available.map((def) => def.tool) as [string, ...string[]];
  const cliParams = z.object({
    args: z
      .array(z.string())
      .describe(
        `The tool's own arguments as a list (no shell). Use \`${BINARY_PLACEHOLDER}\` for the open binary's path; rz-bin uses it automatically. Pass \`["-h"]\` for the tool's full help.`
      ),
    tool: z
      .enum(toolNames)
      .describe(
        `Which rizin CLI tool to run. ${available.map((def) => `${def.tool}: ${def.summary}`).join("\n")}`
      ),
  });

  pi.registerTool({
    name: "rizin_cli",
    label: "rizin CLI",
    description:
      "Run one of rizin's standalone command-line tools (rz-bin, rz-diff, rz-hash, rz-find, rz-asm, rz-ax) with its own arguments, for analysis the in-core tools don't cover: quick binary info without full analysis, diffing two binaries, hashing and entropy, raw pattern search, standalone (dis)assembly, and base conversion. Argv only, no shell. Flags that write files, run code, fetch over the network, or open interactive views are refused. Pass `args: [\"-h\"]` for a tool's full help.",
    approval: (args) => {
      const record =
        args && typeof args === "object"
          ? (args as { tool?: unknown; args?: unknown })
          : {};
      const tool = typeof record.tool === "string" ? record.tool : "?";
      const list = Array.isArray(record.args)
        ? record.args.filter((a): a is string => typeof a === "string")
        : [];
      const shown = `${tool} ${list.join(" ")}`.trim();
      return {
        reason: `Run ${JSON.stringify(shown.length > 160 ? `${shown.slice(0, 157)}...` : shown)}.`,
        tier: "exec",
      };
    },
    loadMode: "essential",
    parameters: cliParams,
    ...reRenderers({ body: "text", subject: "tool", title: "rizin CLI" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const def = byName.get(params.tool);
      if (!def) {
        throw new Error(
          `omp-re: rizin_cli: unknown tool ${JSON.stringify(params.tool)}`
        );
      }
      const check = checkRzCli(def, params.args);
      if (!check.ok) {
        throw new Error(check.reason);
      }

      // Substitute @binary, and for binary-oriented tools append the open binary when the model didn't place it.
      const usesPlaceholder = params.args.includes(BINARY_PLACEHOLDER);
      const binary =
        usesPlaceholder || def.target === "open"
          ? requireBinary(getState(ctx))
          : null;
      const argv = params.args.map((a) =>
        a === BINARY_PLACEHOLDER ? binary! : a
      );
      if (def.target === "open" && !usesPlaceholder) {
        argv.push(binary!);
      }

      const bin = resolveRizinTool(def.tool);
      const result = await pi.exec(bin, argv, {
        signal,
        timeout: RZ_CLI_TIMEOUT_MS,
      });
      const header = `${def.tool} ${argv.join(" ")}`.trim();
      // rz-* tools on Windows end lines with CRLF; normalize to LF so the
      // model (and exact assertions) never see a stray `\r`.
      const stdout = result.stdout
        .replaceAll("\r\n", "\n")
        .replace(/\n+$/u, "");
      if (stdout === "") {
        const err = result.stderr.replaceAll("\r\n", "\n").trim();
        // Many of these tools report "no match" / "no difference" with a non-zero exit and nothing on stdout; only treat stderr as an error.
        return err
          ? {
              ...plainResult(
                `${header}\n(no output; ${def.tool} said:)\n${err}`
              ),
              isError: true,
            }
          : plainResult(`${header}\n(no output)`);
      }
      return textResult(header, stdout, { ctx, tool: "rizin_cli" });
    },
  });
};
