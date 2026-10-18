import { constants as fsConstants } from "node:fs";
/**
 * External triage tools (capa/floss/yara/die).
 *
 * Each wraps an external binary invoked via argv (never a shell) through
 * omp's `pi.exec`, so a cancelled tool call kills the scanner. A tool is
 * registered only when its binary is found on PATH at load time — an offered
 * tool that always fails is worse than an absent one.
 *
 * Like tools-read.ts, every tool returns the real findings (rule names,
 * matched capabilities, detections) as content, not just a count.
 */
import { access, realpath as fsRealpath } from "node:fs/promises";

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { jsonResult, textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { isExecutable } from "./rizin.ts";
import { getState, requireBinary } from "./state.ts";

interface PlainTriageDef {
  /** External tool key (also the summarizer lookup key). */
  name: string;
  /** Executable name resolved on PATH — differs from `name` only for "die" (binary is `diec`). */
  bin: string;
  description: string;
  timeoutMs: number;
}

/** capa/floss/die all take a bare `{{file}}` argv and emit real JSON via `-j`; yara has no JSON mode and is handled separately below. */
const PLAIN_TRIAGE_TOOLS: PlainTriageDef[] = [
  {
    bin: "capa",
    description:
      "Run capa rules against the binary to detect capabilities and ATT&CK techniques.",
    name: "capa",
    timeoutMs: 300_000,
  },
  {
    bin: "floss",
    description:
      "Extract obfuscated strings (stack, decoded, static) from the binary using FLOSS.",
    name: "floss",
    timeoutMs: 600_000,
  },
  {
    bin: "diec",
    description:
      "Detect packers, compilers, and file types using Detect It Easy.",
    name: "die",
    timeoutMs: 60_000,
  },
];

const YARA_TIMEOUT_MS = 120_000;

/** Resolve and validate an existing, readable file path (used for both the session binary and yara's rules file). */
const resolveExistingFile = async (
  label: string,
  value: string
): Promise<string> => {
  let real: string;
  try {
    real = await fsRealpath(value);
  } catch {
    throw new Error(`omp-re: invalid ${label}: ${value}`);
  }
  try {
    await access(real, fsConstants.R_OK);
  } catch {
    throw new Error(`omp-re: invalid ${label}: ${value}`);
  }
  return real;
};

/** capa: pull rule name + ATT&CK/MBC mapping out of each matched rule's `meta`, not just a count. */
const capaFindings = (parsed: unknown): unknown => {
  if (typeof parsed !== "object" || parsed === null || !("rules" in parsed)) {
    return null;
  }
  const { rules } = parsed;
  if (rules === null || typeof rules !== "object") {
    return null;
  }
  // capa's top-level `rules` is a map keyed by rule name, not an array.
  return Object.entries(rules as Record<string, unknown>).map(
    ([name, rule]) => {
      const meta =
        typeof rule === "object" && rule !== null && "meta" in rule
          ? (rule as Record<string, unknown>).meta
          : undefined;
      return { meta, name };
    }
  );
};

/** floss: return the actual decoded/stack/static strings, not just totals. */
const flossFindings = (parsed: unknown): unknown => {
  if (typeof parsed !== "object" || parsed === null || !("strings" in parsed)) {
    return null;
  }
  const { strings } = parsed;
  if (typeof strings !== "object" || strings === null) {
    return null;
  }
  const out: Record<string, unknown> = {};
  for (const key of ["stack_strings", "decoded_strings", "static_strings"]) {
    if (key in strings) {
      out[key] = (strings as Record<string, unknown>)[key];
    }
  }
  return out;
};

/** die: return the actual per-scan detections, not just a count. */
const dieFindings = (parsed: unknown): unknown => {
  if (typeof parsed !== "object" || parsed === null || !("scans" in parsed)) {
    return null;
  }
  const { scans } = parsed;
  if (!Array.isArray(scans)) {
    return null;
  }
  return scans;
};

const FINDERS: Record<string, (parsed: unknown) => unknown> = {
  capa: capaFindings,
  die: dieFindings,
  floss: flossFindings,
};

/** One matched YARA rule, parsed from real plain-text CLI output (`<rule> <file>` per line — yara has no JSON output mode). */
interface YaraMatch {
  rule: string;
  file: string;
}

const parseYaraPlainText = (stdout: string): YaraMatch[] => {
  const matches: YaraMatch[] = [];
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const spaceIndex = line.indexOf(" ");
    if (spaceIndex === -1) {
      continue;
      // malformed line (e.g. a warning) — skip rather than misparse
    }
    matches.push({
      file: line.slice(spaceIndex + 1).trim(),
      rule: line.slice(0, spaceIndex),
    });
  }
  return matches;
};

export const registerTriageTools = async (pi: ExtensionAPI): Promise<void> => {
  const z = pi.zod;
  const [plainAvailability, yaraAvailable] = await Promise.all([
    Promise.all(PLAIN_TRIAGE_TOOLS.map((def) => isExecutable(def.bin))),
    isExecutable("yara"),
  ]);

  // Named const schemas: see registerReadTools for why they stay outside registerTool({...}).
  const noParams = z.object({});
  const yaraParams = z.object({
    rules_path: z.string().describe("Path to a YARA rules file."),
  });

  for (const [index, def] of PLAIN_TRIAGE_TOOLS.entries()) {
    if (!plainAvailability[index]) {
      continue;
      // absent binary — skip silently, never register a tool that always fails
    }

    pi.registerTool({
      approval: {
        reason: `Run ${def.bin} against the open binary.`,
        tier: "exec",
      },
      description: def.description,
      label: `Triage: ${def.name}`,
      loadMode: "essential",
      name: `triage_${def.name}`,
      parameters: noParams,
      ...reRenderers({ body: "json", title: `Triage: ${def.name}` }),
      async execute(_id, _params, signal, _onUpdate, ctx) {
        const file = await resolveExistingFile(
          "file",
          requireBinary(getState(ctx))
        );
        const result = await pi.exec(def.bin, ["-j", file], {
          signal,
          timeout: def.timeoutMs,
        });
        // Exit code is advisory, not failure: capa signals "no matches" with a non-zero exit.
        // But empty stdout + non-zero exit means it never ran at all — that must not read as "0 findings".
        if (result.code !== 0 && result.stdout.trim() === "") {
          throw new Error(
            `omp-re: ${def.name} failed (exit ${result.code}): ${result.stderr.trim() || "no output"}`
          );
        }
        const options = { ctx, tool: `triage_${def.name}` };
        let parsed: unknown;
        try {
          parsed = JSON.parse(result.stdout);
        } catch {
          return textResult(
            `${def.name}: output was not valid JSON (schema not recognized)`,
            result.stdout,
            options
          );
        }
        const findings = FINDERS[def.name]?.(parsed);
        if (findings === null || findings === undefined) {
          return textResult(
            `${def.name}: expected JSON shape not found`,
            result.stdout,
            options
          );
        }
        const count = Array.isArray(findings)
          ? findings.length
          : Object.keys(findings as object).length;
        return jsonResult(
          `${def.name}: ${count} finding group(s)`,
          findings,
          options
        );
      },
    });
  }

  if (yaraAvailable) {
    pi.registerTool({
      approval: (args) => ({
        reason: `Run yara with rules ${JSON.stringify((args as { rules_path?: unknown })?.rules_path ?? "?")} against the open binary.`,
        tier: "exec",
      }),
      description: "Scan the binary with user-supplied YARA rules.",
      label: "Triage: yara",
      loadMode: "essential",
      name: "triage_yara",
      parameters: yaraParams,
      ...reRenderers({
        body: "json",
        subject: "rules_path",
        title: "Triage: yara",
      }),
      async execute(_id, params, signal, _onUpdate, ctx) {
        if (params.rules_path.trim() === "") {
          throw new Error(
            "omp-re: yara: rules_path argument is required (no default ruleset ships)"
          );
        }
        const file = await resolveExistingFile(
          "file",
          requireBinary(getState(ctx))
        );
        const rules = await resolveExistingFile(
          "rules_path",
          params.rules_path
        );
        const result = await pi.exec("yara", [rules, file], {
          signal,
          timeout: YARA_TIMEOUT_MS,
        });
        // Exit code is advisory, not failure: yara exits non-zero on zero matches. But empty
        // stdout + non-zero exit (e.g. a rules file that failed to compile) must not read as
        // "0 rules matched" — that would be a false all-clear from a security tool.
        if (result.code !== 0 && result.stdout.trim() === "") {
          throw new Error(
            `omp-re: yara failed (exit ${result.code}): ${result.stderr.trim() || "no output"}`
          );
        }
        const matches = parseYaraPlainText(result.stdout);
        return jsonResult(`yara: ${matches.length} rule(s) matched`, matches, {
          ctx,
          tool: "triage_yara",
        });
      },
    });
  }
};
