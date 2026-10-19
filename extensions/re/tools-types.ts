/**
 * Type tools — the book's "Types" chapter (td/ts/tt/te/tf/tp).
 *
 * Surfaces verified against rizin 0.9.1:
 * - `tsj`/`tej`/`ttj`/`tfj` — JSON listings of loaded structs, enums, typedefs,
 *   and function signatures. rizin ships a rich Windows type base (TCCL) plus
 *   the PE's debug info, so these list far more than user-defined types.
 * - `td <C>` — define types from a C definition, string input (no file access).
 * - `tp <type> @ addr` — print memory interpreted as a type.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { jsonResult } from "./format.ts";
import type { ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { resolveNumericAddr, validateAddr } from "./rizin.ts";
import type { RzSession } from "./rizin.ts";
import { inSequence } from "./sequence.ts";
import { ensureRizin } from "./state.ts";
import {
  DEFAULT_LIMIT,
  MAX_LIMIT,
  markEmpty,
  pageHeader,
  paginate,
} from "./tools-read.ts";

const FORBIDDEN_TYPE_DEF_CHARS: ReadonlySet<string> = new Set([
  '"',
  "`",
  "$",
  "\\",
]);

export interface RzTypeListRow {
  name: string;
  /** Structs: member map. Enums: value map. Typedefs: target type. Function defs: signature string. */
  members?: Record<string, string>;
  values?: Record<string, number>;
  type?: string;
}

export interface RzListTypesParams {
  kind: "struct" | "enum" | "typedef" | "function";
  filter?: string;
  offset?: number;
  limit?: number;
}

const KIND_COMMANDS: Record<RzListTypesParams["kind"], string> = {
  enum: "tej",
  function: "tfj",
  struct: "tsj",
  typedef: "ttj",
};

const KIND_LABELS: Record<RzListTypesParams["kind"], string> = {
  enum: "enum types",
  function: "function types",
  struct: "struct types",
  typedef: "typedef types",
};

/** List one type family with an optional name-substring filter, paginated. */
export const listTypeRows = async (
  rz: RzSession,
  params: RzListTypesParams
): Promise<ReToolResult> => {
  const rows =
    (await rz.cmdj<RzTypeListRow[]>(KIND_COMMANDS[params.kind])) ?? [];
  const filter = params.filter?.toLowerCase();
  const filtered = filter
    ? rows.filter((row) => row.name.toLowerCase().includes(filter))
    : rows;
  const { page, total } = paginate(filtered, params.offset, params.limit);
  const result = await jsonResult(
    pageHeader(KIND_LABELS[params.kind], page, total, params.offset),
    page
  );
  return markEmpty(result, page.length === 0);
};

/**
 * Validate and double-quote a `td` C definition. rizin's command parser splits
 * a line on `;`, so an unquoted multi-member struct (`struct S { int a; int b;
 * }`) is cut into fragments and rejected — wrapping the whole definition in
 * `"..."` makes rizin treat the `;`-bearing C as one argument. The quoting is
 * safe only if the definition can't close the quote or substitute, so a `"`,
 * backtick, `$`, `\`, or control character (none of which appears in a C type)
 * is refused rather than passed through.
 */
export const quoteTypeDefinition = (definition: string): string => {
  const trimmed = definition.trim();
  if (trimmed === "") {
    throw new Error("omp-re: define_types: empty definition");
  }
  // quotes, `$` and backslashes would end or escape the double-quoted td argument; control
  // characters (below U+0020) have no place in a C type definition
  const bad = [...trimmed].find(
    (ch) => FORBIDDEN_TYPE_DEF_CHARS.has(ch) || (ch.codePointAt(0) ?? 0) < 0x20
  );
  if (bad !== undefined) {
    throw new Error(
      `omp-re: define_types: a C type definition may not contain ${JSON.stringify(bad)}`
    );
  }
  return `td "${trimmed}"`;
};

/** Define types from C statements, one td per entry. Each definition is double-quoted so its member `;`s survive rizin's line splitter. Surfaces rizin's stderr verbatim. */
export const defineTypeLines = async (
  rz: RzSession,
  definitions: string[]
): Promise<ReToolResult> => {
  const lines: string[] = [];
  await inSequence(definitions, async (definition) => {
    const { output, stderr } = await rz.cmdWithStderr(
      quoteTypeDefinition(definition)
    );
    if (output.trim().length > 0) {
      lines.push(output.trim());
    }
    if (stderr.trim().length > 0) {
      lines.push(stderr.trim());
    }
  });
  if (lines.length === 0) {
    return {
      content: [
        {
          text: `${definitions.length} definition(s) accepted silently (rizin td prints nothing on success). Verify with list_types.`,
          type: "text",
        },
      ],
    };
  }
  return { content: [{ text: lines.join("\n"), type: "text" }] };
};

/** Print memory at an address cast as a named type (rizin tp). */
export const castMemory = async (
  rz: RzSession,
  addr: string,
  type: string,
  signal?: AbortSignal
): Promise<ReToolResult> => {
  const ea = await resolveNumericAddr(rz, validateAddr(addr), signal);
  const { output, stderr } = await rz.cmdWithStderr(`tp ${type} @ ${ea}`, {
    signal,
  });
  const text = [output.trim(), stderr.trim()]
    .filter((part) => part.length > 0)
    .join("\n");
  return {
    content: [{ text: text.length > 0 ? text : "(no output)", type: "text" }],
  };
};

export const registerTypeTools = (pi: ExtensionAPI): void => {
  const z = pi.zod;
  const listTypesParams = z.object({
    filter: z
      .string()
      .optional()
      .describe("Case-insensitive substring filter on the type name."),
    kind: z
      .enum(["struct", "enum", "typedef", "function"])
      .describe("Which type family to list."),
    limit: z
      .number()
      .int()
      .optional()
      .describe(
        `Max types to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`
      ),
    offset: z
      .number()
      .int()
      .optional()
      .describe("Skip this many types (default 0)."),
  });
  const defineTypesParams = z.object({
    definitions: z
      .array(z.string().min(1).trim())
      .min(1)
      .describe(
        'C definitions, one declaration per entry, each ending in ";" (e.g. "struct config { int version; char *name; };").'
      ),
  });
  const castMemoryParams = z.object({
    addr: z.string().describe("Address, flag, or module.symbol to interpret."),
    type: z
      .string()
      .min(1)
      .describe('Type name to cast the memory as (e.g. "struct config").'),
  });

  pi.registerTool({
    approval: "read",
    description:
      "List types loaded in rizin's type database (structs via tsj, enums via tej, typedefs via ttj, function definitions via tfj). Includes rizin's built-in Windows type base plus debug-info and user-defined types. Filter by name substring; page through large lists.",
    label: "List Types",
    loadMode: "essential",
    name: "list_types",
    parameters: listTypesParams,
    ...reRenderers({ body: "json", subject: "kind", title: "List types" }),
    async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
      const rz = await ensureRizin(ctx, { signal });
      return listTypeRows(rz, params);
    },
  });

  pi.registerTool({
    approval: "read",
    description:
      "Define types from C definitions (rizin td). Each statement is one C declaration ending in ';' — structs, unions, enums, typedefs. Type names used but not yet defined must be defined first (td processes statements in order).",
    label: "Define Types",
    loadMode: "essential",
    name: "define_types",
    parameters: defineTypesParams,
    ...reRenderers({ body: "text", subject: "count", title: "Define types" }),
    async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
      const rz = await ensureRizin(ctx, { signal });
      return defineTypeLines(rz, params.definitions);
    },
  });

  pi.registerTool({
    approval: "read",
    description:
      "Print memory at an address interpreted as a named type (rizin tp). The type must exist — define it with define_types first, or list existing ones with list_types.",
    label: "Cast Memory",
    loadMode: "essential",
    name: "cast_memory",
    parameters: castMemoryParams,
    ...reRenderers({ body: "text", subject: "addr", title: "Cast memory" }),
    async execute(_id, params, signal, _onUpdate, ctx): Promise<ReToolResult> {
      const rz = await ensureRizin(ctx, { signal });
      return castMemory(rz, params.addr, params.type, signal);
    },
  });
};
