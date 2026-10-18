/**
 * Search tools — the book's "Searching" chapter, exposed to the model.
 *
 * `/xj` (raw hex search, JSON) and `/xrj` (regex bytes search, JSON) are the
 * two JSON-carrying byte-search surfaces in rizin 0.9.x; both return rows of
 * `{ address, size, flag }`. String search is hex-encoded client-side and run
 * through `/xj`, which keeps one row shape and avoids quoting hazards in the
 * persistent-session transport. `/aj` (assemble-and-search) shares the row
 * shape, and the `/v` value-search family emits the same rows.
 *
 * ROP/COP gadget search (`/R`, `/C`) is native JSON too — but in 0.9.1 the
 * `/Rj`/`/Cj` modes only emit after a text-mode run primes the gadget cache,
 * so search_gadgets runs the prime command (output discarded) and then the
 * JSON command, with rizin's own filter string on both.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { forbiddenSyntaxReason } from "./catalog.ts";
import { jsonResult } from "./format.ts";
import type { ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { eaFromOffset, validateAddr } from "./rizin.ts";
import type { RzSession } from "./rizin.ts";
import { ensureRizin } from "./state.ts";
import {
  DEFAULT_LIMIT,
  MAX_LIMIT,
  knownAddr,
  markEmpty,
  pageHeader,
  paginate,
} from "./tools-read.ts";

interface AfijBounds {
  name?: string;
  offset?: number;
  size?: number;
  minbound?: number;
  maxbound?: number;
}

/** The [from, to) extent of the function at `nameOrAddr`, for scoping a search to it. Uses the function's full bounds (minbound/maxbound), falling back to offset+size. */
const functionRange = async (
  rz: RzSession,
  nameOrAddr: string,
  signal?: AbortSignal
): Promise<{ from: number; to: number; name: string }> => {
  const rawFn = await rz.cmdj<AfijBounds[]>(
    `afij @ ${validateAddr(nameOrAddr)}`,
    {
      signal,
    }
  );
  const fn = rawFn?.[0];
  if (!fn) {
    throw new Error(
      `omp-re: no function at ${JSON.stringify(nameOrAddr)} to scope the search to`
    );
  }
  const from = fn.minbound ?? fn.offset;
  const to =
    fn.maxbound ??
    (fn.offset !== undefined && fn.size !== undefined
      ? fn.offset + fn.size
      : undefined);
  if (from === undefined || to === undefined || to <= from) {
    throw new Error(
      `omp-re: could not determine the bounds of the function at ${JSON.stringify(nameOrAddr)}`
    );
  }
  return { from, name: fn.name ?? nameOrAddr, to };
};

/**
 * Run `fn` with rizin's search restricted to [from, to), then restore the
 * previous search scope no matter what. rizin searches honor `search.in` +
 * `search.from`/`search.to`; this sets them to a range and puts the prior
 * values back in a finally, so a scoped search never leaks its scope into the
 * next one (the session is shared).
 */
const withSearchScope = async <T>(
  rz: RzSession,
  from: number,
  to: number,
  signal: AbortSignal | undefined,
  fn: () => Promise<T>
): Promise<T> => {
  const rawSavedIn = await rz.cmd("e search.in", { signal });
  const savedIn = rawSavedIn.trim() || "io.maps";
  const rawSavedFrom = await rz.cmd("e search.from", { signal });
  const savedFrom = rawSavedFrom.trim() || "0";
  const rawSavedTo = await rz.cmd("e search.to", { signal });
  const savedTo = rawSavedTo.trim() || "0";
  try {
    await rz.cmd(`e search.in=range`, { signal });
    await rz.cmd(`e search.from=${from}`, { signal });
    await rz.cmd(`e search.to=${to}`, { signal });
    return await fn();
  } finally {
    await rz.cmd(`e search.in=${savedIn}`);
    await rz.cmd(`e search.from=${savedFrom}`);
    await rz.cmd(`e search.to=${savedTo}`);
  }
};

export interface RzSearchHit {
  address: number;
  size: number;
  flag: string;
}

interface SearchHitRow {
  ea: string;
  size: number;
  flag: string;
}

const hitRow = (hit: RzSearchHit): SearchHitRow => ({
  ea: eaFromOffset(knownAddr(hit.address) ?? 0),
  flag: hit.flag,
  size: hit.size,
});

/**
 * Reject a free-form search argument (a regex, assembly text, or a gadget
 * filter) that carries a rizin command-injection character before it is
 * interpolated into the search command line. Unlike `search_bytes`
 * (hex-charset) and `search_string` (hex-encoded), these arguments reach the
 * `-q0` pipe verbatim, where `;`/newline chain a second command, `>`/`<`
 * redirect to a file, and backtick/`$()` substitute — so they go through the
 * same guard `rizin_command` applies. (`;`-separated assembly never worked
 * through this transport anyway: rizin runs the second instruction as its own
 * command.)
 */
export const validateSearchArg = (kind: string, value: string): string => {
  const bad = forbiddenSyntaxReason(value);
  if (bad) {
    throw new Error(
      `omp-re: ${kind}: ${bad} is not allowed in a search argument`
    );
  }
  return value;
};

/** Core shared by the three search tools: run one JSON search command and render its hits as paginated rows. */
export const searchCommand = async (
  rz: RzSession,
  command: string,
  label: string,
  params: { offset?: number; limit?: number }
): Promise<ReToolResult> => {
  const hits = (await rz.cmdj<RzSearchHit[]>(command)) ?? [];
  const { page, total } = paginate(hits, params.offset, params.limit);
  const rows = page.map(hitRow);
  const result = await jsonResult(
    pageHeader(label, rows, total, params.offset),
    rows
  );
  return markEmpty(result, rows.length === 0);
};

/** Run a {@link searchCommand}, optionally scoped to the function named by `in_function` (whole binary when omitted). */
export const scopedSearch = async (
  rz: RzSession,
  command: string,
  label: string,
  params: { in_function?: string; offset?: number; limit?: number },
  signal?: AbortSignal
): Promise<ReToolResult> => {
  if (params.in_function === undefined) {
    return searchCommand(rz, command, label, params);
  }
  const range = await functionRange(rz, params.in_function, signal);
  return withSearchScope(rz, range.from, range.to, signal, () =>
    searchCommand(rz, command, `${label} in ${range.name}`, params)
  );
};

export interface RzGadgetOpcode {
  offset: number;
  size: number;
  opcode: string;
  type: string;
}

export interface RzGadgetRow {
  opcodes: RzGadgetOpcode[];
  retaddr: number;
  size: number;
}

/** ROP/COP gadget search, native: prime the gadget cache with a text-mode run, then take rizin's own JSON rows. The filter string is rizin's own gadget filter. */
export const searchGadgets = async (
  rz: RzSession,
  kind: "rop" | "cop",
  filter: string | undefined,
  params: { offset?: number; limit?: number }
): Promise<ReToolResult> => {
  const base = kind === "rop" ? "/R" : "/C";
  const safeFilter =
    filter === undefined
      ? undefined
      : validateSearchArg("search_gadgets", filter);
  // 0.9.1: /Rj and /Cj emit nothing until a text-mode run populates the gadget cache.
  await rz.cmd(safeFilter === undefined ? base : `${base} ${safeFilter}`);
  const hits =
    (await rz.cmdj<RzGadgetRow[]>(
      safeFilter === undefined ? `${base}j` : `${base}j ${safeFilter}`
    )) ?? [];
  const rows = hits.map((hit) => ({
    ea: eaFromOffset(knownAddr(hit.retaddr) ?? 0),
    gadgets: hit.opcodes.map((op) => op.opcode),
    size: hit.size,
  }));
  const { page, total } = paginate(rows, params.offset, params.limit);
  const result = await jsonResult(
    pageHeader(`${kind.toUpperCase()} gadgets`, page, total, params.offset),
    page
  );
  return markEmpty(result, rows.length === 0);
};

export const registerSearchTools = (pi: ExtensionAPI): void => {
  const z = pi.zod;
  const offsetLimit = {
    in_function: z
      .string()
      .optional()
      .describe(
        "Restrict the search to the function at this address or name (its full extent); omit to search the whole binary."
      ),
    limit: z
      .number()
      .int()
      .optional()
      .describe(
        `Max results to return (default ${DEFAULT_LIMIT}, capped at ${MAX_LIMIT}).`
      ),
    offset: z
      .number()
      .int()
      .optional()
      .describe("Skip this many results (default 0)."),
  };

  const searchBytesParams = z.object({
    // Hex pairs, spaces optional; rizin's `..` byte-mask wildcard is honored (e.g. "8b 4f ..").
    pattern: z
      .string()
      .regex(/^[0-9a-fA-F.?]+(?:\s+[0-9a-fA-F.?]+)*$/u)
      .describe(
        'Raw hex bytes to search for, spaces optional; ".." masks one nibble (e.g. "8b 4f ..").'
      ),
    ...offsetLimit,
  });
  const searchStringParams = z.object({
    pattern: z
      .string()
      .min(1)
      .describe("Literal string to search for in the binary's raw bytes."),
    ...offsetLimit,
  });
  const searchRegexParams = z.object({
    pattern: z
      .string()
      .min(1)
      .describe("Regex over raw bytes (rizin /xr syntax)."),
    ...offsetLimit,
  });
  const searchAsmParams = z.object({
    instructions: z
      .string()
      .min(1)
      .describe(
        'Assembly text to assemble and search for (e.g. "push rbp; ret" for a gadget tail).'
      ),
    ...offsetLimit,
  });
  const searchValueParams = z.object({
    max: z
      .number()
      .int()
      .min(0)
      .optional()
      .describe("Inclusive upper bound of a value range (with min)."),
    min: z
      .number()
      .int()
      .min(0)
      .optional()
      .describe("Inclusive lower bound of a value range (with max)."),
    value: z
      .number()
      .int()
      .min(0)
      .optional()
      .describe("Exact value to search for (pass value, or min+max)."),
    width: z
      .enum(["1", "2", "4", "8"])
      .describe("Value byte width (endianness auto)."),
    ...offsetLimit,
  });
  const searchGadgetsParams = z.object({
    filter: z
      .string()
      .optional()
      .describe(
        'Substring filter on the disassembled gadget text (e.g. "pop rdi; ret").'
      ),
    kind: z
      .enum(["rop", "cop"])
      .describe("ROP (return-oriented) or COP (call-oriented) gadgets."),
    ...offsetLimit,
  });

  pi.registerTool({
    name: "search_bytes",
    label: "Search Bytes",
    description:
      "Search the open binary's raw bytes for a hex pattern (rizin /xj). '..' masks one nibble for wildcard matching. Returns each hit's address, length, and flag name.",
    approval: "read",
    loadMode: "essential",
    parameters: searchBytesParams,
    ...reRenderers({ body: "json", subject: "pattern", title: "Search bytes" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const hex = params.pattern.replaceAll(/\s+/gu, "");
      return scopedSearch(
        rz,
        `/xj ${hex}`,
        `hits for ${params.pattern}`,
        params,
        signal
      );
    },
  });

  pi.registerTool({
    name: "search_string",
    label: "Search String",
    description:
      "Search the open binary's raw bytes for a literal string (hex-encoded client-side, then rizin /xj). Finds matches everywhere, including code pages — unlike list_strings, which only reports rizin's detected string metadata.",
    approval: "read",
    loadMode: "essential",
    parameters: searchStringParams,
    ...reRenderers({
      body: "json",
      subject: "pattern",
      title: "Search string",
    }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const hex = Buffer.from(params.pattern, "utf-8").toString("hex");
      return scopedSearch(
        rz,
        `/xj ${hex}`,
        `hits for ${JSON.stringify(params.pattern)}`,
        params,
        signal
      );
    },
  });

  pi.registerTool({
    name: "search_regex_bytes",
    label: "Search Regex Bytes",
    description:
      "Search the open binary's raw bytes with a rizin /xr regex over bytes. Use for shaped patterns (e.g. an instruction encoding with a variable displacement).",
    approval: "read",
    loadMode: "essential",
    parameters: searchRegexParams,
    ...reRenderers({ body: "json", subject: "pattern", title: "Search regex" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      return scopedSearch(
        rz,
        `/xrj ${validateSearchArg("search_regex_bytes", params.pattern)}`,
        `regex hits for ${JSON.stringify(params.pattern)}`,
        params,
        signal
      );
    },
  });

  pi.registerTool({
    name: "search_asm",
    label: "Search Asm",
    description:
      "Assemble instruction text with the binary's arch config and search for the resulting bytes (rizin /aj). Same {ea, size, flag} rows as search_bytes.",
    approval: "read",
    loadMode: "essential",
    parameters: searchAsmParams,
    ...reRenderers({
      body: "json",
      subject: "instructions",
      title: "Search asm",
    }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      const text = validateSearchArg("search_asm", params.instructions);
      return scopedSearch(
        rz,
        `/aj ${text}`,
        `asm hits for ${JSON.stringify(params.instructions)}`,
        params,
        signal
      );
    },
  });

  pi.registerTool({
    name: "search_value",
    label: "Search Value",
    description:
      "Search for immediate values (rizin /v1j../v8j exact, /V1j../V8j range). Finds hardcoded constants, magic numbers, and pointer-sized immediates. Pass value for exact, or min+max for a range.",
    approval: "read",
    loadMode: "essential",
    parameters: searchValueParams,
    ...reRenderers({ body: "json", subject: "value", title: "Search value" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      if (
        params.value === undefined &&
        (params.min === undefined || params.max === undefined)
      ) {
        throw new Error(
          "Pass value (exact search) or both min and max (range search)."
        );
      }
      const command =
        params.value === undefined
          ? `/V${params.width}j ${params.min} ${params.max}`
          : `/v${params.width}j ${params.value}`;
      const label =
        params.value === undefined
          ? `values ${params.min}..${params.max} (${params.width}B)`
          : `value ${params.value} (${params.width}B)`;
      return scopedSearch(rz, command, `hits for ${label}`, params, signal);
    },
  });

  pi.registerTool({
    name: "search_gadgets",
    label: "Search Gadgets",
    description:
      "Search ROP (return-oriented) or COP (call-oriented) gadgets natively (rizin /R + /Rj, /C + /Cj). Rows carry the gadget's entry address, size, and disassembled instruction chain. Optional filter string (rizin's own gadget filter, e.g. \"pop rdi; ret\" or a regex-free substring).",
    approval: "read",
    loadMode: "essential",
    parameters: searchGadgetsParams,
    ...reRenderers({ body: "json", subject: "kind", title: "Search gadgets" }),
    async execute(_id, params, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      if (params.in_function === undefined) {
        return searchGadgets(rz, params.kind, params.filter, params);
      }
      const range = await functionRange(rz, params.in_function, signal);
      return withSearchScope(rz, range.from, range.to, signal, () =>
        searchGadgets(rz, params.kind, params.filter, params)
      );
    },
  });
};
