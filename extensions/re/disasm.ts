/**
 * Function disassembly via rizin's `pdfj`, rendered as compact annotated text.
 * The one formatter behind `disassemble_function`, the decompiler fallback,
 * and the code view, so all three show the same lines for the same function.
 */
import { addrOf, eaFromOffset } from "./rizin.ts";
import type { RzSession } from "./rizin.ts";

/** One pdfj op. rizin reports the op address as `offset`; incoming references arrive as `xrefs_to` rows carrying `addr`. `comment` is base64. */
export interface PdfjOp {
  offset?: number;
  addr?: number;
  disasm: string;
  /** Base64-encoded; decode before display. */
  comment?: string;
  /** Flag/symbol names attached at this address. */
  flags?: string[];
  /** Other locations that reference (jump/call to) this instruction's address. */
  xrefs_to?: { addr?: number; offset?: number; type: string }[];
}

/** pdfj's top level: the function name and start `addr`, plus its ops. */
export interface PdfjResult {
  name?: string;
  addr?: number;
  offset?: number;
  ops: PdfjOp[];
}

/** Render one op as 1-2 lines: an optional flag/label line, then the address-prefixed instruction with any comment/xrefs folded in as a trailing annotation. Compact on purpose — this feeds an LLM context window. */
export function formatPdfOp(op: PdfjOp): string[] {
  const opAddr = addrOf(op);
  if (opAddr === undefined) {
    return [];
  }
  const lines: string[] = [];
  if (op.flags && op.flags.length > 0) {
    lines.push(`${op.flags.join(", ")}:`);
  }

  const annotations: string[] = [];
  if (op.comment) {
    try {
      const decoded = Buffer.from(op.comment, "base64")
        .toString("utf-8")
        .trim();
      if (decoded.length > 0) {
        annotations.push(decoded);
      }
    } catch {
      // Malformed base64 in a pdfj comment must never crash the tool; just omit the annotation.
    }
  }
  const xrefs = (op.xrefs_to ?? []).flatMap((xref) => {
    const from = addrOf(xref);
    return from === undefined ? [] : [`${xref.type} ${eaFromOffset(from)}`];
  });
  if (xrefs.length > 0) {
    annotations.push(`xrefs: ${xrefs.join(", ")}`);
  }
  const suffix = annotations.length > 0 ? `  ; ${annotations.join(" | ")}` : "";
  lines.push(`${eaFromOffset(opAddr)}  ${op.disasm}${suffix}`);
  return lines;
}

export interface Disassembly {
  name?: string;
  opCount: number;
  lines: string[];
}

/** Disassemble the function containing `ea`. Returns null when rizin knows no function there. */
export async function disassembleAt(
  rz: RzSession,
  ea: string,
  signal?: AbortSignal
): Promise<Disassembly | null> {
  const pdf = await rz.cmdj<PdfjResult>(`pdfj @ ${ea}`, { signal });
  if (!pdf || !Array.isArray(pdf.ops) || pdf.ops.length === 0) {
    return null;
  }
  return {
    lines: pdf.ops.flatMap(formatPdfOp),
    name: pdf.name,
    opCount: pdf.ops.length,
  };
}
