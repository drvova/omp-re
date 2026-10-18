/**
 * Anchor fingerprints: find a report's code again in a different build.
 *
 * A `rizin_command` cited in a report is usually pinned to an address (`pdf @
 * sym.decrypt_config`, `px 64 @ 0x4012a0`). On the next build that anchor can
 * vanish (the symbol was renamed or stripped) or point somewhere else (a numeric
 * address whose code moved). When `/re report` writes the manifest with the
 * report's own binary still open, each anchored entry gets a fingerprint of the
 * function containing the anchor — name, offset, size, block count, the anchor's
 * offset into the function, and the function's mnemonic sequence. `/re carry`
 * then searches the new build's function list for the closest match (size and
 * block count prefilter, then mnemonic-sequence similarity) and re-runs the
 * command at the matched function plus the same delta.
 *
 * Mnemonics only, never operands: a rebuild changes addresses, displacements,
 * and register allocation long before it changes the instruction mix, so the
 * mnemonic sequence is the cheap, stable shape of a function.
 */
import type { RzSession } from "./rizin.ts";
import { eaFromOffset, resolveNumericAddr } from "./rizin.ts";

/** Cap on mnemonics kept per fingerprint: plenty to identify a function, small enough to keep the manifest and the O(n·m) similarity cheap. */
const MAX_MNEMONICS = 512;
/** Cap on candidate functions scored per relocation (the size/block-count prefilter usually leaves far fewer). */
const MAX_CANDIDATES = 64;
/** Minimum mnemonic-sequence similarity for a candidate to count as the same function. */
export const RELOCATE_THRESHOLD = 0.8;

export interface AnchorFingerprint {
  /** The anchor expression as cited (`sym.fib`, `0x1292`). */
  anchor: string;
  /** Name of the function containing the anchor, in the report's binary. */
  function: string;
  /** That function's start address (hex) in the report's binary. */
  offset: string;
  /** Byte offset of the anchor from the function start, so an anchor inside a function relocates to the same spot. */
  delta: number;
  size: number;
  nbbs: number;
  mnemonics: string[];
}

export interface Relocation {
  function: string;
  /** The matched function's start address (hex) in the new build. */
  offset: string;
  /** Where to re-run the command: the matched function's start plus the recorded delta (hex). */
  addr: string;
  similarity: number;
}

interface FnInfo {
  offset: number;
  name: string;
  size: number;
  nbbs: number;
}

const parseJson = <T>(raw: string): T | undefined => {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return undefined;
  }
};

/** The mnemonic sequence of the function starting at `offset` (`pdfj`), or undefined when rizin has none there. */
const mnemonicsAt = async (
  rz: RzSession,
  offset: number
): Promise<string[] | undefined> => {
  const pdf = parseJson<{ ops?: { disasm?: unknown; type?: unknown }[] }>(
    await rz.cmd(`pdfj @ ${eaFromOffset(offset)}`)
  );
  if (!pdf?.ops) {
    return undefined;
  }
  return pdf.ops
    .filter((op) => typeof op.disasm === "string" && op.type !== "invalid")
    .map((op) =>
      (op.disasm as string).trim().split(/\s+/u, 1)[0]!.toLowerCase()
    )
    .slice(0, MAX_MNEMONICS);
};

/** Fingerprint the function containing `anchor` in the open build, or undefined when the anchor is in no function (data, a gap) or doesn't resolve. Never throws. */
export const fingerprintAnchor = async (
  rz: RzSession,
  anchor: string
): Promise<AnchorFingerprint | undefined> => {
  try {
    const at = await resolveNumericAddr(rz, anchor);
    const fn = parseJson<FnInfo[]>(
      await rz.cmd(`afij @ ${eaFromOffset(at)}`)
    )?.[0];
    if (!fn || typeof fn.offset !== "number") {
      return undefined;
    }
    const mnemonics = await mnemonicsAt(rz, fn.offset);
    if (!mnemonics || mnemonics.length === 0) {
      return undefined;
    }
    return {
      anchor,
      delta: at - fn.offset,
      function: fn.name,
      mnemonics,
      nbbs: fn.nbbs,
      offset: eaFromOffset(fn.offset),
      size: fn.size,
    };
  } catch {
    return undefined;
  }
};

/** Similarity of two sequences: 2·LCS / (|a| + |b|), in [0, 1]. */
export const sequenceSimilarity = (
  a: readonly string[],
  b: readonly string[]
): number => {
  if (a.length === 0 && b.length === 0) {
    return 1;
  }
  let prev = Array.from({ length: b.length + 1 }, () => 0);
  for (let i = 1; i <= a.length; i += 1) {
    const cur = Array.from({ length: b.length + 1 }, () => 0);
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] =
        a[i - 1] === b[j - 1]
          ? prev[j - 1]! + 1
          : Math.max(prev[j]!, cur[j - 1]!);
    }
    prev = cur;
  }
  return (2 * prev[b.length]!) / (a.length + b.length);
};

/**
 * Find the function in the open build that best matches `fp`: prefilter the
 * function list to sizes within ±50% and block counts within ±50% (+2), rank by
 * how close size and block count are, score the top {@link MAX_CANDIDATES} by
 * mnemonic similarity, and return the best at or above {@link RELOCATE_THRESHOLD}
 * (ties go to a candidate with the recorded name). Never throws.
 */
export const relocateAnchor = async (
  rz: RzSession,
  fp: AnchorFingerprint
): Promise<Relocation | undefined> => {
  try {
    const fns = parseJson<FnInfo[]>(await rz.cmd("aflj")) ?? [];
    const candidates = fns
      .filter(
        (fn) =>
          typeof fn.offset === "number" &&
          Math.abs(fn.size - fp.size) <= fp.size * 0.5 &&
          Math.abs(fn.nbbs - fp.nbbs) <= fp.nbbs * 0.5 + 2
      )
      .toSorted(
        (x, y) =>
          Math.abs(x.size - fp.size) / fp.size +
          Math.abs(x.nbbs - fp.nbbs) -
          (Math.abs(y.size - fp.size) / fp.size + Math.abs(y.nbbs - fp.nbbs))
      )
      .slice(0, MAX_CANDIDATES);
    let best: { fn: FnInfo; similarity: number } | undefined;
    for (const fn of candidates) {
      const mnemonics = await mnemonicsAt(rz, fn.offset);
      if (!mnemonics) {
        continue;
      }
      const similarity = sequenceSimilarity(fp.mnemonics, mnemonics);
      const better =
        !best ||
        similarity > best.similarity ||
        (similarity === best.similarity && fn.name === fp.function);
      if (better) {
        best = { fn, similarity };
      }
    }
    if (!best || best.similarity < RELOCATE_THRESHOLD) {
      return undefined;
    }
    return {
      addr: eaFromOffset(best.fn.offset + fp.delta),
      function: best.fn.name,
      offset: eaFromOffset(best.fn.offset),
      similarity: Math.round(best.similarity * 1000) / 1000,
    };
  } catch {
    return undefined;
  }
};
