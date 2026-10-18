/**
 * `deobfuscate` — reveal obfuscated bytes in place without touching the file.
 *
 * Malware hides strings behind a byte transform (xor/add/sub with a key) and
 * embeds configs behind a cipher (RC4, AES, …). rizin's `wo*` block-write
 * operations and `woD` block-decrypt compute exactly these, but they write the
 * in-memory buffer. This tool runs one transform under rizin's write cache
 * (`io.cache`), reads the transformed window back, then resets the cache
 * (`wc-`) — so the result is observed and the buffer is restored, with nothing
 * committed to disk (the static session opened the file read-only, and the
 * cache entry is never written). It is read-tier and its output is evidence:
 * the deobfuscated bytes/string at an address are an observation of the file.
 *
 * Book: basic_commands/write.md ("Implementing cipher algorithms with wo").
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { eaFromOffset, resolveNumericAddr } from "./rizin.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

/** Keyed byte transforms: each XORs/adds/… the window with a repeating key. */
const KEYED_OPS: Record<string, string> = {
  add: "woa",
  and: "woA",
  or: "woo",
  sub: "wos",
  xor: "wox",
};
/** Endian swaps over the window (no key). */
const SWAP_OPS: Record<string, string> = {
  swap2: "wo2",
  swap4: "wo4",
  swap8: "wo8",
};
const OPS = [
  "xor",
  "add",
  "sub",
  "or",
  "and",
  "swap2",
  "swap4",
  "swap8",
  "decrypt",
] as const;

const HEX = /^[0-9a-fA-F]+$/u;
const ALGO = /^[a-z0-9][a-z0-9-]*$/iu;
const MAX_SIZE = 65_536;

const hexArg = (key: string, value: string | undefined): string => {
  if (value === undefined || value === "") {
    throw new Error(
      `omp-re: deobfuscate: ${key} is required (hex bytes, e.g. deadbeef)`
    );
  }
  const h = value.replaceAll(/\s+/gu, "");
  if (!HEX.test(h) || h.length % 2 !== 0) {
    throw new Error(
      `omp-re: deobfuscate: ${key} must be an even number of hex digits (got ${JSON.stringify(value)})`
    );
  }
  return h;
};

/** Build the one `wo*` command (operating on the current block at `ea`). Throws on missing/invalid params before anything runs. */
export const deobfuscateCommand = (
  op: string,
  ea: string,
  params: { key?: string; algo?: string; iv?: string }
): string => {
  if (op in KEYED_OPS) {
    return `${KEYED_OPS[op]} ${hexArg("key", params.key)} @ ${ea}`;
  }
  if (op in SWAP_OPS) {
    return `${SWAP_OPS[op]} @ ${ea}`;
  }
  if (op === "decrypt") {
    if (params.algo === undefined || !ALGO.test(params.algo)) {
      throw new Error(
        `omp-re: deobfuscate: decrypt needs an algo (e.g. rc4, aes-cbc); got ${JSON.stringify(params.algo)}`
      );
    }
    const key = hexArg("key", params.key);
    const iv =
      params.iv !== undefined && params.iv !== ""
        ? ` ${hexArg("iv", params.iv)}`
        : "";
    return `woD ${params.algo} ${key}${iv} @ ${ea}`;
  }
  throw new Error(`omp-re: deobfuscate: unknown op ${JSON.stringify(op)}`);
};

export const registerDeobfuscateTools = (pi: ExtensionAPI): void => {
  const z = pi.zod;
  const params = z.object({
    addr: z
      .string()
      .describe(
        "Address (or name/expression) where the obfuscated bytes start."
      ),
    algo: z
      .string()
      .optional()
      .describe(
        "Cipher name for decrypt, e.g. rc4, aes-cbc, aes-ecb (see rizin's crypto plugins)."
      ),
    iv: z.string().optional().describe("Optional hex IV for decrypt."),
    key: z
      .string()
      .optional()
      .describe(
        "Hex key bytes for xor/add/sub/or/and and for decrypt, e.g. `deadbeef` (repeated over the window)."
      ),
    op: z
      .enum(OPS)
      .describe(
        "xor/add/sub/or/and: byte transform with `key`. swap2/swap4/swap8: endian swap. decrypt: a cipher via `algo`+`key`(+`iv`)."
      ),
    size: z
      .number()
      .describe(`Number of bytes to transform and show (1..${MAX_SIZE}).`),
  });

  pi.registerTool({
    name: "deobfuscate",
    label: "Deobfuscate",
    description:
      "Reveal obfuscated bytes in place: apply a byte transform (xor/add/sub/or/and with a key), an endian swap, or a cipher decrypt (decrypt with algo+key[+iv]) to a window and show the result as hex and as a string. Common for unmasking xor-hidden strings and decrypting embedded configs (RC4/AES). The transform runs under rizin's write cache and is reset immediately — the file on disk is never modified. Read-only and recorded as evidence.",
    approval: "read",
    loadMode: "essential",
    parameters: params,
    ...reRenderers({ body: "text", subject: "op", title: "Deobfuscate" }),
    async execute(_id, p, signal, _onUpdate, ctx) {
      const rz = await ensureRizin(ctx, { signal });
      requireBinary(getState(ctx));
      if (!Number.isInteger(p.size) || p.size <= 0 || p.size > MAX_SIZE) {
        throw new Error(
          `omp-re: deobfuscate: size must be an integer in 1..${MAX_SIZE}`
        );
      }
      const ea = eaFromOffset(await resolveNumericAddr(rz, p.addr, signal));
      // throws on bad params before any state change
      const command = deobfuscateCommand(p.op, ea, p);

      // Save the io-cache setting and block size, transform under the cache, read, then revert everything.
      const oldCache = (await rz.cmd("e io.cache", { signal })).trim();
      const oldBlock = (await rz.cmd("%v $b", { signal })).trim();
      try {
        await rz.cmd("e io.cache=true", { signal });
        await rz.cmd(`b ${p.size}`, { signal });
        const { stderr } = await rz.cmdWithStderr(command, { signal });
        const err = stderr.trim();
        if (err) {
          return {
            ...textResult(`deobfuscate: ${p.op} @ ${ea}`, `${command}: ${err}`),
            isError: true,
          };
        }
        const hex = (await rz.cmd(`p8 ${p.size} @ ${ea}`, { signal })).trim();
        const str = (await rz.cmd(`ps @ ${ea}`, { signal })).trim();
        return textResult(
          `deobfuscate: ${p.op} ${p.size} bytes @ ${ea}`,
          `hex: ${hex}\nstring: ${str}`,
          { ctx, tool: "deobfuscate" }
        );
      } finally {
        // revert the cached transform — the file is never written
        await rz.cmd("wc-", { signal }).catch(() => {});
        await rz.cmd(`b ${oldBlock}`, { signal }).catch(() => {});
        await rz
          .cmd(`e io.cache=${oldCache || "false"}`, { signal })
          .catch(() => {});
      }
    },
  });
};
