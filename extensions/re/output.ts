/**
 * The one directory omp-re writes files to.
 *
 * omp-re never writes to the sample on disk (SECURITY.md: "Mutations never
 * touch the file on disk"). A few debugger capabilities, though, need to *emit*
 * a separate artifact — a dump of the live process's memory too large to return
 * inline. Those files go here and nowhere else: a single dedicated directory,
 * never a path the model chose, so a tool can't traverse out of it or overwrite
 * an arbitrary file.
 *
 * The directory is `OMPRE_OUTPUT_DIR` when set, else `<tmpdir>/omp-re-out`.
 * Callers pass a basename only ({@link safeBasename} rejects separators and
 * `..`); {@link prepareOutputPath} joins it under the directory, creates the
 * directory, and returns the absolute path to write to.
 */
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";

import { rzQuote } from "./rizin.ts";

/** Forward-slash form of a path, which rizin accepts on every platform. Used by {@link rizinPathArg} and by callers that build their own rizin argument. */
export const toRizinPath = (path: string): string => path.replaceAll("\\", "/");

/**
 * A rizin command argument for an output path: forward-slash normalized (rizin
 * accepts `/` on every platform) and single-quoted, so rizin takes the whole
 * path literally. This matters on Windows, where a temp dir is an 8.3 short
 * name like `C:\Users\RUNNER~1\...`: raw, rizin reads the `~` as its grep
 * operator (and `;`/`|`/`>` as separators), so `Ps C:/…/RUNNER~1/x` writes to
 * the wrong place or errors. Quoting makes every byte literal — the same guard
 * annotations and `Fs` already use. Callers keep the native path for Node's own
 * fs calls and for what they report to the user.
 */
export const rizinPathArg = (path: string): string =>
  rzQuote(toRizinPath(path));

/**
 * Reject a path that can't ride the NUL-framed pipe. The path reaches rizin
 * only through {@link rizinPathArg} (single-quoted), so every shell
 * metacharacter — and a Windows drive colon, backslash or `~` short-name — is
 * already made literal there; the one thing quoting can't survive is a line
 * break or NUL, which would end the pipe line. (The model-supplied part is a
 * {@link safeBasename} besides.)
 */
const assertRizinSafePath = (path: string): void => {
  if (/[\r\n\0]/u.test(path)) {
    throw new Error(
      `omp-re: the output path ${JSON.stringify(path)} contains a line break or NUL`
    );
  }
};

/** The directory omp-re writes output artifacts to (`OMPRE_OUTPUT_DIR`, else `<tmpdir>/omp-re-out`). */
export const outputDir = (): string => {
  const configured = (process.env.OMPRE_OUTPUT_DIR ?? "").trim();
  return configured === "" ? join(tmpdir(), "omp-re-out") : resolve(configured);
};

/**
 * Validate a model-supplied output filename: a bare basename of safe
 * characters, no path separators, no `..`, not absolute. This is the guard
 * that keeps a chosen name from escaping {@link outputDir}.
 */
export const safeBasename = (name: string): string => {
  const trimmed = name.trim();
  if (trimmed === "" || trimmed === "." || trimmed === "..") {
    throw new Error(`omp-re: invalid output filename ${JSON.stringify(name)}`);
  }
  if (
    !/^[A-Za-z0-9._-]+$/u.test(trimmed) ||
    trimmed.includes("..") ||
    isAbsolute(trimmed)
  ) {
    throw new Error(
      `omp-re: invalid output filename ${JSON.stringify(name)} — use a bare name of letters, digits, '.', '_' or '-' (no path separators)`
    );
  }
  return trimmed;
};

/** Ensure {@link outputDir} exists and return the absolute path for `basename` inside it. The returned path is always within the output directory (verified after resolve). */
export const prepareOutputPath = async (basename: string): Promise<string> => {
  const dir = outputDir();
  const full = resolve(dir, safeBasename(basename));
  // Defense in depth: safeBasename already forbids separators, but confirm the
  // join stayed inside the directory. `sep` (not a literal `/`) so the
  // containment check holds on Windows, where resolve/join use `\`.
  if (full !== join(dir, basename) || !full.startsWith(`${dir}${sep}`)) {
    throw new Error(
      `omp-re: refusing to write outside the output directory: ${JSON.stringify(basename)}`
    );
  }
  await mkdir(dir, { recursive: true });
  return full;
};

/**
 * Like {@link prepareOutputPath}: the native absolute path for `basename`,
 * directory created. Used when rizin itself writes the file (a project
 * `.rzdb`, a signature `.pat`), so the caller reports/stats this path and
 * hands rizin {@link rizinPathArg}(it) for the command.
 */
export const rizinOutputPath = async (basename: string): Promise<string> => {
  const full = await prepareOutputPath(basename);
  assertRizinSafePath(full);
  return full;
};

/**
 * The absolute path of a subdirectory `basename` inside {@link outputDir},
 * safe to hand to rizin. With `create`, the directory is made; without it (a
 * load), the caller checks existence. Used for trace sessions, which rizin
 * writes and reads itself (so the path, not just the bytes, reaches rizin).
 */
export const outputSubdir = async (
  basename: string,
  create: boolean
): Promise<string> => {
  const dir = outputDir();
  const full = resolve(dir, safeBasename(basename));
  if (full !== join(dir, basename) || !full.startsWith(`${dir}${sep}`)) {
    throw new Error(
      `omp-re: refusing to use a path outside the output directory: ${JSON.stringify(basename)}`
    );
  }
  assertRizinSafePath(full);
  if (create) {
    await mkdir(full, { recursive: true });
  }
  // native path — the caller wraps it with rizinPathArg for the rizin command
  return full;
};
