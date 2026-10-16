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
import { isAbsolute, join, resolve } from "node:path";

/** The directory omp-re writes output artifacts to (`OMPRE_OUTPUT_DIR`, else `<tmpdir>/omp-re-out`). */
export function outputDir(): string {
	const configured = (process.env.OMPRE_OUTPUT_DIR ?? "").trim();
	return configured !== "" ? resolve(configured) : join(tmpdir(), "omp-re-out");
}

/**
 * Validate a model-supplied output filename: a bare basename of safe
 * characters, no path separators, no `..`, not absolute. This is the guard
 * that keeps a chosen name from escaping {@link outputDir}.
 */
export function safeBasename(name: string): string {
	const trimmed = name.trim();
	if (trimmed === "" || trimmed === "." || trimmed === "..") throw new Error(`omp-re: invalid output filename ${JSON.stringify(name)}`);
	if (!/^[A-Za-z0-9._-]+$/.test(trimmed) || trimmed.includes("..") || isAbsolute(trimmed)) {
		throw new Error(`omp-re: invalid output filename ${JSON.stringify(name)} — use a bare name of letters, digits, '.', '_' or '-' (no path separators)`);
	}
	return trimmed;
}

/** Ensure {@link outputDir} exists and return the absolute path for `basename` inside it. The returned path is always within the output directory (verified after resolve). */
export async function prepareOutputPath(basename: string): Promise<string> {
	const dir = outputDir();
	const full = resolve(dir, safeBasename(basename));
	// Defense in depth: safeBasename already forbids separators, but confirm the join stayed inside the directory.
	if (full !== join(dir, basename) || !full.startsWith(`${dir}/`)) {
		throw new Error(`omp-re: refusing to write outside the output directory: ${JSON.stringify(basename)}`);
	}
	await mkdir(dir, { recursive: true });
	return full;
}
