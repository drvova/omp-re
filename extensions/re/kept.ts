/**
 * Kept definitions: the helpers the model builds in `run` cells, persisted so
 * a fresh omp process starts with them.
 *
 * Each top-level definition a successful cell made (cell.ts decides what
 * counts: functions, classes, `const`s with static initializers) is written
 * to its own file, `<dir>/<name>.ts`, holding exactly that definition's
 * source. A new session's namespace loads every unit back (namespace.ts),
 * each in isolation, so a broken one is reported and skipped instead of
 * stopping the others. Work is never persisted, only definitions.
 *
 * The directory is `OMPRE_KEPT_DIR` when set, else `<omp agent dir>/re/kept`
 * (next to the evidence blobs and audit logs). It is shared by every session
 * and subagent on this machine, so a helper one session writes is there for
 * the next.
 */
import { randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { getAgentDir } from "@oh-my-pi/pi-utils";
import type { Definition } from "./cell.ts";

export interface KeptUnit {
	name: string;
	source: string;
	path: string;
}

const UNIT_EXT = ".ts";

/** A JavaScript identifier, so a unit name can never become a path (`..`, `/`). */
const IDENTIFIER = /^[\p{ID_Start}$_][\p{ID_Continue}$\u200c\u200d]*$/u;

export function keptDir(): string {
	return process.env.OMPRE_KEPT_DIR || join(getAgentDir(), "re", "kept");
}

export function isUnitName(name: string): boolean {
	return IDENTIFIER.test(name);
}

function unitPath(name: string): string {
	if (!isUnitName(name)) throw new Error(`omp-re: ${JSON.stringify(name)} is not a definition name`);
	return join(keptDir(), `${name}${UNIT_EXT}`);
}

/** Write each definition to its unit file (temp file then rename, so a reader never sees half a unit). Returns the names written. */
export async function saveDefinitions(definitions: readonly Definition[]): Promise<string[]> {
	if (definitions.length === 0) return [];
	const dir = keptDir();
	await mkdir(dir, { recursive: true, mode: 0o700 });
	const saved: string[] = [];
	for (const def of definitions) {
		const target = unitPath(def.name);
		const tmp = join(dir, `.${def.name}.${process.pid}.${randomUUID()}.tmp`);
		await writeFile(tmp, `${def.source}\n`, { mode: 0o600 });
		await rename(tmp, target);
		saved.push(def.name);
	}
	return saved;
}

/** Every kept unit, by name (a unit that names another loads on the namespace's retry pass, so order does not matter). An unreadable directory is an empty one. */
export async function listKept(): Promise<KeptUnit[]> {
	const dir = keptDir();
	let names: string[];
	try {
		names = await readdir(dir);
	} catch {
		return [];
	}
	const units: KeptUnit[] = [];
	for (const file of names) {
		if (!file.endsWith(UNIT_EXT)) continue;
		const name = file.slice(0, -UNIT_EXT.length);
		if (!isUnitName(name)) continue;
		const path = join(dir, file);
		try {
			units.push({ name, source: (await readFile(path, "utf8")).trimEnd(), path });
		} catch {
			// Removed between readdir and read (another session's forget): not kept any more.
		}
	}
	return units.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** Delete one kept unit. Returns whether there was one. */
export async function forgetKept(name: string): Promise<boolean> {
	try {
		await unlink(unitPath(name));
		return true;
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw err;
	}
}
