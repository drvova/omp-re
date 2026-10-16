/**
 * The single source of truth for what an `re.annotation` means to rizin.
 *
 * `annotationCommands()` turns "make this annotation's value X" into rizin
 * commands; the forward mutate tools (value = requested), `/re undo` (value =
 * oldValue), and replay after a respawn or reload (value = newValue) all go
 * through it, so a command template can never drift between the three.
 *
 * Annotations live in rizin's process memory only. Whenever a fresh process
 * is spawned for a binary (reopen, `--continue`, respawn after a timeout,
 * tree navigation), `liveAnnotations()` recomputes which annotations the
 * current session branch says should be applied, and `replayAnnotations()`
 * re-applies them, so the rizin state always matches what the session log
 * claims.
 */
import type { SessionEntry } from "@oh-my-pi/pi-coding-agent";
import { customEntries } from "./entries.ts";
import { rzQuote, validateAddr, validateIdent, validateText, validateTypeLike, type RzSession } from "./rizin.ts";

export type AnnotationKind =
	| "rename_function"
	| "rename_variable"
	| "set_comment"
	| "set_prototype"
	| "set_variable_type"
	| "define_function"
	| "set_calling_convention"
	| "set_flag"
	| "set_arch_hint"
	| "set_data"
	| "set_string"
	| "set_format";

export interface AnnotationData {
	kind: string;
	ea: string;
	oldValue: string;
	newValue: string;
	/** Extra identifier beyond ea/oldValue/newValue — only set_variable_type needs it (the variable name; old/new values there are types). */
	target?: string;
	evidenceId?: string;
	ungrounded?: boolean;
}

/** One annotation still in effect on the current branch, with the session entry id `/re undo` marks. */
export interface LiveAnnotation {
	entryId: string;
	data: AnnotationData;
}

/**
 * rizin commands that set annotation `kind` at `ea` to `to`. `from` is the
 * value being replaced — only rename_variable needs it (`afvn` addresses the
 * variable by its current name).
 */
export function annotationCommands(kind: string, ea: string, to: string, from: string, target?: string): string[] {
	const at = `@ ${validateAddr(ea)}`;
	switch (kind) {
		case "rename_function":
			return [`afn ${rzQuote(validateIdent("name", to))} ${at}`];
		case "rename_variable":
			return [`afvn ${rzQuote(validateIdent("name", to))} ${rzQuote(validateIdent("name", from))} ${at}`];
		case "set_comment":
			// rizin's CC appends to an existing comment, so a replace is always clear-then-write.
			return to === "" ? [`CC- ${at}`] : [`CC- ${at}`, `CC ${rzQuote(validateText(to))} ${at}`];
		case "set_prototype":
			// An empty value only arises when undoing onto a function rizin had no signature for: nothing to restore.
			return to === "" ? [] : [`afs ${rzQuote(validateTypeLike("sig", to))} ${at}`];
		case "set_variable_type":
			if (!target) throw new Error("omp-re: set_variable_type annotation is missing the variable name");
			return to === "" ? [] : [`afvt ${rzQuote(validateIdent("var", target))} ${rzQuote(validateTypeLike("type", to))} ${at}`];
		case "define_function":
			// `to` is a non-empty sentinel (the function name rizin assigned) when a function should exist, "" when it should not.
			return to === "" ? [`af- ${at}`] : [`af ${at}`];
		case "set_calling_convention":
			// A function always has some convention, so both the forward value and the restored one are non-empty cc names.
			return [`afc ${validateIdent("cc", to)} ${at}`];
		case "set_flag":
			// The flag at `ea` is named `to` (was `from`): drop the old name, add the new. Either side may be "" (no flag).
			return [...(from === "" ? [] : [`f- ${validateIdent("flag", from)}`]), ...(to === "" ? [] : [`f ${validateIdent("flag", to)} ${at}`])];
		case "set_arch_hint":
			// `to` encodes the arch/bits hint at `ea` as `arch=<a>` and/or `bits=<n>` joined by `;`; "" means no hint (undo deletes both).
			return to === "" ? [`aha- ${at}`, `ahb- ${at}`] : archHintCommands(to, at);
		case "set_data":
			// `to` is `<size>` or `<size>:<repeat>`; "" removes the data mark.
			return to === "" ? [`Cd- ${at}`] : [`Cd ${dataMarkArgs(to)} ${at}`];
		case "set_string":
			// `to` is a byte size, or "auto" to let rizin detect the encoding/length; "" removes the string mark.
			return to === "" ? [`Cs- ${at}`] : [`Cs${to === "auto" ? "" : ` ${intArg("size", to)}`} ${at}`];
		case "set_format":
			// `to` is `<size> <pf-format[ fields...]>`; "" removes the format mark.
			return to === "" ? [`Cf- ${at}`] : [`Cf ${formatMarkArgs(to)} ${at}`];
		default:
			throw new Error(`omp-re: unknown annotation kind: ${kind}`);
	}
}

/** A positive integer argument (data/string/format sizes). */
function intArg(key: string, value: string): string {
	if (!/^[0-9]+$/.test(value) || value === "0") throw new Error(`omp-re: invalid ${key}: ${JSON.stringify(value)} — a positive integer`);
	return value;
}

/** `Cd` arguments from `<size>` or `<size>:<repeat>`. */
function dataMarkArgs(encoded: string): string {
	const [size, repeat] = encoded.split(":", 2);
	return repeat === undefined ? intArg("size", size ?? "") : `${intArg("size", size ?? "")} ${intArg("repeat", repeat)}`;
}

/** `Cf` arguments from `<size> <pf-format[ fields...]>`. The format is a pf format string plus optional field names; validated to a safe charset (it reaches rizin through the pipe, so no separators/framing bytes). */
function formatMarkArgs(encoded: string): string {
	const sp = encoded.indexOf(" ");
	if (sp === -1) throw new Error("omp-re: set_format needs a size and a pf format, e.g. `8 xxdd field1 field2`");
	const size = intArg("size", encoded.slice(0, sp));
	const format = encoded.slice(sp + 1).trim();
	if (!/^[A-Za-z0-9_ .*[\]]+$/.test(format)) throw new Error(`omp-re: invalid pf format: ${JSON.stringify(format)}`);
	return `${size} ${format}`;
}

/** Build the `aha <arch>` / `ahb <bits>` commands from an encoded arch-hint value (`arch=arm;bits=16`). Each part is validated so a malformed hint fails here, not at rizin. */
export function archHintCommands(encoded: string, at: string): string[] {
	const cmds: string[] = [];
	for (const part of encoded.split(";")) {
		const [key, value] = part.split("=", 2);
		if (key === "arch") cmds.push(`aha ${validateIdent("arch", value ?? "")} ${at}`);
		else if (key === "bits") {
			if (!/^(8|16|32|64)$/.test(value ?? "")) throw new Error(`omp-re: invalid arch hint bits: ${JSON.stringify(value)} — one of 8, 16, 32, 64`);
			cmds.push(`ahb ${value} ${at}`);
		} else throw new Error(`omp-re: invalid arch hint ${JSON.stringify(part)} — use arch=<name> and/or bits=<n>`);
	}
	if (cmds.length === 0) throw new Error("omp-re: set_arch_hint needs arch and/or bits");
	return cmds;
}

/**
 * Annotations recorded against `binaryPath` on this branch and not since
 * undone, oldest first. An annotation belongs to whichever binary the most
 * recent `re.binary` entry before it opened, so switching binaries mid-session
 * never replays one binary's renames onto another.
 */
export function liveAnnotations(entries: readonly SessionEntry[], binaryPath: string): LiveAnnotation[] {
	const undone = new Set<string>();
	for (const entry of customEntries(entries, "re.undo")) {
		const marker = entry.data as { undidEntryId?: unknown } | undefined;
		if (typeof marker?.undidEntryId === "string") undone.add(marker.undidEntryId);
	}

	const live: LiveAnnotation[] = [];
	let current: string | undefined;
	for (const entry of entries) {
		if (entry.type !== "custom") continue;
		if (entry.customType === "re.binary") {
			const path = (entry.data as { path?: unknown } | undefined)?.path;
			current = typeof path === "string" ? path : undefined;
			continue;
		}
		if (entry.customType !== "re.annotation" || current !== binaryPath || undone.has(entry.id)) continue;
		const data = entry.data as Partial<AnnotationData> | undefined;
		if (!data || typeof data.kind !== "string" || typeof data.ea !== "string") continue;
		live.push({
			entryId: entry.id,
			data: {
				kind: data.kind,
				ea: data.ea,
				oldValue: data.oldValue ?? "",
				newValue: data.newValue ?? "",
				target: data.target,
				evidenceId: data.evidenceId,
				ungrounded: data.ungrounded,
			},
		});
	}
	return live;
}

/** Stable identity of a set of live annotations; two branches with the same fingerprint need the same rizin state. */
export function annotationFingerprint(live: readonly LiveAnnotation[]): string {
	return live.map((a) => a.entryId).join(",");
}

/**
 * Re-apply `live` to a freshly analyzed rizin process, in order. A single
 * annotation that no longer applies (e.g. rizin's analysis changed between
 * versions) is reported back rather than aborting the rest.
 */
export async function replayAnnotations(rz: RzSession, live: readonly LiveAnnotation[]): Promise<string[]> {
	const failures: string[] = [];
	for (const { data } of live) {
		try {
			for (const command of annotationCommands(data.kind, data.ea, data.newValue, data.oldValue, data.target)) {
				await rz.cmd(command);
			}
		} catch (err) {
			failures.push(`${data.kind} @ ${data.ea}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}
	return failures;
}
