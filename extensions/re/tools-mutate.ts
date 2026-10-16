/**
 * The five mutating annotation tools.
 *
 * Every mutation follows the exact sequence: resolve -> read-old -> write ->
 * read-back -> verify -> record. Verification compares the read-back against
 * the requested value; a mismatch throws with what rizin actually stored
 * (never a silent "success"). oldValue comes from the pre-read, newValue from
 * the read-back — never from the request — so a tool can't claim a value
 * that didn't land. The write itself is built by annotations.ts, the same
 * builder `/re undo` and annotation replay use.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { annotationCommands, liveAnnotations, type AnnotationData, type AnnotationKind } from "./annotations.ts";
import { branchEntries } from "./entries.ts";
import { plainResult, type ReToolResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { addrOf, eaFromOffset, normalizeAddr, resolveNumericAddr, validateIdent, validateText, validateTypeLike, type RzSession } from "./rizin.ts";
import { ensureRizin, getState, markAnnotationsApplied } from "./state.ts";

interface AfijRow {
	addr?: number;
	offset?: number;
	name?: string;
	signature?: string;
}

interface AfvlVar {
	name: string;
	type: string;
	arg?: boolean;
}

/** The function containing `addr`: its start EA and current name. Mutations key on the start EA so an annotation stays addressable after the name it was requested by is gone (a rename can retire the old flag). */
async function functionAt(rz: RzSession, addr: string, signal?: AbortSignal): Promise<{ ea: string; name: string }> {
	const numeric = eaFromOffset(await resolveNumericAddr(rz, addr, signal));
	const fn = (await rz.cmdj<AfijRow[]>(`afij @ ${numeric}`, { signal }))?.[0];
	const start = fn ? addrOf(fn) : undefined;
	if (!fn || start === undefined || typeof fn.name !== "string") throw new Error(`omp-re: no function at ${addr}`);
	return { ea: eaFromOffset(start), name: fn.name };
}

/** afvlj groups variables by storage kind ({stack: [...], reg: [...], ...}); flatten every group. */
async function variablesAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<AfvlVar[]> {
	const grouped = await rz.cmdj<Record<string, unknown>>(`afvlj @ ${ea}`, { signal });
	if (!grouped || typeof grouped !== "object") return [];
	return Object.values(grouped).flatMap((group) =>
		Array.isArray(group) ? group.filter((v): v is AfvlVar => typeof v?.name === "string" && typeof v?.type === "string") : [],
	);
}

/** `afs` read-back: rizin prints the stored signature with a trailing `;`. */
async function signatureAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<string> {
	return (await rz.cmd(`afs @ ${ea}`, { signal })).trim().replace(/;\s*$/, "");
}

/** The function whose start address is exactly `ea`, or undefined when none begins there (`afij` returns the function *containing* ea, which may start earlier). */
async function functionStartingAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<AfijRow | undefined> {
	const fn = (await rz.cmdj<AfijRow[]>(`afij @ ${ea}`, { signal }))?.[0];
	return fn && eaFromOffset(addrOf(fn) ?? -1) === ea ? fn : undefined;
}

/** The current calling convention of the function at `ea` (`afc` with no argument prints it). */
async function callingConventionAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<string> {
	return (await rz.cmd(`afc @ ${ea}`, { signal })).trim();
}

/** The name of the flag at `ea`, or "" when none (`fdj` prints `{offset,name,realname}` for the flag there). */
async function flagAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<string> {
	const flag = await rz.cmdj<{ name?: string }>(`fdj @ ${ea}`, { signal });
	return flag && typeof flag.name === "string" ? flag.name : "";
}

/** Tolerate only rizin's own cosmetic re-punctuation (spacing, trailing `;`) when comparing signatures/types — never a semantic difference. */
function normalizeCType(value: string): string {
	return value.trim().replace(/;+\s*$/, "").replace(/\s+/g, "");
}

async function apply(rz: RzSession, commands: string[], signal?: AbortSignal): Promise<void> {
	for (const command of commands) await rz.cmd(command, { signal });
}

/** Append the `re.annotation` entry (grounded by the latest evidence at the same EA, if any) and record that rizin now matches the branch. */
function recordAnnotation(pi: ExtensionAPI, ctx: ExtensionContext, data: Omit<AnnotationData, "evidenceId" | "ungrounded">): void {
	const evidenceId = getState(ctx).evidenceByAddr.get(normalizeAddr(data.ea)) ?? "";
	pi.appendEntry("re.annotation", { ...data, evidenceId, ungrounded: evidenceId === "" });
	markAnnotationsApplied(ctx);
}

function mutateResult(kind: AnnotationKind, data: { ea: string; oldValue: string; newValue: string; target?: string }): ReToolResult {
	const what = data.target ? `${data.target}: ` : "";
	return plainResult(`${kind}: ${what}${JSON.stringify(data.oldValue)} -> ${JSON.stringify(data.newValue)} @ ${data.ea}`, data.ea);
}

export function registerMutateTools(pi: ExtensionAPI): void {
	// Named const schemas: see registerReadTools for why they stay outside registerTool({...}).
	const z = pi.zod;
	const undoNote = "Reversible with /re undo.";
	const fnAddr = () => z.string().describe("Function address or name.");
	const renameFunctionParams = z.object({
		addr: fnAddr(),
		new: z.string().describe("New function name (identifier characters only)."),
	});
	const renameVariableParams = z.object({
		addr: fnAddr(),
		old: z.string().describe("Current variable name."),
		new: z.string().describe("New variable name."),
	});
	const setCommentParams = z.object({
		addr: z.string().describe("Address (or name) to comment."),
		text: z.string().describe("Comment text (single line); empty string clears the comment."),
	});
	const setPrototypeParams = z.object({
		addr: fnAddr(),
		sig: z.string().describe("New C-style prototype, without a trailing semicolon."),
	});
	const setVariableTypeParams = z.object({
		addr: fnAddr(),
		var: z.string().describe("Variable name."),
		type: z.string().describe("New C-style type, e.g. `char *` or `struct sockaddr_in *`."),
	});
	const defineFunctionParams = z.object({
		addr: z.string().describe("Address (or name/expression) where a function begins that rizin's auto-analysis missed."),
	});
	const setCallingConventionParams = z.object({
		addr: fnAddr(),
		cc: z.string().describe("Calling convention name, e.g. `amd64`, `ms`, `cdecl`, `stdcall` — see the list from rizin_command afcl."),
	});
	const setFlagParams = z.object({
		addr: z.string().describe("Address (or name/expression) to label."),
		name: z.string().describe("Flag name (identifier characters, dots allowed), e.g. `str.banner` or `decrypt_key`."),
	});

	pi.registerTool({
		name: "rename_function",
		label: "Rename Function",
		description: "Rename the function at an address, verifying the rename actually landed before reporting success.",
		approval: (args) => ({ tier: "write", reason: `Rename function ${describeArg(args, "addr")} to ${describeArg(args, "new")}. ${undoNote}` }),
		loadMode: "essential",
		parameters: renameFunctionParams,
		...reRenderers({ title: "Rename function", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const newName = validateIdent("new", params.new);
			const fn = await functionAt(rz, params.addr, signal);

			await apply(rz, annotationCommands("rename_function", fn.ea, newName, fn.name), signal);

			const landed = (await rz.cmdj<AfijRow[]>(`afij @ ${fn.ea}`, { signal }))?.[0]?.name;
			if (landed !== newName) {
				throw new Error(`omp-re: rename_function: mutation did not land: expected ${JSON.stringify(newName)}, rizin has ${JSON.stringify(landed ?? null)}`);
			}
			const data = { kind: "rename_function", ea: fn.ea, oldValue: fn.name, newValue: landed };
			recordAnnotation(pi, ctx, data);
			return mutateResult("rename_function", data);
		},
	});

	pi.registerTool({
		name: "rename_variable",
		label: "Rename Variable",
		description: "Rename a local variable or argument within a function, verifying the rename actually landed before reporting success.",
		approval: (args) => ({
			tier: "write",
			reason: `Rename variable ${describeArg(args, "old")} to ${describeArg(args, "new")} in ${describeArg(args, "addr")}. ${undoNote}`,
		}),
		loadMode: "essential",
		parameters: renameVariableParams,
		...reRenderers({ title: "Rename variable", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const oldName = validateIdent("old", params.old);
			const newName = validateIdent("new", params.new);
			const fn = await functionAt(rz, params.addr, signal);
			const before = await variablesAt(rz, fn.ea, signal);
			if (!before.some((v) => v.name === oldName)) {
				throw new Error(`omp-re: rename_variable: ${fn.name} has no variable ${JSON.stringify(oldName)} (has: ${before.map((v) => v.name).join(", ") || "none"})`);
			}

			await apply(rz, annotationCommands("rename_variable", fn.ea, newName, oldName), signal);

			const after = await variablesAt(rz, fn.ea, signal);
			if (!after.some((v) => v.name === newName) || after.some((v) => v.name === oldName)) {
				throw new Error(`omp-re: rename_variable: mutation did not land: expected ${JSON.stringify(newName)} in place of ${JSON.stringify(oldName)}`);
			}
			const data = { kind: "rename_variable", ea: fn.ea, oldValue: oldName, newValue: newName };
			recordAnnotation(pi, ctx, data);
			return mutateResult("rename_variable", data);
		},
	});

	pi.registerTool({
		name: "set_comment",
		label: "Set Comment",
		description: "Set (or clear, with empty text) the comment at an address, replacing any existing comment, and verify it landed before reporting success.",
		approval: (args) => ({ tier: "write", reason: `Set the comment at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: "essential",
		parameters: setCommentParams,
		...reRenderers({ title: "Comment", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const text = validateText(params.text).trim();
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const oldValue = (await rz.cmd(`CC. @ ${ea}`, { signal })).trim();

			await apply(rz, annotationCommands("set_comment", ea, text, oldValue), signal);

			const readBack = (await rz.cmd(`CC. @ ${ea}`, { signal })).trim();
			if (readBack !== text) {
				throw new Error(`omp-re: set_comment: mutation did not land: expected ${JSON.stringify(text)}, rizin has ${JSON.stringify(readBack)}`);
			}
			const data = { kind: "set_comment", ea, oldValue, newValue: readBack };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_comment", data);
		},
	});

	pi.registerTool({
		name: "set_prototype",
		label: "Set Prototype",
		description:
			"Set a function's C prototype, e.g. `int parse_config(const char *path, int flags)`. The name in the prototype becomes the function's name. Verifies what rizin stored and reports it if rizin's C parser normalized it differently.",
		approval: (args) => ({ tier: "write", reason: `Set the prototype of ${describeArg(args, "addr")} to ${describeArg(args, "sig")}. ${undoNote}` }),
		loadMode: "essential",
		parameters: setPrototypeParams,
		...reRenderers({ title: "Prototype", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const sig = validateTypeLike("sig", params.sig.trim());
			const fn = await functionAt(rz, params.addr, signal);
			const oldValue = await signatureAt(rz, fn.ea, signal);

			await apply(rz, annotationCommands("set_prototype", fn.ea, sig, oldValue), signal);

			const readBack = await signatureAt(rz, fn.ea, signal);
			if (normalizeCType(readBack) !== normalizeCType(sig)) {
				throw new Error(`omp-re: set_prototype: mutation did not land as requested: expected ${JSON.stringify(sig)}, rizin stored ${JSON.stringify(readBack)}`);
			}
			const data = { kind: "set_prototype", ea: fn.ea, oldValue, newValue: readBack };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_prototype", data);
		},
	});

	pi.registerTool({
		name: "set_variable_type",
		label: "Set Variable Type",
		description: "Set a local variable's or argument's C type, verifying it actually landed before reporting success.",
		approval: (args) => ({
			tier: "write",
			reason: `Set the type of ${describeArg(args, "var")} in ${describeArg(args, "addr")} to ${describeArg(args, "type")}. ${undoNote}`,
		}),
		loadMode: "essential",
		parameters: setVariableTypeParams,
		...reRenderers({ title: "Variable type", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const varName = validateIdent("var", params.var);
			const type = validateTypeLike("type", params.type.trim());
			const fn = await functionAt(rz, params.addr, signal);
			const old = (await variablesAt(rz, fn.ea, signal)).find((v) => v.name === varName);
			if (!old) throw new Error(`omp-re: set_variable_type: ${fn.name} has no variable ${JSON.stringify(varName)}`);

			await apply(rz, annotationCommands("set_variable_type", fn.ea, type, old.type, varName), signal);

			const landed = (await variablesAt(rz, fn.ea, signal)).find((v) => v.name === varName);
			if (!landed || normalizeCType(landed.type) !== normalizeCType(type)) {
				throw new Error(
					`omp-re: set_variable_type: mutation did not land: expected ${JSON.stringify(type)}, rizin has ${JSON.stringify(landed?.type ?? null)}`,
				);
			}
			const data = { kind: "set_variable_type", ea: fn.ea, oldValue: old.type, newValue: landed.type, target: varName };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_variable_type", data);
		},
	});

	pi.registerTool({
		name: "define_function",
		label: "Define Function",
		description:
			"Define a function at an address rizin's auto-analysis missed (obfuscated call targets, hand-written stubs, code reached only indirectly). Runs `af`, then verifies a function now begins exactly there. Reversible with /re undo (which runs `af-`).",
		approval: (args) => ({ tier: "write", reason: `Define a function at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: "essential",
		parameters: defineFunctionParams,
		...reRenderers({ title: "Define function", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const existing = await functionStartingAt(rz, ea, signal);
			if (existing) throw new Error(`omp-re: define_function: a function already begins at ${ea} (${JSON.stringify(existing.name ?? null)}); nothing to define`);

			await apply(rz, annotationCommands("define_function", ea, "function", ""), signal);

			const landed = await functionStartingAt(rz, ea, signal);
			if (!landed) throw new Error(`omp-re: define_function: rizin did not create a function at ${ea} (it may not be valid code there)`);
			const name = typeof landed.name === "string" ? landed.name : "function";
			const data = { kind: "define_function", ea, oldValue: "", newValue: name };
			recordAnnotation(pi, ctx, data);
			return mutateResult("define_function", data);
		},
	});

	pi.registerTool({
		name: "set_calling_convention",
		label: "Set Calling Convention",
		description:
			"Set a function's calling convention (how arguments and the return value are passed), which corrects argument recovery in the decompiler and call sites. Verifies what rizin stored; an unknown convention is rejected with rizin's own error (list them with rizin_command afcl). Reversible with /re undo.",
		approval: (args) => ({ tier: "write", reason: `Set the calling convention of ${describeArg(args, "addr")} to ${describeArg(args, "cc")}. ${undoNote}` }),
		loadMode: "essential",
		parameters: setCallingConventionParams,
		...reRenderers({ title: "Calling convention", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const cc = validateIdent("cc", params.cc.trim());
			const fn = await functionAt(rz, params.addr, signal);
			const oldValue = await callingConventionAt(rz, fn.ea, signal);

			await apply(rz, annotationCommands("set_calling_convention", fn.ea, cc, oldValue), signal);

			const readBack = await callingConventionAt(rz, fn.ea, signal);
			if (readBack !== cc) {
				throw new Error(`omp-re: set_calling_convention: mutation did not land: expected ${JSON.stringify(cc)}, rizin has ${JSON.stringify(readBack)} (unknown convention? see rizin_command afcl)`);
			}
			const data = { kind: "set_calling_convention", ea: fn.ea, oldValue, newValue: readBack };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_calling_convention", data);
		},
	});

	pi.registerTool({
		name: "set_flag",
		label: "Set Flag",
		description:
			"Name an address with a flag (rizin's named label), so disassembly, xrefs, and your own commands can refer to it by name. Replaces any flag already at that address. Verifies the flag landed. Reversible with /re undo.",
		approval: (args) => ({ tier: "write", reason: `Flag ${describeArg(args, "addr")} as ${describeArg(args, "name")}. ${undoNote}` }),
		loadMode: "essential",
		parameters: setFlagParams,
		...reRenderers({ title: "Flag", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const name = validateIdent("name", params.name);
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const oldValue = await flagAt(rz, ea, signal);

			await apply(rz, annotationCommands("set_flag", ea, name, oldValue), signal);

			const readBack = await flagAt(rz, ea, signal);
			if (readBack !== name) {
				throw new Error(`omp-re: set_flag: mutation did not land: expected flag ${JSON.stringify(name)} at ${ea}, rizin has ${JSON.stringify(readBack || null)}`);
			}
			const data = { kind: "set_flag", ea, oldValue, newValue: name };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_flag", data);
		},
	});
}

/** A tool argument for an approval prompt: quoted, and bounded so a huge value can't flood the dialog. */
function describeArg(args: unknown, key: string): string {
	const value = args && typeof args === "object" ? (args as Record<string, unknown>)[key] : undefined;
	const text = typeof value === "string" ? value : "?";
	return JSON.stringify(text.length > 80 ? `${text.slice(0, 77)}...` : text);
}

/** Reverse the most recent annotation still in effect on this branch by re-applying its oldValue, then record an `re.undo` marker so a repeated `/re undo` steps further back instead of re-applying the same reversal. */
export async function undoLastAnnotation(pi: ExtensionAPI, ctx: ExtensionContext): Promise<string> {
	const binaryPath = getState(ctx).binaryPath;
	const last = binaryPath ? liveAnnotations(branchEntries(ctx), binaryPath).at(-1) : undefined;
	if (!last) throw new Error("omp-re: no annotation left to undo");
	const { data } = last;

	const rz = await ensureRizin(ctx);
	await apply(rz, annotationCommands(data.kind, data.ea, data.oldValue, data.newValue, data.target));

	pi.appendEntry("re.undo", { undidEntryId: last.entryId });
	markAnnotationsApplied(ctx);
	return `omp-re: undid ${data.kind} @ ${data.ea} (restored ${JSON.stringify(data.oldValue)})`;
}
