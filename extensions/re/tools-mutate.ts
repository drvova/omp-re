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
import { annotationCommands, HINT_KINDS, HINT_SPEC, type HintKind, liveAnnotations, type AnnotationData, type AnnotationKind } from "./annotations.ts";
import { branchEntries } from "./entries.ts";
import { plainResult, type ReToolResult } from "./format.ts";
import { RE_LOAD_MODE, reRenderers } from "./render.ts";
import { addrOf, eaFromOffset, normalizeAddr, resolveNumericAddr, validateIdent, validateText, validateTypeLike, type RzSession } from "./rizin.ts";
import { ensureRizin, evidenceIdAt, getState, markAnnotationsApplied } from "./state.ts";

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

/** The arch/bits hint at `ea`, or undefined when none (`ahl.j` prints `[{addr,arch?,bits?}]` for the hints there). */
async function archHintAt(rz: RzSession, ea: string, signal?: AbortSignal): Promise<{ arch?: string; bits?: number } | undefined> {
	const hints = await rz.cmdj<{ arch?: string; bits?: number }[]>(`ahl.j @ ${ea}`, { signal });
	return Array.isArray(hints) && hints.length > 0 ? hints[0] : undefined;
}

/** The current value of analysis hint `kind` at `ea` as a canonical string, or "" when unset. `ahl.j` prints `[{addr,immbase?,type?,size?,jump?,ret?,…}]` for the hints there. */
async function hintValueAt(rz: RzSession, ea: string, kind: HintKind, signal?: AbortSignal): Promise<string> {
	const key = HINT_SPEC[kind].key;
	const hints = await rz.cmdj<Record<string, unknown>[]>(`ahl.j @ ${ea}`, { signal });
	const raw = Array.isArray(hints) && hints.length > 0 ? hints[0]?.[key] : undefined;
	if (raw === undefined || raw === null) return "";
	// `jump` reads back as a number; re-apply it as hex so the undo/replay command round-trips.
	if (kind === "jump_target" && typeof raw === "number") return `0x${raw.toString(16)}`;
	return String(raw);
}

/** The global variable named `name`, or undefined when none. `avglj` lists globals as `[{name,type,size,addr}]` (addr is a hex string). */
async function globalByName(rz: RzSession, name: string, signal?: AbortSignal): Promise<{ type: string; addr: string } | undefined> {
	const globals = await rz.cmdj<{ name?: string; type?: string; addr?: string }[]>("avglj", { signal });
	const g = Array.isArray(globals) ? globals.find((x) => x.name === name) : undefined;
	return g && typeof g.type === "string" ? { type: g.type, addr: String(g.addr ?? "") } : undefined;
}

/** The metadata item of a given type (`Cd`/`Cs`/`Cf`) at `ea`, or undefined when none. `C.j` lists all meta at an address as `[{offset,type,size?,...}]`. */
async function metaAt(rz: RzSession, ea: string, type: string, signal?: AbortSignal): Promise<{ type: string; size?: number } | undefined> {
	const meta = await rz.cmdj<{ type?: string; size?: number }[]>(`C.j @ ${ea}`, { signal });
	return Array.isArray(meta) ? (meta.find((m) => m.type === type) as { type: string; size?: number } | undefined) : undefined;
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
	const evidenceId = evidenceIdAt(ctx, data.ea) ?? "";
	pi.appendEntry("re.annotation", { ...data, evidenceId, ungrounded: evidenceId === "" });
	markAnnotationsApplied(ctx);
}

function mutateResult(kind: AnnotationKind, data: { ea: string; oldValue: string; newValue: string; target?: string }): ReToolResult {
	const what = data.target ? `${data.target}: ` : "";
	return plainResult(`${kind}: ${what}${JSON.stringify(data.oldValue)} -> ${JSON.stringify(data.newValue)} @ ${data.ea}`, data.ea);
}

export function registerMutateTools(pi: ExtensionAPI): void {
	// Named const schemas, declared outside registerTool so TypeScript infers each tool's param type in execute().
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
	const defineGlobalParams = z.object({
		addr: z.string().describe("Data address (or name/expression) where the global variable lives."),
		name: z.string().describe("Global variable name (identifier characters)."),
		type: z.string().describe("C type, e.g. `int`, `char *`, or a named struct/typedef."),
	});
	const defineVariableParams = z.object({
		addr: fnAddr(),
		storage: z.enum(["stack", "reg"]).describe("`stack` for a stack-based local/argument (`afvs`), `reg` for a register-based one (`afvr`)."),
		location: z.string().describe("For `stack`: the frame offset as a decimal or 0x-hex delta (e.g. `0x30`). For `reg`: the register name (e.g. `rdi`)."),
		name: z.string().describe("New variable name (identifier characters)."),
		type: z.string().optional().describe("C type, e.g. `int` or `char *`; omit to let rizin default it (int)."),
	});
	const setCallingConventionParams = z.object({
		addr: fnAddr(),
		cc: z.string().describe("Calling convention name, e.g. `amd64`, `ms`, `cdecl`, `stdcall` — see the list from rizin_command afcl."),
	});
	const setFlagParams = z.object({
		addr: z.string().describe("Address (or name/expression) to label."),
		name: z.string().describe("Flag name (identifier characters, dots allowed), e.g. `str.banner` or `decrypt_key`."),
	});
	const setArchHintParams = z.object({
		addr: z.string().describe("Address (or name/expression) where the hint applies."),
		arch: z.string().optional().describe("Architecture to disassemble as from here, e.g. `arm`, `x86` (sets an `aha` hint)."),
		bits: z.union([z.literal(8), z.literal(16), z.literal(32), z.literal(64)]).optional().describe("Word size from here, e.g. 16 for ARM Thumb (sets an `ahb` hint)."),
	});
	const setHintParams = z.object({
		addr: z.string().describe("Instruction address (or name/expression) the hint applies to."),
		hint: z.enum(HINT_KINDS).describe(
			[
				"immediate_base: how an operand's immediate is shown (value: 2/8/10/10u/16 or b/o/h/i/p/S/s — e.g. `h` hex, `S` string, `s` syscall, `i` IP-relative).",
				"opcode_type: reclassify the instruction (value: a type such as call, jmp, ret, nop, mov).",
				"opcode_size: force the instruction's byte length (value: a positive integer) to realign disassembly.",
				"jump_target: the real destination of an indirect/computed jump or call (value: an address).",
				"return_value: a function's return-value hint (value: a decimal or 0x-hex integer).",
			].join("\n"),
		),
		value: z.string().describe("The hint value; its grammar depends on `hint` (see the hint descriptions)."),
	});
	const setDataParams = z.object({
		addr: z.string().describe("Address (or name/expression) to mark as data."),
		size: z.number().describe("Size in bytes of one data element."),
		count: z.number().optional().describe("Number of consecutive elements (an array); default 1."),
	});
	const setStringParams = z.object({
		addr: z.string().describe("Address (or name/expression) where a string begins."),
		size: z.number().optional().describe("String length in bytes; omit to let rizin autodetect the encoding and length."),
	});
	const setFormatParams = z.object({
		addr: z.string().describe("Address (or name/expression) to overlay a struct format on."),
		size: z.number().describe("Total size in bytes the format covers."),
		format: z.string().describe("A pf format string, optionally with field names, e.g. `xxdd field1 field2 field3 field4` (see rizin_help pf)."),
	});

	pi.registerTool({
		name: "rename_function",
		label: "Rename Function",
		description: "Rename the function at an address, verifying the rename actually landed before reporting success.",
		approval: (args) => ({ tier: "write", reason: `Rename function ${describeArg(args, "addr")} to ${describeArg(args, "new")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
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
		loadMode: RE_LOAD_MODE,
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
		loadMode: RE_LOAD_MODE,
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
		loadMode: RE_LOAD_MODE,
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
		loadMode: RE_LOAD_MODE,
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
		name: "define_variable",
		label: "Define Variable",
		description:
			"Define a local variable or argument in a function that rizin's analysis didn't recover — a stack slot (`afvs`, by frame delta) or a register variable (`afvr`, by register) — so the decompiler and disassembly name it instead of showing a raw offset. Refuses when a variable of that name already exists, verifies the new one landed, and is reversible with /re undo (which runs `afv-`).",
		approval: (args) => ({ tier: "write", reason: `Define ${describeArg(args, "storage")} variable ${describeArg(args, "name")} in ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: defineVariableParams,
		...reRenderers({ title: "Define variable", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const name = validateIdent("name", params.name);
			const fn = await functionAt(rz, params.addr, signal);
			if ((await variablesAt(rz, fn.ea, signal)).some((v) => v.name === name)) {
				throw new Error(`omp-re: define_variable: ${fn.name} already has a variable ${JSON.stringify(name)}`);
			}
			const type = params.type !== undefined && params.type.trim() !== "" ? validateTypeLike("type", params.type.trim()) : "";
			const encoded = `${params.storage} ${params.location.trim()}${type !== "" ? ` ${type}` : ""}`;

			await apply(rz, annotationCommands("define_variable", fn.ea, encoded, "", name), signal);

			const landed = (await variablesAt(rz, fn.ea, signal)).find((v) => v.name === name);
			if (!landed) throw new Error(`omp-re: define_variable: mutation did not land: no variable ${JSON.stringify(name)} in ${fn.name} after defining it`);
			const data = { kind: "define_variable", ea: fn.ea, oldValue: "", newValue: encoded, target: name };
			recordAnnotation(pi, ctx, data);
			return mutateResult("define_variable", data);
		},
	});

	pi.registerTool({
		name: "define_global",
		label: "Define Global",
		description:
			"Define a global variable at a data address (`avga`), giving it a name and a C type so disassembly, xrefs, and the decompiler show the name and typed accesses instead of a raw address. Refuses when a global of that name already exists, verifies it landed, and is reversible with /re undo (which runs `avgm`).",
		approval: (args) => ({ tier: "write", reason: `Define global ${describeArg(args, "name")} at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: defineGlobalParams,
		...reRenderers({ title: "Define global", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const name = validateIdent("name", params.name);
			const type = validateTypeLike("type", params.type.trim());
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			if (await globalByName(rz, name, signal)) throw new Error(`omp-re: define_global: a global named ${JSON.stringify(name)} already exists`);

			await apply(rz, annotationCommands("define_global", ea, type, "", name), signal);

			const landed = await globalByName(rz, name, signal);
			if (!landed) throw new Error(`omp-re: define_global: mutation did not land: no global ${JSON.stringify(name)} after defining it at ${ea}`);
			const data = { kind: "define_global", ea, oldValue: "", newValue: landed.type, target: name };
			recordAnnotation(pi, ctx, data);
			return mutateResult("define_global", data);
		},
	});

	pi.registerTool({
		name: "define_function",
		label: "Define Function",
		description:
			"Define a function at an address rizin's auto-analysis missed (obfuscated call targets, hand-written stubs, code reached only indirectly). Runs `af`, then verifies a function now begins exactly there. Reversible with /re undo (which runs `af-`).",
		approval: (args) => ({ tier: "write", reason: `Define a function at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
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
		loadMode: RE_LOAD_MODE,
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
		loadMode: RE_LOAD_MODE,
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

	pi.registerTool({
		name: "set_arch_hint",
		label: "Set Arch Hint",
		description:
			"Hint the architecture and/or word size to disassemble from an address, for a region that differs from the file's default — most often ARM/Thumb switches (bits 16) or mixed-arch firmware. Sets `aha`/`ahb`, verifies the hint landed, and is reversible with /re undo (which deletes it).",
		approval: (args) => ({ tier: "write", reason: `Hint arch/bits at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: setArchHintParams,
		...reRenderers({ title: "Arch hint", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			if (params.arch === undefined && params.bits === undefined) throw new Error("omp-re: set_arch_hint needs arch and/or bits");
			const rz = await ensureRizin(ctx, { signal });
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const parts: string[] = [];
			if (params.arch !== undefined) parts.push(`arch=${validateIdent("arch", params.arch)}`);
			if (params.bits !== undefined) parts.push(`bits=${params.bits}`);
			const encoded = parts.join(";");

			await apply(rz, annotationCommands("set_arch_hint", ea, encoded, ""), signal);

			const landed = await archHintAt(rz, ea, signal);
			const archOk = params.arch === undefined || landed?.arch === params.arch;
			const bitsOk = params.bits === undefined || landed?.bits === params.bits;
			if (!landed || !archOk || !bitsOk) {
				throw new Error(`omp-re: set_arch_hint: mutation did not land: expected ${JSON.stringify(encoded)}, rizin has ${JSON.stringify(landed ?? null)}`);
			}
			const data = { kind: "set_arch_hint", ea, oldValue: "", newValue: encoded };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_arch_hint", data);
		},
	});

	pi.registerTool({
		name: "set_hint",
		label: "Set Hint",
		description:
			"Set an analysis hint at an instruction that corrects how rizin reads it: the display base of an immediate (hex/decimal/char/string/syscall/IP-relative), the opcode type, the opcode byte-length (to realign disassembly), the real target of an indirect jump/call, or a function's return value. Verifies the hint landed and records what rizin stored; reversible with /re undo (which deletes it or restores the prior hint).",
		approval: (args) => ({ tier: "write", reason: `Set the ${describeArg(args, "hint")} hint at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: setHintParams,
		...reRenderers({ title: "Hint", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const kind = params.hint as HintKind;
			const oldValue = await hintValueAt(rz, ea, kind, signal);

			// Forward value comes from the request (validated in annotationCommands); newValue below is the read-back, never the request.
			await apply(rz, annotationCommands("set_hint", ea, params.value, "", kind), signal);

			const landed = await hintValueAt(rz, ea, kind, signal);
			if (landed === "") {
				throw new Error(`omp-re: set_hint: mutation did not land: no ${kind} hint at ${ea} after setting ${JSON.stringify(params.value)}`);
			}
			const data = { kind: "set_hint", ea, oldValue, newValue: landed, target: kind };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_hint", data);
		},
	});

	pi.registerTool({
		name: "set_data",
		label: "Set Data",
		description:
			"Mark bytes as a data element (or an array, with `count`) so disassembly and xrefs stop rendering data as code. Verifies the mark landed; reversible with /re undo.",
		approval: (args) => ({ tier: "write", reason: `Mark data at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: setDataParams,
		...reRenderers({ title: "Data", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			if (!Number.isInteger(params.size) || params.size <= 0) throw new Error("omp-re: set_data: size must be a positive integer");
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const encoded = params.count !== undefined && params.count > 1 ? `${params.size}:${params.count}` : `${params.size}`;

			await apply(rz, annotationCommands("set_data", ea, encoded, ""), signal);

			const landed = await metaAt(rz, ea, "Cd", signal);
			if (!landed) throw new Error(`omp-re: set_data: mutation did not land: no data mark at ${ea}`);
			const data = { kind: "set_data", ea, oldValue: "", newValue: encoded };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_data", data);
		},
	});

	pi.registerTool({
		name: "set_string",
		label: "Set String",
		description:
			"Mark bytes as a string where rizin's auto-analysis missed one, so it shows in the disassembly and string views. Omit `size` to autodetect encoding and length. Verifies it landed; reversible with /re undo.",
		approval: (args) => ({ tier: "write", reason: `Mark a string at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: setStringParams,
		...reRenderers({ title: "String", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			if (params.size !== undefined && (!Number.isInteger(params.size) || params.size <= 0)) throw new Error("omp-re: set_string: size must be a positive integer");
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const encoded = params.size === undefined ? "auto" : `${params.size}`;

			await apply(rz, annotationCommands("set_string", ea, encoded, ""), signal);

			const landed = await metaAt(rz, ea, "Cs", signal);
			if (!landed) throw new Error(`omp-re: set_string: mutation did not land: no string mark at ${ea} (not valid string bytes there?)`);
			const data = { kind: "set_string", ea, oldValue: "", newValue: encoded };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_string", data);
		},
	});

	pi.registerTool({
		name: "set_format",
		label: "Set Format",
		description:
			"Overlay a struct format (a pf format string, optionally with field names) on a memory region, so the disassembly shows named, typed fields instead of raw bytes — one of the highest-leverage annotations for data structures. Display-only (doesn't perturb analysis). Verifies it landed; reversible with /re undo.",
		approval: (args) => ({ tier: "write", reason: `Overlay a format at ${describeArg(args, "addr")}. ${undoNote}` }),
		loadMode: RE_LOAD_MODE,
		parameters: setFormatParams,
		...reRenderers({ title: "Format", subject: "addr", body: "none" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			if (!Number.isInteger(params.size) || params.size <= 0) throw new Error("omp-re: set_format: size must be a positive integer");
			const ea = eaFromOffset(await resolveNumericAddr(rz, params.addr, signal));
			const encoded = `${params.size} ${params.format.trim()}`;

			await apply(rz, annotationCommands("set_format", ea, encoded, ""), signal);

			const landed = await metaAt(rz, ea, "Cf", signal);
			if (!landed) throw new Error(`omp-re: set_format: mutation did not land: no format mark at ${ea} (bad pf format?)`);
			const data = { kind: "set_format", ea, oldValue: "", newValue: encoded };
			recordAnnotation(pi, ctx, data);
			return mutateResult("set_format", data);
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
