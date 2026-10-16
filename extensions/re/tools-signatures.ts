/**
 * FLIRT signatures (book: analysis/signatures) — naming library functions
 * from a signature database.
 *
 * rizin's `aaa` already applies the built-in signature database on open
 * (`analysis.apply.signature`), so the common case needs no tool. This covers
 * the two things that doesn't: re-applying the built-in database on demand
 * (`Fa`), and applying a *custom* `.sig`/`.pat` file the analyst has (`Fs`),
 * which `rizin_command` can't do because it refuses file arguments.
 *
 * Applying signatures renames matched functions — it changes analysis — so
 * this is exec-tier. A custom-file application is recorded as an `re.signature`
 * entry and re-applied on every respawn/resume (signatures.ts + runtime.ts),
 * the same way annotations are replayed, so the names it produced survive. It
 * is not an undoable annotation: reopening and re-running `aaa` is how you
 * start clean.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { branchEntries, recordedSignatures } from "./entries.ts";
import { textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { parseAppliedCount, signatureApplyCommand, validateSignaturePath } from "./signatures.ts";
import { ensureRizin, getState, requireBinary } from "./state.ts";

export function registerSignatureTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const applyParams = z.object({
		source: z.enum(["sigdb", "file"]).describe("sigdb: re-apply rizin's built-in signature database. file: apply a custom FLIRT .sig/.pat file (path required)."),
		path: z.string().optional().describe("Path to a .sig/.pat file, required when source is 'file'."),
	});

	pi.registerTool({
		name: "apply_signatures",
		label: "Apply Signatures",
		description:
			"Name library functions from FLIRT signatures. source 'sigdb' re-applies rizin's built-in signature database (already applied once by open_binary's analysis); source 'file' applies a custom .sig/.pat file you provide, which open_binary can't know about. This renames matched functions (it changes analysis). A custom file is re-applied automatically on resume/respawn. List the built-in database with rizin_command Flt.",
		approval: (args) => {
			const record = args && typeof args === "object" ? (args as { source?: unknown; path?: unknown }) : {};
			if (record.source === "file" && typeof record.path === "string") {
				return { tier: "exec" as const, reason: `Apply the FLIRT signature file ${JSON.stringify(record.path)} — this renames matched functions.` };
			}
			return { tier: "exec" as const, reason: "Re-apply rizin's built-in signature database — this renames matched functions." };
		},
		loadMode: "essential",
		parameters: applyParams,
		...reRenderers({ title: "Apply signatures", subject: "source", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const rz = await ensureRizin(ctx, { signal });
			const binary = requireBinary(getState(ctx));

			if (params.source === "sigdb") {
				const before = Number((await rz.cmd("aflc", { signal })).trim()) || 0;
				await rz.cmd("Fa", { signal });
				const after = Number((await rz.cmd("aflc", { signal })).trim()) || 0;
				return textResult("apply_signatures: sigdb", `Re-applied the built-in signature database. Functions: ${before} before, ${after} after.`);
			}

			if (params.path === undefined) throw new Error("omp-re: apply_signatures: source 'file' needs a path");
			const path = validateSignaturePath(params.path);
			const out = (await rz.cmd(signatureApplyCommand(path), { signal })).trim();
			const count = parseAppliedCount(out);
			// Record it for replay only when it actually applied signatures: a
			// zero-match or error application has nothing to reproduce on resume.
			if ((count ?? 0) > 0) {
				const already = recordedSignatures(branchEntries(ctx), binary);
				if (!already.includes(path)) pi.appendEntry("re.signature", { path });
			}
			return textResult(`apply_signatures: ${path}`, count === undefined ? out || "(applied)" : `Applied ${count} FLIRT signature(s) from ${path}.`);
		},
	});
}
