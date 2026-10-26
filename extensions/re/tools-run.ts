/**
 * `run`: the one tool omp-re advertises.
 *
 * A fixed menu of typed tools is the wrong interface for reverse engineering:
 * every rizin build, platform, and install supports a different subset of
 * operations, and different models use a given menu differently well. So
 * omp-re exposes one tool that runs code against a live API instead — the
 * model discovers what is there (`describe(re)`), writes helpers on top of
 * it, and keeps refining them; helpers it defines persist across calls and
 * across restarts (namespace.ts, kept.ts). Every RE operation is a method on
 * `re` (capabilities.ts), recorded, audited, and grounded exactly as it was
 * when it was a tool of its own.
 *
 * Running code is what this tool is. It executes with omp's own authority —
 * files, processes, network — and there is no switch that makes it anything
 * else; omp is meant to run sandboxed (a container or VM) when the sample is
 * untrusted. See SECURITY.md.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import type { CapabilityRegistry } from "./capabilities.ts";
import { plainResult, textResult } from "./format.ts";
import { CellError, type CellOutcome, namespaceFor } from "./namespace.ts";
import { reRenderers } from "./render.ts";

export const RUN_TOOL_NAME = "run";

const DESCRIPTION = [
	"Reverse-engineer binaries by running TypeScript/JavaScript in this session's persistent omp-re namespace — the only omp-re tool. Call it with empty `code` first: that returns the manual.",
	"",
	"`re` is the RE workspace bound to this session (rizin behind it): every operation is `await re.<name>({ ...params })` — open_binary, list_functions, decompile_function, get_xrefs_to, rizin_command, rename_function, record_finding, and the rest. `describe(re)` lists what this install actually supports with signatures; `describe(re.<name>)` shows one in full.",
	"Top-level declarations persist across calls, and top-level functions, classes, and static consts are kept across restarts — build helpers once and reuse them. The last expression is returned; print() / console.log() output is returned too. Pass long literal text (rules, payloads) in `strings` and read it as strings.<name>.",
	"Results of observing operations end with an [evidence xxxxxxxx] id (each call's result also lists them); cite those ids in re.record_finding — /re report includes only grounded findings.",
	"MCP servers are functions too: `await mcp.servers()`, then `const s = await mcp.connect(\"name\")` and `await s.<tool>({ ... })`. A cancelled call stops at once and resets the namespace (kept definitions reload).",
	"",
	"SECURITY: this tool executes code with omp's full authority (files, processes, network). There is no restricted mode; run omp inside a sandbox (container/VM) when analysing untrusted samples.",
].join("\n");

/** The result's header line: what the cell did, at a glance. */
function headerOf(outcome: CellOutcome): string {
	const parts: string[] = [];
	const calls = outcome.scope.calls.length;
	if (calls > 0) parts.push(`${calls} re call${calls === 1 ? "" : "s"}`);
	if (outcome.scope.evidence.length > 0) parts.push(`${outcome.scope.evidence.length} evidence`);
	if (outcome.kept.length > 0) parts.push(`kept ${outcome.kept.join(", ")}`);
	return parts.length > 0 ? `ran · ${parts.join(" · ")}` : "ran";
}

/** The evidence a call recorded, so the ids reach the model even when the code never printed the results. */
function evidenceLines(scope: CellOutcome["scope"] | null): string[] {
	if (!scope || scope.evidence.length === 0) return [];
	return [`evidence recorded (cite in re.record_finding): ${scope.evidence.map((e) => `${e.id.slice(0, 8)} ${e.tool}${e.ea ? ` @ ${e.ea}` : ""}`).join(" · ")}`];
}

function bodyOf(outcome: CellOutcome): string {
	const sections = [...outcome.output];
	if (outcome.shown !== undefined) sections.push(outcome.shown);
	if (sections.length === 0) sections.push("(no output — the last expression was undefined; end with an expression or print() what you want back)");
	const trailer = [...evidenceLines(outcome.scope), ...(outcome.kept.length > 0 ? [`kept across restarts: ${outcome.kept.join(", ")} (kept() lists, forget(name) removes)`] : [])];
	return [...sections, ...(trailer.length > 0 ? ["", ...trailer] : [])].join("\n");
}

/** A failed cell as the tool error: the error first (it is the head line omp shows), then what ran before it. */
function failureOf(err: CellError): string {
	const lines = [err.message];
	if (err.output.length > 0) lines.push("", "output before the error:", ...err.output);
	const calls = err.scope?.calls ?? [];
	if (calls.length > 0) lines.push("", `re calls that completed or failed: ${calls.join(", ")}`);
	lines.push(...evidenceLines(err.scope));
	return lines.join("\n");
}

export function registerRunTool(pi: ExtensionAPI, registry: CapabilityRegistry): void {
	// Named const schema: see registerReadTools for why it stays outside registerTool({...}).
	const z = pi.zod;
	const runParams = z.object({
		code: z.string().describe("TypeScript or JavaScript to run in this session's persistent namespace (top-level await works). Empty returns the manual."),
		strings: z
			.record(z.string())
			.optional()
			.describe("Named literal strings — YARA rules, C declarations, payloads, any long text — readable in the code as strings.<name>, so nothing needs escaping inside `code`."),
	});

	pi.registerTool({
		name: RUN_TOOL_NAME,
		label: "Run",
		description: DESCRIPTION,
		approval: (args) => {
			const code = (args as { code?: unknown } | undefined)?.code;
			const first = typeof code === "string" ? (code.split("\n").find((line) => line.trim() !== "") ?? "").trim() : "";
			return { tier: "exec", reason: first ? `Run code in the omp-re namespace (with omp's authority): ${first.length > 120 ? `${first.slice(0, 119)}…` : first}` : "Show the omp-re manual" };
		},
		loadMode: "essential",
		parameters: runParams,
		...reRenderers({ title: "Run", subject: "code", subjectFirstLine: true, body: "text" }),
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			const ns = await namespaceFor(ctx, registry, RUN_TOOL_NAME);
			if (params.code.trim() === "") return plainResult(await ns.manual(ctx));
			try {
				const outcome = await ns.run(params.code, { pi, ctx, signal, onUpdate, toolCallId, strings: params.strings ?? {} });
				return await textResult(headerOf(outcome), bodyOf(outcome), { ctx, tool: RUN_TOOL_NAME, narrowHint: "Print less, or slice what you return." });
			} catch (err) {
				if (err instanceof CellError) throw new Error(failureOf(err));
				throw err;
			}
		},
	});
}
