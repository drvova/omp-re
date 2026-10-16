/**
 * RzIL emulation tools — the book's "Emulation" chapter, `aez` family
 * (live-verified in 0.9.1: ESIL `ae*` is deprecated upstream and dead through
 * the session transport; RzIL is the designed replacement).
 *
 * The VM is stateful but contained: it interprets the target's code logic
 * inside the static rizin session — no OS process runs. `init` (re)starts it
 * at an address without moving the session's seek (`aezi @ addr`), so other
 * tools are unaffected. Typical flow for argument recovery: init at a
 * function, set registers/stack (set_var), step and watch the change events.
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { textResult } from "./format.ts";
import { reRenderers } from "./render.ts";
import { ensureRizin } from "./state.ts";
import { debugTimeoutMs, validateAddr, type RzSession } from "./rizin.ts";

const EMULATE_ACTIONS = ["init", "step", "step_until", "vars", "set_var"] as const;
type EmulateAction = (typeof EMULATE_ACTIONS)[number];

function approvalReason(action: EmulateAction): string {
	switch (action) {
		case "init":
		case "set_var":
			return "Set up the RzIL emulation state (no OS process runs — the code is interpreted inside rizin).";
		case "step":
		case "step_until":
			return "Run the target's code logic inside rizin's RzIL VM (interpreted, no OS process).";
		case "vars":
			return "Read the RzIL VM state.";
	}
}

/**
 * A VM variable name for `aezv` — the live state dump shows keys like
 * `PC`, `rsp`, `rax`, `zf`, `xmm0` (alphanumeric), and rizin rejects
 * anything else anyway; validating here keeps the error message ours.
 */
function validateVarName(name: string): string {
	if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name)) {
		throw new Error(`omp-re: emulate: bad variable name ${JSON.stringify(name)} — use a name from the vars action`);
	}
	return name;
}

/** A value for `aezv <name> <number>` — rizin accepts decimal and 0x hex. */
function validateVarValue(value: string): string {
	if (!/^0x[0-9a-fA-F]+$|^[0-9]+$/.test(value)) {
		throw new Error(`omp-re: emulate: bad value ${JSON.stringify(value)} — use a decimal or 0x hex number`);
	}
	return value;
}

export function registerEmulateTools(pi: ExtensionAPI): void {
	const z = pi.zod;
	const emulateParams = z.object({
		action: z.enum(EMULATE_ACTIONS).describe(
			[
				"init: (re)start the RzIL VM at `addr` (required) — does not seek the session.",
				"step: run `count` instructions (default 1), returning the VM change events (register/flag/PC writes).",
				"step_until: run until PC equals `addr` (required).",
				"vars: full VM state (registers, flags, PC) as JSON.",
				"set_var: set VM variable `name` to `value` (e.g. the stack pointer before stepping).",
			].join("\n"),
		),
		addr: z.string().optional().describe("Address or symbol for init / step_until."),
		count: z.number().optional().describe("Instruction count for step (default 1)."),
		name: z.string().optional().describe("VM variable name for set_var (from the vars action)."),
		value: z.string().optional().describe("Number (decimal or 0x hex) for set_var."),
	});

	pi.registerTool({
		name: "rizin_emulate",
		label: "emulator",
		description:
			"Emulate code with rizin's RzIL VM: init at an address, step instructions and watch register/flag changes, step until an address, read and set VM variables. No process runs — the target's logic is interpreted inside rizin, and the VM state lives in the analysis session (init resets it). External calls and syscalls are not emulated; keep runs small (a decryptor loop, an argument computation). To execute the real process instead, use the debugger tool.",
		approval: (args) => {
			let action: EmulateAction | undefined;
			if (args && typeof args === "object" && "action" in args && typeof args.action === "string") {
				const raw = args.action;
				// includes() against the literal tuple proves the union membership the compiler cannot see.
				if ((EMULATE_ACTIONS as readonly string[]).includes(raw)) action = raw as EmulateAction;
			}
			return { tier: "exec", reason: action ? approvalReason(action) : "Drive the RzIL emulation." };
		},
		loadMode: "essential",
		parameters: emulateParams,
		...reRenderers({ title: "emulator", subject: "action", body: "text" }),
		async execute(_id, params, signal, _onUpdate, ctx) {
			const emuTimeout = debugTimeoutMs();
			const rz = await ensureRizin(ctx, { signal });

			switch (params.action) {
				case "init": {
					if (params.addr === undefined) throw new Error("omp-re: emulate init needs addr");
					const ea = validateAddr(params.addr);
					await rz.cmd(`aezi @ ${ea}`, { signal });
					const vars = (await rz.cmd("aezvj", { signal })).trim();
					return textResult(`emulate: VM initialized at ${ea}`, vars || "(no VM state)", { ctx, tool: "rizin_emulate" });
				}
				case "step": {
					const n = clampCount(params.count);
					const out = (await rz.cmd(`aezsej ${n}`, { timeoutMs: emuTimeout, signal })).trim();
					return textResult(`emulate: step ${n}`, out || "(no changes — init the VM first)", { ctx, tool: "rizin_emulate" });
				}
				case "step_until": {
					if (params.addr === undefined) throw new Error("omp-re: emulate step_until needs addr");
					const ea = validateAddr(params.addr);
					await rz.cmd(`aezsu ${ea}`, { timeoutMs: emuTimeout, signal });
					const vars = (await rz.cmd("aezvj", { signal })).trim();
					return textResult(`emulate: step_until ${ea}`, vars || "(no VM state — the run may have stalled)", { ctx, tool: "rizin_emulate" });
				}
				case "vars": {
					const vars = (await rz.cmd("aezvj", { signal })).trim();
					return textResult("emulate: vars", vars || "(no VM state — init first)", { ctx, tool: "rizin_emulate" });
				}
				case "set_var": {
					if (params.name === undefined || params.value === undefined) throw new Error("omp-re: emulate set_var needs name and value");
					const name = validateVarName(params.name);
					const value = validateVarValue(params.value);
					// The set form echoes the assignment ("rsp = 0x7ff000"); the bare
					// print form (`aezv rsp`) is empty in practice — use the echo.
					const out = (await rz.cmd(`aezv ${name} ${value}`, { signal })).trim();
					return textResult(`emulate: set_var ${name}`, out || `${name} set`, { ctx, tool: "rizin_emulate" });
				}
				default:
					throw new Error(`omp-re: emulate: unknown action ${JSON.stringify(params.action)}`);
			}
		},
	});
}

/** Clamp the step count to a sane range (1..1000 instructions). */
function clampCount(value: number | undefined): number {
	if (value === undefined || !Number.isFinite(value)) return 1;
	return Math.max(1, Math.min(Math.floor(value), 1000));
}
