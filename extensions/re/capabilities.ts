/**
 * The capability registry: omp-re's RE operations, reached from code instead
 * of advertised as tools.
 *
 * Every tool module (tools-read.ts, tools-mutate.ts, findings.ts, …) still
 * builds its operations with `pi.registerTool({...})`, unchanged — the tests
 * drive those definitions directly. At load, index.ts hands those modules
 * `registry.host(pi)` instead of `pi`: the same host, except that
 * `registerTool` records the definition here rather than advertising it. The
 * one tool omp actually sees is `run` (tools-run.ts); inside it, each recorded
 * definition is a method on `re` (namespace.ts), and {@link invokeCapability}
 * is the single path a method call takes:
 *
 *   validate the params against the definition's own schema
 *   → one audit-log line (audit.ts), as a tool call used to get
 *   → the definition's own `execute`
 *   → for an evidence-tier operation, a `re.evidence` record and the
 *     `[evidence xxxxxxxx]` tag (evidence.ts), as a tool result used to get.
 *
 * What a session can do depends on what is installed (capa, floss, the rz-*
 * tools) and enabled (the debugger), so the registry holds exactly what was
 * registered at load — the live capability set `describe(re)` shows.
 */
import type { AgentToolUpdateCallback, ExtensionAPI, ExtensionContext, ToolDefinition } from "@oh-my-pi/pi-coding-agent";
import { appendAuditLine, RE_EVIDENCE_TOOL_NAMES } from "./audit.ts";
import { extractText, recordAndTag } from "./evidence.ts";

type AnyTool = ToolDefinition<any, any>;
type Tier = "read" | "write" | "exec";

export interface Capability {
	name: string;
	/** The definition's full description, as the tool used to present it to the model. */
	description: string;
	/** omp's approval tier the definition declares; now descriptive only — the `run` call is what omp approves. */
	tier: Tier;
	/** Whether a successful call becomes a `re.evidence` record (evidence.ts). */
	evidence: boolean;
	/** JSON Schema of the parameters (omp's schema builder emits it), for signatures and validation messages. */
	schema: JsonSchema;
	definition: AnyTool;
}

export interface JsonSchema {
	type?: string;
	description?: string;
	properties?: Record<string, JsonSchema>;
	required?: string[];
	items?: JsonSchema;
	enum?: unknown[];
	const?: unknown;
	anyOf?: JsonSchema[];
	oneOf?: JsonSchema[];
	additionalProperties?: JsonSchema | boolean;
}

/** What one `run` call lends its capability calls: the host, the call's context and signal, and the tallies its result reports. */
export interface CallScope {
	pi: ExtensionAPI;
	ctx: ExtensionContext;
	signal: AbortSignal | undefined;
	onUpdate: AgentToolUpdateCallback<any> | undefined;
	toolCallId: string;
	/** Capability calls made so far in this run, by name, in order. */
	calls: string[];
	/** Evidence recorded in this run, so the result can list the ids even when the code never printed them. */
	evidence: { id: string; tool: string; ea?: string }[];
}

function tierOf(def: AnyTool): Tier {
	const approval = def.approval as unknown;
	if (typeof approval === "string") return approval as Tier;
	if (typeof approval === "function") {
		try {
			const decided = approval({}) as { tier?: Tier } | Tier;
			return typeof decided === "string" ? decided : (decided.tier ?? "exec");
		} catch {
			return "exec";
		}
	}
	return "exec"; // omp's own default for a tool that declares none
}

function schemaOf(def: AnyTool): JsonSchema {
	const params = def.parameters as { toJsonSchema?: () => JsonSchema };
	try {
		return params.toJsonSchema?.() ?? {};
	} catch {
		return {};
	}
}

export class CapabilityRegistry {
	private readonly byName = new Map<string, Capability>();

	/**
	 * The host as a capability module sees it: `registerTool` records the
	 * definition here instead of advertising it; every other member is the
	 * real host's, bound to it.
	 */
	host(pi: ExtensionAPI): ExtensionAPI {
		return new Proxy(pi, {
			get: (target, prop) => {
				if (prop === "registerTool") return (def: AnyTool) => this.add(def);
				const value = Reflect.get(target, prop, target) as unknown;
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
	}

	add(def: AnyTool): void {
		this.byName.set(def.name, {
			name: def.name,
			description: def.description,
			tier: tierOf(def),
			evidence: RE_EVIDENCE_TOOL_NAMES[def.name] === true,
			schema: schemaOf(def),
			definition: def,
		});
	}

	get(name: string): Capability | undefined {
		return this.byName.get(name);
	}

	list(): Capability[] {
		return [...this.byName.values()];
	}
}

/** The parameter a bare (non-object) argument fills: the only required one, or the only one there is. */
export function shorthandParam(cap: Capability): string | undefined {
	const required = cap.schema.required ?? [];
	if (required.length === 1) return required[0];
	const props = Object.keys(cap.schema.properties ?? {});
	return required.length === 0 && props.length === 1 ? props[0] : undefined;
}

/**
 * Turn what the code passed into the definition's params: a plain object, or —
 * for an operation with one required parameter (or only one parameter) — that
 * parameter's value alone (`re.decompile_function("main")`). Copied into this realm
 * (cells run in their own), then checked against the schema, including
 * unknown keys, which the schema would otherwise drop silently.
 */
function toParams(cap: Capability, raw: unknown): Record<string, unknown> {
	let value = raw ?? {};
	if (typeof value !== "object" || Array.isArray(value)) {
		const only = shorthandParam(cap);
		if (!only) {
			const required = cap.schema.required ?? [];
			throw new TypeError(`re.${cap.name} takes one params object${required.length ? ` (required: ${required.join(", ")})` : ""} — see describe(re.${cap.name})`);
		}
		value = { [only]: value };
	}
	let params: Record<string, unknown>;
	try {
		params = structuredClone(value) as Record<string, unknown>;
	} catch {
		throw new TypeError(`re.${cap.name}: params must be plain data (strings, numbers, booleans, arrays, objects)`);
	}
	const known = Object.keys(cap.schema.properties ?? {});
	const unknown = Object.keys(params).filter((key) => !known.includes(key));
	if (unknown.length > 0) {
		throw new TypeError(`re.${cap.name}: unknown parameter${unknown.length > 1 ? "s" : ""} ${unknown.join(", ")} — expected ${known.length ? known.join(", ") : "none"}`);
	}
	const schema = cap.definition.parameters as { safeParse?: (v: unknown) => { success: boolean; data?: unknown; error?: { message: string } } };
	const checked = schema.safeParse?.(params);
	if (checked && !checked.success) throw new TypeError(`re.${cap.name}: ${checked.error?.message ?? "invalid params"}`);
	return (checked?.data as Record<string, unknown> | undefined) ?? params;
}

/**
 * One capability call from a `run` cell. Returns the text the tool used to
 * return to the model — with the `[evidence xxxxxxxx]` tag for an evidence
 * operation — and throws what the tool threw, so the code can catch it.
 */
export async function invokeCapability(cap: Capability, raw: unknown, scope: CallScope): Promise<string> {
	const params = toParams(cap, raw);
	scope.calls.push(cap.name);
	const callId = `${scope.toolCallId}.${scope.calls.length}`;
	await appendAuditLine(scope.ctx, { toolCallId: callId, tool: cap.name, args: params }, scope.pi.logger);
	const result = await cap.definition.execute(callId, params, scope.signal, scope.onUpdate, scope.ctx);
	if (result.isError) throw new Error(extractText(result.content) || `re.${cap.name} failed`);
	if (!cap.evidence) return extractText(result.content);
	const tagged = await recordAndTag(scope.pi, scope.ctx, cap.name, params, result.content, result.details);
	if (!tagged) return extractText(result.content);
	const ea = (result.details as { ea?: unknown } | undefined)?.ea;
	scope.evidence.push({ id: tagged.id, tool: cap.name, ...(typeof ea === "string" ? { ea } : {}) });
	return extractText(tagged.content);
}
