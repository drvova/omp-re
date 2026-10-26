/**
 * The messages between a session's namespace host (namespace.ts, omp's main
 * thread) and its worker (namespace-worker.ts, where the model's code runs).
 *
 * The worker owns the realm: it compiles and evaluates cells, formats output,
 * and reads and writes kept definitions. Everything that needs omp — a `re`
 * capability, the session's rizin process, the branch's evidence, `exec`, an
 * MCP server — is a `call` the worker sends and the host answers, so a killed
 * worker can never leave omp half-way through one of them.
 */
import type { CapabilityInfo } from "./describe.ts";

export interface BinaryInfo {
	path: string;
	sha256: string | null;
}

export interface KeptFailure {
	name: string;
	error: string;
}

/** An MCP server to connect to that is not in omp's configuration. */
export interface AdHocMcpServer {
	name?: string;
	command?: string;
	args?: string[];
	env?: Record<string, string>;
	cwd?: string;
	url?: string;
	headers?: Record<string, string>;
}

export interface McpToolInfo {
	name: string;
	description?: string;
	inputSchema?: CapabilityInfo["schema"];
}

export interface McpConnectionInfo {
	id: number;
	name: string;
	instructions?: string;
	tools: McpToolInfo[];
}

/** One thing the worker asks the host to do on behalf of the running cell. */
export type HostOp =
	| { kind: "capability"; name: string; params: unknown }
	| { kind: "rz"; method: "open" | "cmd" | "cmdj" | "cmdWithStderr" | "close"; command?: string }
	| { kind: "evidence" }
	| { kind: "findings" }
	| { kind: "exec"; bin: string; argv: string[]; timeout?: number }
	| { kind: "mcp.servers" }
	| { kind: "mcp.connect"; target: string | AdHocMcpServer }
	| { kind: "mcp.call"; connection: number; tool: string; args: unknown }
	| { kind: "mcp.close"; connection: number };

export type ToWorker =
	| { type: "init"; capabilities: CapabilityInfo[]; keptDir: string; toolName: string; binary: BinaryInfo | null }
	| { type: "run"; runId: number; code: string; strings: Record<string, string>; binary: BinaryInfo | null }
	| { type: "reply"; callId: number; ok: true; value: unknown; binary: BinaryInfo | null }
	| { type: "reply"; callId: number; ok: false; error: { name: string; message: string }; binary: BinaryInfo | null };

export type FromWorker =
	| { type: "ready"; kept: string[]; failures: KeptFailure[] }
	| { type: "print"; runId: number; text: string }
	| { type: "call"; callId: number; runId: number; op: HostOp }
	| { type: "done"; runId: number; value: unknown; shown: string | undefined; saved: string[]; kept: string[]; failures: KeptFailure[]; notes: string[] }
	| { type: "failed"; runId: number; error: string; kept: string[]; failures: KeptFailure[] };
