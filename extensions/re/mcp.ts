/**
 * MCP servers as functions inside the `run` namespace ("tools as code").
 *
 * omp gives an extension no way to call other tools: `ctx.invokeTool` reaches
 * only the built-in of the extension tool's own name, by design, so an
 * extension cannot get past the approval omp gave for its own call. So omp's
 * built-in tools stay out of the namespace. MCP servers do not need omp's tool
 * dispatch. The namespace speaks MCP to them itself, with omp's own client
 * (`connectToServer` / `listTools` / `callTool`) and omp's own server
 * configuration (`loadAllMCPConfigs`, the same project and user `mcp.json`
 * sources omp reads), so `await mcp.connect("github")` gives the code a server
 * whose tools are async methods.
 *
 * Connections live here on the host, never in the namespace worker: a stdio
 * server is a child process, and terminating a worker must not orphan one.
 * Each namespace owns a bridge; resetting or disposing the namespace closes
 * every connection it opened. Every tool call is audited like a capability
 * call.
 */
import type { MCPServerConfig, MCPServerConnection, MCPToolCallResult } from "@oh-my-pi/pi-coding-agent/mcp/types";
import type { AdHocMcpServer, McpConnectionInfo } from "./namespace-protocol.ts";

type McpClient = typeof import("@oh-my-pi/pi-coding-agent/mcp/client");
type McpConfig = typeof import("@oh-my-pi/pi-coding-agent/mcp/config");

let modules: Promise<{ client: McpClient; config: McpConfig }> | null = null;

/** omp's MCP client and config loader, loaded on first use (an omp plugin can resolve only the host's packages). */
function omp(): Promise<{ client: McpClient; config: McpConfig }> {
	if (!modules) {
		modules = Promise.all([import("@oh-my-pi/pi-coding-agent/mcp/client"), import("@oh-my-pi/pi-coding-agent/mcp/config")])
			.then(([client, config]) => ({ client, config }))
			.catch((err) => {
				modules = null;
				throw new Error(`omp-re: mcp: could not load omp's MCP client (${err instanceof Error ? err.message : String(err)}); this omp build may be incompatible`);
			});
	}
	return modules;
}

function targetOf(config: MCPServerConfig): string {
	return config.type === "http" || config.type === "sse" ? config.url : [config.command, ...(config.args ?? [])].join(" ");
}

function adHocConfig(target: AdHocMcpServer): MCPServerConfig {
	if (target.url) return { type: "http", url: target.url, ...(target.headers ? { headers: target.headers } : {}) };
	if (target.command) {
		return { type: "stdio", command: target.command, ...(target.args ? { args: target.args } : {}), ...(target.env ? { env: target.env } : {}), ...(target.cwd ? { cwd: target.cwd } : {}) };
	}
	throw new TypeError("omp-re: mcp.connect takes a configured server's name, { command, args?, env?, cwd? }, or { url, headers? }");
}

/** What a tool call returns to the code: the server's structured content when it sends some, else its text. An error result rejects. */
function resultOf(result: MCPToolCallResult, label: string): unknown {
	const text = result.content
		.map((part) => (part.type === "text" ? part.text : `[${part.type}]`))
		.join("\n");
	if (result.isError) throw new Error(`${label}: ${text || "the server reported an error"}`);
	return result.structuredContent ?? text;
}

export class McpBridge {
	private readonly connections = new Map<number, MCPServerConnection>();
	private next = 1;

	/** The servers omp is configured with for this project and user: name → transport, target, enabled. */
	async servers(cwd: string): Promise<Record<string, { type: string; target: string; enabled: boolean }>> {
		const { config } = await omp();
		const { configs } = await config.loadAllMCPConfigs(cwd);
		return Object.fromEntries(
			Object.entries(configs).map(([name, server]) => [name, { type: server.type ?? "stdio", target: targetOf(server), enabled: server.enabled !== false }]),
		);
	}

	async connect(target: string | AdHocMcpServer, cwd: string, signal: AbortSignal | undefined): Promise<McpConnectionInfo> {
		const { client, config } = await omp();
		let name: string;
		let server: MCPServerConfig;
		if (typeof target === "string") {
			const { configs } = await config.loadAllMCPConfigs(cwd);
			const found = configs[target];
			if (!found) throw new Error(`omp-re: mcp: no MCP server named ${JSON.stringify(target)} is configured — mcp.servers() lists them, or pass { command } / { url }`);
			if (found.enabled === false) throw new Error(`omp-re: mcp: server ${JSON.stringify(target)} is disabled in omp's configuration`);
			name = target;
			server = found;
		} else {
			name = target.name ?? `mcp${this.next}`;
			server = adHocConfig(target);
		}
		const connection = await client.connectToServer(name, server, { signal });
		try {
			const tools = await client.listTools(connection, { signal });
			const id = this.next++;
			this.connections.set(id, connection);
			return {
				id,
				name,
				...(connection.instructions ? { instructions: connection.instructions } : {}),
				tools: tools.map((tool) => ({ name: tool.name, ...(tool.description ? { description: tool.description } : {}), inputSchema: tool.inputSchema as McpConnectionInfo["tools"][number]["inputSchema"] })),
			};
		} catch (err) {
			await client.disconnectServer(connection).catch(() => {});
			throw err;
		}
	}

	/** The connection's server name, for audit lines and error messages. */
	nameOf(id: number): string {
		return this.connections.get(id)?.name ?? `mcp#${id}`;
	}

	async call(id: number, tool: string, args: unknown, signal: AbortSignal | undefined): Promise<unknown> {
		const connection = this.connections.get(id);
		if (!connection) throw new Error("omp-re: mcp: this server connection is closed — connect again");
		if (args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args))) {
			throw new TypeError(`omp-re: mcp: ${connection.name}.${tool} takes one params object`);
		}
		const { client } = await omp();
		const result = await client.callTool(connection, tool, (args ?? {}) as Record<string, unknown>, { signal });
		return resultOf(result, `${connection.name}.${tool}`);
	}

	async close(id: number): Promise<void> {
		const connection = this.connections.get(id);
		if (!connection) return;
		this.connections.delete(id);
		const { client } = await omp();
		await client.disconnectServer(connection);
	}

	/** Close every connection (the namespace was reset or disposed). Never throws. */
	async closeAll(): Promise<void> {
		const ids = [...this.connections.keys()];
		await Promise.all(ids.map((id) => this.close(id).catch(() => {})));
	}
}
