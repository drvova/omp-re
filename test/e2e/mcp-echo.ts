/**
 * A minimal MCP server over stdio (newline-delimited JSON-RPC), for
 * test/run.test.ts: `echo` returns its text, `add` returns structured
 * content, `fail` returns an error result.
 *
 *   bun test/e2e/mcp-echo.ts
 */
export {};
const tools = [
	{ name: "echo", description: "Return the text you send. Nothing else.", inputSchema: { type: "object", properties: { text: { type: "string", description: "What to echo." } }, required: ["text"] } },
	{ name: "add", description: "Add two numbers.", inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] } },
	{ name: "fail", description: "Always fails.", inputSchema: { type: "object", properties: {} } },
];

function reply(id: unknown, result: unknown): void {
	process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

function handle(message: { id?: unknown; method?: string; params?: { name?: string; arguments?: Record<string, unknown>; protocolVersion?: string } }): void {
	if (message.id === undefined) return; // a notification
	switch (message.method) {
		case "initialize":
			return reply(message.id, { protocolVersion: message.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "echo", version: "1.0.0" }, instructions: "A test server. It echoes." });
		case "ping":
			return reply(message.id, {});
		case "tools/list":
			return reply(message.id, { tools });
		case "tools/call": {
			const args = message.params?.arguments ?? {};
			if (message.params?.name === "echo") return reply(message.id, { content: [{ type: "text", text: String(args.text) }] });
			if (message.params?.name === "add") return reply(message.id, { content: [{ type: "text", text: "sum" }], structuredContent: { sum: Number(args.a) + Number(args.b) } });
			return reply(message.id, { content: [{ type: "text", text: "deliberate failure" }], isError: true });
		}
		default:
			process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "method not found" } })}\n`);
	}
}

for await (const line of console) {
	if (line.trim()) handle(JSON.parse(line));
}
