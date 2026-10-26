/**
 * Boot omp-re through omp's real SDK in THIS process and run one cell through
 * the `run` tool, printing the result as JSON — used by test/run.test.ts to
 * prove that a definition kept by one process is loaded into a fresh one.
 *
 *   bun test/e2e/run-cell.ts <agentDir> <code>
 *
 * The kept directory comes from OMPRE_KEPT_DIR, exactly as in production.
 */
import { resolve } from "node:path";
import { setAgentDir } from "@oh-my-pi/pi-utils";

const [agentDir, code] = process.argv.slice(2);
if (!agentDir || code === undefined) {
	console.error("usage: bun test/e2e/run-cell.ts <agentDir> <code>");
	process.exit(2);
}
setAgentDir(agentDir);

const sdk = await import("@oh-my-pi/pi-coding-agent");
const { initializeExtensions } = await import("@oh-my-pi/pi-coding-agent/modes/runtime-init");
const { session, extensionsResult } = await sdk.createAgentSession({
	cwd: agentDir,
	additionalExtensionPaths: [resolve(import.meta.dir, "../../extensions/re")],
	disableExtensionDiscovery: true,
	sessionManager: sdk.SessionManager.inMemory() as never,
});
if (extensionsResult.errors.length > 0) throw new Error(JSON.stringify(extensionsResult.errors));
await initializeExtensions(session, { reportSendError: () => {}, reportRuntimeError: () => {} } as never);

let output: { ok: boolean; text: string };
try {
	const result = await session.getToolByName("run")!.execute("t-child", { code });
	const block = result.content[0];
	output = { ok: true, text: block?.type === "text" ? block.text : "" };
} catch (err) {
	output = { ok: false, text: err instanceof Error ? err.message : String(err) };
}
await session.dispose();
console.log(JSON.stringify(output));
process.exit(0);
