/**
 * Per-omp-session state, now a thin facade over the cordis backend in
 * `runtime.ts`. The exported surface is unchanged so the tools, UI, evidence,
 * and audit modules keep their imports; the process lifecycle underneath is
 * managed by cordis revertible effects rather than hand-rolled `.close()`
 * calls. Keyed by `ctx.sessionManager.getSessionId()`, so the main session
 * and every task subagent get their own rizin process.
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { type RzSession, type SpawnOptions } from "./rizin.ts";
import { backend, type ReSessionState } from "./runtime.ts";

export type { ReSessionState } from "./runtime.ts";

export function getState(ctx: ExtensionContext): ReSessionState {
	return backend().record(ctx.sessionManager.getSessionId());
}

/** Idempotent teardown: closes the session's rizin (and debug) processes via their effects and drops the record. */
export function shutdownState(sessionId: string): void {
	backend().dispose(sessionId);
}

/** Carry a session's state over to a new session id (a branch writes a new session file with the same history up to the branch point). */
export function rekeyState(fromId: string, toId: string): void {
	backend().rekey(fromId, toId);
}

export function requireBinary(state: ReSessionState): string {
	return backend().requireBinary(state);
}

/** Spawn and analyze a fresh rizin process, replaying this branch's annotations. Returns replay failures for the caller to surface. */
export function spawnRizin(ctx: ExtensionContext, binaryPath: string, options: SpawnOptions = {}): Promise<{ rz: RzSession; replayFailures: string[] }> {
	return backend().spawn(ctx, binaryPath, options);
}

/** A live RzSession for this session, respawning and replaying annotations transparently if the previous process died or went stale. */
export function ensureRizin(ctx: ExtensionContext, options: SpawnOptions = {}): Promise<RzSession> {
	return backend().ensure(ctx, options);
}

/** Launch the opt-in debug session (rizin -d) for this session, or return the running one. */
export function startDebug(ctx: ExtensionContext, options: SpawnOptions = {}): Promise<RzSession> {
	return backend().startDebug(ctx, options);
}

/** Tear down just the debug process, leaving the static session alive. Returns whether one was running. */
export function stopDebug(ctx: ExtensionContext): Promise<boolean> {
	return backend().stopDebug(ctx);
}

/** The running debug session for this session, or throw omp-re's guidance to start one first. */
export function requireDebug(ctx: ExtensionContext): RzSession {
	const rz = getState(ctx).dbg;
	if (!rz || rz.isClosed) {
		throw new Error("omp-re: no debug session — run the debug tool with action 'start' first (it launches the process).");
	}
	return rz;
}

/** Record that the rizin process now matches the branch's annotations (after a forward mutation or an undo applied them directly). */
export function markAnnotationsApplied(ctx: ExtensionContext): void {
	backend().markAnnotationsApplied(ctx);
}

/** After `/tree` navigation or a branch, tear down the process if the active branch's annotations differ; the next tool call respawns and replays them. */
export function syncAnnotationsToBranch(ctx: ExtensionContext): void {
	backend().syncToBranch(ctx);
}
