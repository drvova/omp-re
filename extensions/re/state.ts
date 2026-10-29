/**
 * Per-omp-session state, a thin facade over the backend in `runtime.ts`. Keyed
 * by `ctx.sessionManager.getSessionId()`, so the main session and every task
 * subagent get their own rizin process.
 *
 * `getState` hands back a **read-only view**: external modules (tools, UI,
 * evidence, audit) query it, but every mutation goes through a named function
 * here. That keeps the shared per-session record from being poked field-by-field
 * across two dozen files — the coupling is explicit and the invariants live in
 * one place (the backend for process lifecycle, this facade for the rest).
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { normalizeAddr, type LoadOptions, type RzSession, type SpawnOptions } from "./rizin.ts";
import { backend, type ReSessionState, type ReSessionView } from "./runtime.ts";

export type { ReSessionView } from "./runtime.ts";

const sid = (ctx: ExtensionContext): string => ctx.sessionManager.getSessionId();
/** The mutable record. Only this facade touches it directly; external modules get the read-only view. */
const rec = (ctx: ExtensionContext): ReSessionState => backend().record(sid(ctx));

/** The read-only per-session view. Query it; mutate only through the named functions below. */
export function getState(ctx: ExtensionContext): ReSessionView {
	return backend().record(sid(ctx));
}

/** Idempotent teardown: closes the session's rizin (and debug) processes via their effects and drops the record. */
export function shutdownState(sessionId: string): void {
	backend().dispose(sessionId);
}

/** Carry a session's state over to a new session id (a branch writes a new session file with the same history up to the branch point). */
export function rekeyState(fromId: string, toId: string): void {
	backend().rekey(fromId, toId);
}

export function requireBinary(state: ReSessionView): string {
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

// --- Intent mutators: the only way external modules change session state. ---

/** `/re off`/`/re on`: gate every RE tool call in this session. */
export function setToolsOff(ctx: ExtensionContext, off: boolean): void {
	rec(ctx).toolsOff = off;
}

/** Stamp the SHA-256 of the open binary (bound into evidence for `/re verify`); null clears it. */
export function setBinarySha256(ctx: ExtensionContext, sha: string | null): void {
	rec(ctx).binarySha256 = sha;
}

/** Publish an in-flight background open so tool calls and `/re` wait on it instead of racing. */
export function setPendingOpen(ctx: ExtensionContext, opening: Promise<void> | null): void {
	rec(ctx).opening = opening;
}

/** Clear the pending open only if it is still this one (a later open may have replaced it). */
export function clearPendingOpen(ctx: ExtensionContext, opening: Promise<void>): void {
	const r = rec(ctx);
	if (r.opening === opening) r.opening = null;
}

/** Warn-once latch for a missing audit HMAC key: true the first time this session (warn now), false after. */
export function markAuditHmacWarned(ctx: ExtensionContext): boolean {
	const r = rec(ctx);
	if (r.auditHmacWarned) return false;
	r.auditHmacWarned = true;
	return true;
}

/** A branch/resume switched which binary this session is about: tear the live process down and record the new identity (the next tool call respawns). No-op when unchanged. */
export function switchBinary(ctx: ExtensionContext, binaryPath: string | null, loadOptions: LoadOptions | null = null): void {
	backend().switchBinary(sid(ctx), binaryPath, loadOptions);
}

/** Attach an already-spawned rizin process as the session's live one (a direct attach, and the test fixtures that inject a process). */
export function attachSession(ctx: ExtensionContext, rz: RzSession): void {
	backend().attachSession(sid(ctx), rz);
}

/** Drop the in-memory evidence index (it is rebuilt from the branch on resume/branch/tree). */
export function resetEvidenceIndex(ctx: ExtensionContext): void {
	const r = rec(ctx);
	r.evidenceByAddr.clear();
	r.evidenceCount = 0;
}

/** Count one evidence record; index it by address when it has one. */
export function recordEvidenceAt(ctx: ExtensionContext, ea: string | undefined, id: string): void {
	const r = rec(ctx);
	r.evidenceCount++;
	if (ea) r.evidenceByAddr.set(normalizeAddr(ea), id);
}

/** The most recent evidence id recorded at an address, or undefined — the grounding lookup for mutate tools. */
export function evidenceIdAt(ctx: ExtensionContext, ea: string): string | undefined {
	return rec(ctx).evidenceByAddr.get(normalizeAddr(ea));
}
