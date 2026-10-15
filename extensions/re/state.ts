/**
 * Per-omp-session state shared across the omp-re modules: the rizin process
 * and the currently open binary. Keyed by ctx.sessionManager.getSessionId(),
 * so the main session and every task subagent (each with its own session id)
 * get their own rizin process.
 */
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { annotationFingerprint, liveAnnotations, replayAnnotations } from "./annotations.ts";
import { branchEntries } from "./entries.ts";
import { assertRizinAvailable, raceAbort, RzSession, resolveBinaryPath, resolveRizinPath, type SpawnOptions } from "./rizin.ts";

export interface ReSessionState {
	sessionId: string;
	rz: RzSession | null;
	/** In-flight spawn, so concurrent tool calls after a crash share one respawn instead of racing two. */
	spawning: Promise<RzSession> | null;
	/** The DEBUG session (rizin -d), which has launched the target process. Separate from `rz`, created only by the `debug` tool, never auto-respawned (that would silently re-run the program). */
	dbg: RzSession | null;
	binaryPath: string | null;
	/** annotationFingerprint() of the annotations applied to `rz`; compared after branch/tree changes. */
	appliedAnnotations: string;
	auditHmacWarned: boolean;
	evidenceCount: number;
	findingCount: number;
	/** normalized addr -> most recent evidence id observed at that address (used by mutate tools to ground annotations, and by report anchors) */
	evidenceByAddr: Map<string, string>;
}

const sessions = new Map<string, ReSessionState>();

function newState(sessionId: string): ReSessionState {
	return {
		sessionId,
		rz: null,
		spawning: null,
		dbg: null,
		binaryPath: null,
		appliedAnnotations: "",
		auditHmacWarned: false,
		evidenceCount: 0,
		findingCount: 0,
		evidenceByAddr: new Map(),
	};
}

export function getState(ctx: ExtensionContext): ReSessionState {
	const sessionId = ctx.sessionManager.getSessionId();
	let state = sessions.get(sessionId);
	if (!state) {
		state = newState(sessionId);
		sessions.set(sessionId, state);
	}
	return state;
}

/** Idempotent teardown: closes the rizin process and drops the state entry. */
export function shutdownState(sessionId: string): void {
	const state = sessions.get(sessionId);
	if (!state) return;
	state.rz?.close();
	state.dbg?.close(); // closing the debug rizin also kills the launched debuggee
	sessions.delete(sessionId);
}

/** Carry a session's state over to a new session id (a branch writes a new session file with the same history up to the branch point), instead of leaking the old process and re-analyzing from scratch. */
export function rekeyState(fromId: string, toId: string): void {
	if (fromId === toId) return;
	const state = sessions.get(fromId);
	if (!state || sessions.has(toId)) return;
	sessions.delete(fromId);
	state.sessionId = toId;
	sessions.set(toId, state);
}

export function requireBinary(state: ReSessionState): string {
	if (!state.binaryPath) {
		throw new Error("omp-re: no binary open — use /re open <path>, open_binary, or --binary <path> first");
	}
	return state.binaryPath;
}

/**
 * Spawn and analyze a fresh rizin process for `binaryPath`, then replay the
 * annotations this branch recorded for it. Replaces (and closes) any process
 * the state already held. Returns replay failures for the caller to surface.
 */
export async function spawnRizin(
	ctx: ExtensionContext,
	binaryPath: string,
	options: SpawnOptions = {},
): Promise<{ rz: RzSession; replayFailures: string[] }> {
	const state = getState(ctx);
	// Fail with omp-re's own messages (binary gone since the session recorded it, rizin not installed) rather than a bare spawn error.
	await resolveBinaryPath(binaryPath);
	await assertRizinAvailable();
	const rz = await RzSession.spawn(resolveRizinPath(), binaryPath, options);
	const live = liveAnnotations(branchEntries(ctx), binaryPath);
	const replayFailures = await replayAnnotations(rz, live);
	if (state.rz !== rz) state.rz?.close();
	state.rz = rz;
	state.binaryPath = binaryPath;
	state.appliedAnnotations = annotationFingerprint(live);
	return { rz, replayFailures };
}

/**
 * Returns a live RzSession for this session, transparently respawning (and
 * replaying annotations) against the same binary if the previous process
 * died, timed out, or went stale after a branch change. The respawn is shared
 * by every concurrent caller, so a caller's `signal` only stops that caller
 * waiting — it never kills an analysis other calls are also waiting on.
 */
export async function ensureRizin(ctx: ExtensionContext, options: SpawnOptions = {}): Promise<RzSession> {
	const state = getState(ctx);
	if (state.rz && !state.rz.isClosed) return state.rz;
	if (state.spawning) return raceAbort(state.spawning, options.signal, "waiting for rizin analysis");
	const binaryPath = requireBinary(state);
	state.spawning = spawnRizin(ctx, binaryPath, { onProgress: options.onProgress })
		.then(({ rz, replayFailures }) => {
			if (replayFailures.length > 0 && ctx.hasUI) {
				ctx.ui.notify(`omp-re: ${replayFailures.length} annotation(s) could not be replayed:\n${replayFailures.join("\n")}`, "warning");
			}
			return rz;
		})
		.finally(() => {
			state.spawning = null;
		});
	return raceAbort(state.spawning, options.signal, "waiting for rizin analysis");
}

/** Record that the rizin process now matches the branch's annotations (after a forward mutation or an undo applied them directly). */
export function markAnnotationsApplied(ctx: ExtensionContext): void {
	const state = getState(ctx);
	if (!state.binaryPath) return;
	state.appliedAnnotations = annotationFingerprint(liveAnnotations(branchEntries(ctx), state.binaryPath));
}

/**
 * After `/tree` navigation or a branch, the active branch may carry a
 * different set of annotations than the live rizin process. When it does,
 * close the process; the next tool call respawns it and replays exactly this
 * branch's annotations. Lazy on purpose: a navigation that never touches the
 * binary again costs nothing.
 */
export function syncAnnotationsToBranch(ctx: ExtensionContext): void {
	const state = getState(ctx);
	if (!state.binaryPath || !state.rz) return;
	const wanted = annotationFingerprint(liveAnnotations(branchEntries(ctx), state.binaryPath));
	if (wanted !== state.appliedAnnotations) {
		state.rz.close();
		state.rz = null;
	}
}
