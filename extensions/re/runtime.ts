/**
 * The cordis backbone for omp-re.
 *
 * Process lifecycle — the part that used to be hand-rolled in `state.ts` as a
 * `Map` of nullable fields with scattered `.close()` calls — is modelled with
 * cordis's *revertible effects* (https://github.com/cordiverse/cordis, the
 * "context paradigm"). One root `Context` is created per extension load; each
 * omp session gets a child scope (a cordis fiber), and each rizin process it
 * owns — the static analysis session and the opt-in debug session — is a
 * `ctx.effect` whose setup returns its own teardown. The runtime holds that
 * inverse, so closing a process is never wired by hand: disposing the one
 * effect closes one process (a respawn), and disposing the whole session
 * scope closes every process it owns (session shutdown). RzSession itself
 * stays the low-level transport; cordis owns *when it lives and dies*.
 *
 * `getState()` stays synchronous and returns a plain record, so the many
 * call sites that read/write counters and paths are unchanged; the cordis
 * scope attaches lazily the first time a process is spawned.
 */
import { Context } from "cordis";
import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { annotationFingerprint, liveAnnotations, replayAnnotations } from "./annotations.ts";
import { branchEntries, recordedAnalysisPasses, recordedSignatures } from "./entries.ts";
import { replayAnalysisPasses } from "./passes.ts";
import { analysisTimeoutMs, assertRizinAvailable, type LoadOptions, raceAbort, RzSession, rizinBitsMismatch, resolveBinaryPath, resolveRizinPath, type SpawnOptions } from "./rizin.ts";
import { replaySignatures } from "./signatures.ts";

/** The per-omp-session record. The public fields are read and written directly by the tools, UI, evidence, and audit modules exactly as before. */
export interface ReSessionState {
	sessionId: string;
	rz: RzSession | null;
	/** In-flight spawn, so concurrent tool calls after a crash share one respawn instead of racing two. */
	spawning: Promise<RzSession> | null;
	/** The DEBUG session (rizin -d), which has launched the target process. Separate from `rz`, created only by the `debug` tool, never auto-respawned (that would silently re-run the program). */
	dbg: RzSession | null;
	binaryPath: string | null;
	/** Explicit load settings (`-a/-b/-B/-F`) for a headerless/raw target, reused on every respawn so a resume or crash recovery loads the blob the same way. Null means header autodetection. */
	loadOptions: LoadOptions | null;
	/** annotationFingerprint() of the annotations applied to `rz`; compared after branch/tree changes. */
	appliedAnnotations: string;
	auditHmacWarned: boolean;
	evidenceCount: number;
	findingCount: number;
	/** normalized addr -> most recent evidence id observed at that address (used by mutate tools to ground annotations, and by report anchors) */
	evidenceByAddr: Map<string, string>;
	/** cordis internals: the session's child scope and the live effect disposers that own each process's teardown. Not read outside the backend. */
	_scope: ScopeHandle | null;
	_disposeRz: Disposer | null;
	_disposeDbg: Disposer | null;
}

type Disposer = () => Promise<void> | void;

interface ScopeHandle {
	ctx: Context;
	dispose: () => Promise<void>;
}

function newState(sessionId: string): ReSessionState {
	return {
		sessionId,
		rz: null,
		spawning: null,
		dbg: null,
		binaryPath: null,
		loadOptions: null,
		appliedAnnotations: "",
		auditHmacWarned: false,
		evidenceCount: 0,
		findingCount: 0,
		evidenceByAddr: new Map(),
		_scope: null,
		_disposeRz: null,
		_disposeDbg: null,
	};
}

/**
 * Owns the root cordis `Context` and the per-session scopes. One instance per
 * process (lazily built), reachable through the `state.ts` facade so tools and
 * tests keep their existing imports.
 */
class RizinBackend {
	private readonly root = new Context();
	private readonly records = new Map<string, ReSessionState>();

	/** The plain record for a session, created on first use. Synchronous: the cordis scope is attached later, on first spawn. */
	record(sessionId: string): ReSessionState {
		let rec = this.records.get(sessionId);
		if (!rec) {
			rec = newState(sessionId);
			this.records.set(sessionId, rec);
		}
		return rec;
	}

	/** The session's child scope (a cordis fiber), created and activated on demand. Processes register their teardown as effects on `scope.ctx`. */
	private async scope(rec: ReSessionState): Promise<Context> {
		if (rec._scope) return rec._scope.ctx;
		const fiber = this.root.plugin(() => {});
		await fiber;
		rec._scope = { ctx: fiber.ctx, dispose: () => fiber.dispose() };
		return rec._scope.ctx;
	}

	requireBinary(rec: ReSessionState): string {
		if (!rec.binaryPath) {
			throw new Error("omp-re: no binary open — use /re open <path>, open_binary, or --binary <path> first");
		}
		return rec.binaryPath;
	}

	/**
	 * Spawn and analyze a fresh rizin process for `binaryPath`, replay this
	 * branch's annotations, and hand the process's teardown to the session
	 * scope as a revertible effect. The previous process (if any) is torn down
	 * through its own effect once the new one is live.
	 */
	async spawn(ctx: ExtensionContext, binaryPath: string, options: SpawnOptions = {}): Promise<{ rz: RzSession; replayFailures: string[] }> {
		const rec = this.record(ctx.sessionManager.getSessionId());
		// Fail with omp-re's own messages (binary gone since the session recorded it, rizin not installed) rather than a bare spawn error.
		await resolveBinaryPath(binaryPath);
		await assertRizinAvailable();
		// A fresh open carries explicit load options; a respawn/resume (none passed) reuses what this session last opened the binary with.
		if (options.loadOptions) rec.loadOptions = options.loadOptions;
		const loadOptions = options.loadOptions ?? rec.loadOptions ?? undefined;
		const rz = await RzSession.spawn(resolveRizinPath(binaryPath, loadOptions?.bits), binaryPath, { ...options, loadOptions });
		// Rebuild the branch's layered analysis on top of the baseline `aaa`, in
		// dependency order so each layer can see the one before it, and so switching
		// binaries never carries one binary's layers onto another:
		//   1. analysis passes find functions (prelude scan, Go/ObjC recovery, …),
		//   2. signatures name the functions that now exist,
		//   3. annotations (renames, types, …) are the analyst's edits on top.
		const entries = branchEntries(ctx);
		const passFailures = await replayAnalysisPasses(rz, recordedAnalysisPasses(entries, binaryPath), analysisTimeoutMs());
		const signatureFailures = await replaySignatures(rz, recordedSignatures(entries, binaryPath));
		const live = liveAnnotations(entries, binaryPath);
		const replayFailures = [...passFailures, ...signatureFailures, ...(await replayAnnotations(rz, live))];

		const scope = await this.scope(rec);
		const previous = rec._disposeRz;
		// Revertible effect: the inverse closes exactly this process. Idempotent, so an explicit close elsewhere is harmless.
		rec._disposeRz = scope.effect(() => () => {
			if (!rz.isClosed) rz.close();
		}, "rizin process");
		rec.rz = rz;
		rec.binaryPath = binaryPath;
		rec.appliedAnnotations = annotationFingerprint(live);
		await previous?.(); // close the prior process now that the replacement is analyzed and live
		return { rz, replayFailures };
	}

	/**
	 * A live RzSession for this session, respawning (and replaying annotations)
	 * if the previous process died or went stale. The respawn is shared by
	 * every concurrent caller, so one caller's `signal` only stops that caller
	 * waiting — it never kills an analysis the others are also waiting on.
	 */
	async ensure(ctx: ExtensionContext, options: SpawnOptions = {}): Promise<RzSession> {
		const rec = this.record(ctx.sessionManager.getSessionId());
		if (rec.rz && !rec.rz.isClosed) return rec.rz;
		if (rec.spawning) return raceAbort(rec.spawning, options.signal, "waiting for rizin analysis");
		const binaryPath = this.requireBinary(rec);
		rec.spawning = this.spawn(ctx, binaryPath, { onProgress: options.onProgress })
			.then(({ rz, replayFailures }) => {
				if (replayFailures.length > 0 && ctx.hasUI) {
					ctx.ui.notify(`omp-re: ${replayFailures.length} annotation(s) could not be replayed:\n${replayFailures.join("\n")}`, "warning");
				}
				return rz;
			})
			.finally(() => {
				rec.spawning = null;
			});
		return raceAbort(rec.spawning, options.signal, "waiting for rizin analysis");
	}

	/** Launch the debug session (rizin -d) as a second effect on the same scope. Returns the existing one if already running. */
	async startDebug(ctx: ExtensionContext, options: SpawnOptions = {}): Promise<RzSession> {
		const rec = this.record(ctx.sessionManager.getSessionId());
		if (rec.dbg && !rec.dbg.isClosed) return rec.dbg;
		const binaryPath = this.requireBinary(rec);
		// The debug launch loads the target the same way the static session did
		// (raw blob arch/bits/base), so stepping agrees with the analysis.
		const loadOptions = rec.loadOptions ?? undefined;
		const rizinPath = resolveRizinPath(binaryPath, loadOptions?.bits);
		// The debugger executes the process: a build whose bits don't match the
		// target produces wrong-arch semantics (file-relative VM bases,
		// esp-vs-rsp) — say so loudly instead of letting them pass as results.
		const mismatch = await rizinBitsMismatch(binaryPath);
		if (mismatch) ctx.ui?.notify?.(`omp-re: ${mismatch}`, "warning");
		const dbg = await RzSession.spawnDebug(rizinPath, binaryPath, { ...options, loadOptions });
		const scope = await this.scope(rec);
		rec._disposeDbg = scope.effect(() => () => {
			if (!dbg.isClosed) dbg.close(); // closing the debug rizin also kills the launched debuggee
		}, "debug process");
		rec.dbg = dbg;
		return dbg;
	}

	/** Tear down just the debug process (its effect inverse), leaving the static session untouched. */
	async stopDebug(ctx: ExtensionContext): Promise<boolean> {
		const rec = this.record(ctx.sessionManager.getSessionId());
		if (!rec.dbg || rec.dbg.isClosed) {
			rec.dbg = null;
			return false;
		}
		const dispose = rec._disposeDbg;
		rec._disposeDbg = null;
		rec.dbg = null;
		await dispose?.();
		return true;
	}

	markAnnotationsApplied(ctx: ExtensionContext): void {
		const rec = this.record(ctx.sessionManager.getSessionId());
		if (!rec.binaryPath) return;
		rec.appliedAnnotations = annotationFingerprint(liveAnnotations(branchEntries(ctx), rec.binaryPath));
	}

	/**
	 * After `/tree` navigation or a branch, the active branch may carry a
	 * different annotation set than the live process. When it does, tear the
	 * process down (via its effect); the next tool call respawns it and replays
	 * exactly this branch's annotations. Lazy on purpose.
	 */
	syncToBranch(ctx: ExtensionContext): void {
		const rec = this.record(ctx.sessionManager.getSessionId());
		if (!rec.binaryPath || !rec.rz) return;
		const wanted = annotationFingerprint(liveAnnotations(branchEntries(ctx), rec.binaryPath));
		if (wanted !== rec.appliedAnnotations) {
			const dispose = rec._disposeRz;
			rec._disposeRz = null;
			rec.rz = null;
			void dispose?.(); // effect inverse closes the process
		}
	}

	/** Teardown for a session: disposing the scope runs every process effect's inverse. Also closes directly so synchronous callers (tests, shutdown) see the processes gone at once. */
	dispose(sessionId: string): void {
		const rec = this.records.get(sessionId);
		if (!rec) return;
		rec.rz?.close();
		rec.dbg?.close();
		void rec._scope?.dispose();
		this.records.delete(sessionId);
	}

	/** Carry a session's record (and its live scope) to a new id — a branch writes a new session file with the same history up to the branch point. */
	rekey(fromId: string, toId: string): void {
		if (fromId === toId) return;
		const rec = this.records.get(fromId);
		if (!rec || this.records.has(toId)) return;
		this.records.delete(fromId);
		rec.sessionId = toId;
		this.records.set(toId, rec);
	}
}

let backendSingleton: RizinBackend | null = null;

/** The process-wide backend, built on first use. */
export function backend(): RizinBackend {
	if (!backendSingleton) backendSingleton = new RizinBackend();
	return backendSingleton;
}
