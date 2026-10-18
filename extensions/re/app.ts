/**
 * The composition root for omp-re.
 *
 * Every subsystem — the read/mutate/rizin/CLI/debug/triage tool groups, the
 * evidence store, the audit log, the UI, and the command shell — is applied
 * here, in order, with the omp host (`pi`) handed to each. The subsystems'
 * registration functions stay plain `(pi) => …` so they remain unit-testable
 * in isolation; this module only sequences them.
 *
 * This used to be a cordis context graph, but a cordis `Context` meant a
 * third-party runtime dependency, and an installed omp plugin can only resolve
 * the host's own `@oh-my-pi/*` packages — not arbitrary deps — so the plugin
 * failed to load with "Cannot find package 'cordis'". The composition it
 * bought was a plain dependency-ordered loop: every subsystem needs only the
 * host, which is always present, so a sequential `await` over the list gives
 * the same ordering and the same "host injected" guarantee with no dependency
 * to resolve. Teardown that is real lives in `runtime.ts` (the per-session
 * rizin/debug processes); omp exposes no extension-unload hook, so there is
 * nothing to revert at this level (see the note there).
 */
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

/** A subsystem: a name and the registration it runs with the host. */
export interface ReSubsystem {
  name: string;
  apply: (pi: ExtensionAPI) => void | Promise<void>;
}

/**
 * Apply each subsystem in order, awaiting every one (the PATH-probing tool
 * groups are async) so all tools and listeners are registered before the
 * extension finishes initializing.
 */
export async function composeApp(
  pi: ExtensionAPI,
  subsystems: readonly ReSubsystem[]
): Promise<void> {
  for (const sub of subsystems) {
    await sub.apply(pi);
  }
}
