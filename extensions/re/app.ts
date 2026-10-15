/**
 * The cordis composition root for omp-re.
 *
 * Every subsystem — the read/mutate/rizin/CLI/debug/triage tool groups, the
 * evidence store, the audit log, the UI, and the command shell — is a cordis
 * plugin loaded on one `Context` created per extension load. The omp host
 * (`pi`) is provided as a service, and each subsystem declares it as a
 * dependency (`inject: ["pi"]`), so a subsystem activates only once the host
 * is present — the paper's *reactive coeffect* (spatial composability) in
 * practice. One Context per load (not a process singleton) keeps concurrent
 * omp sessions in the same process from sharing a host service.
 *
 * The subsystems' own registration functions stay plain `(pi) => …` so they
 * remain unit-testable in isolation; this module only wires them onto the
 * context graph.
 */
import { Context } from "cordis";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

/** A subsystem: a name and the registration it runs once the host service is available. */
export interface ReSubsystem {
	name: string;
	apply: (pi: ExtensionAPI) => void | Promise<void>;
}

/**
 * Build the extension's context graph: provide `pi`, then load each subsystem
 * as a cordis plugin that injects it. Awaits every plugin's activation (the
 * async ones probe PATH) so all tools and listeners are registered before the
 * extension finishes initializing. Returns the root `Context`; disposing it
 * unwinds every subsystem.
 */
export async function composeApp(pi: ExtensionAPI, subsystems: readonly ReSubsystem[]): Promise<Context> {
	const app = new Context();
	app.provide("pi", pi);
	for (const sub of subsystems) {
		await app.plugin({
			name: sub.name,
			inject: ["pi"],
			apply: (ctx: Context) => sub.apply(ctx.get("pi") as ExtensionAPI),
		});
	}
	return app;
}
