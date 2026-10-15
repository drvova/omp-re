/**
 * The cordis composition root (app.ts): subsystems load as plugins that
 * inject the host `pi` service, their order is preserved, async subsystems
 * (the PATH-probing tool groups) finish before composition resolves, and the
 * returned context disposes cleanly. No rizin needed.
 */
import { describe, expect, test } from "bun:test";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { composeApp, type ReSubsystem } from "../extensions/re/app.ts";

const fakePi = { tag: "the-host" } as unknown as ExtensionAPI;

describe("composeApp", () => {
	test("loads every subsystem once, in order, with the host injected", async () => {
		const seen: string[] = [];
		const subs: ReSubsystem[] = [
			{ name: "a", apply: (pi) => void seen.push(`a:${(pi as unknown as { tag: string }).tag}`) },
			{ name: "b", apply: (pi) => void seen.push(`b:${(pi as unknown as { tag: string }).tag}`) },
		];
		const app = await composeApp(fakePi, subs);
		expect(seen).toEqual(["a:the-host", "b:the-host"]);
		expect(app.get("pi")).toBe(fakePi);
		await app.fiber.dispose();
	});

	test("an async subsystem finishes applying before composeApp resolves", async () => {
		let done = false;
		const subs: ReSubsystem[] = [
			{
				name: "slow",
				apply: async () => {
					await new Promise((r) => setTimeout(r, 20));
					done = true;
				},
			},
		];
		await composeApp(fakePi, subs);
		expect(done).toBe(true); // composeApp awaited the async apply
	});

	test("each load gets its own context — two apps don't share the host service", async () => {
		const piOne = { tag: "one" } as unknown as ExtensionAPI;
		const piTwo = { tag: "two" } as unknown as ExtensionAPI;
		const one = await composeApp(piOne, []);
		const two = await composeApp(piTwo, []);
		expect(one.get("pi")).toBe(piOne);
		expect(two.get("pi")).toBe(piTwo);
		await one.fiber.dispose();
		await two.fiber.dispose();
	});
});
