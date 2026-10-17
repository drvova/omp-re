/**
 * The composition root (app.ts): subsystems are applied in order with the host
 * `pi` handed to each, async subsystems (the PATH-probing tool groups) finish
 * before composition resolves, and each call is independent. No rizin needed.
 */
import { describe, expect, test } from "bun:test";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { composeApp, type ReSubsystem } from "../extensions/re/app.ts";

const fakePi = { tag: "the-host" } as unknown as ExtensionAPI;

describe("composeApp", () => {
	test("applies every subsystem once, in order, with the host passed to each", async () => {
		const seen: string[] = [];
		const subs: ReSubsystem[] = [
			{ name: "a", apply: (pi) => void seen.push(`a:${(pi as unknown as { tag: string }).tag}`) },
			{ name: "b", apply: (pi) => void seen.push(`b:${(pi as unknown as { tag: string }).tag}`) },
		];
		await composeApp(fakePi, subs);
		expect(seen).toEqual(["a:the-host", "b:the-host"]);
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

	test("each call passes its own host — two compositions don't bleed into each other", async () => {
		const piOne = { tag: "one" } as unknown as ExtensionAPI;
		const piTwo = { tag: "two" } as unknown as ExtensionAPI;
		const seenOne: string[] = [];
		const seenTwo: string[] = [];
		await composeApp(piOne, [{ name: "x", apply: (pi) => void seenOne.push((pi as unknown as { tag: string }).tag) }]);
		await composeApp(piTwo, [{ name: "x", apply: (pi) => void seenTwo.push((pi as unknown as { tag: string }).tag) }]);
		expect(seenOne).toEqual(["one"]);
		expect(seenTwo).toEqual(["two"]);
	});
});
