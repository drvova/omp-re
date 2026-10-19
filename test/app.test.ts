/**
 * The composition root (app.ts): subsystems are applied in order with the host
 * `pi` handed to each, async subsystems (the PATH-probing tool groups) finish
 * before composition resolves, and each call is independent. No rizin needed.
 */
import { describe, expect, test } from "bun:test";
import { setTimeout as sleep } from "node:timers/promises";

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

import { composeApp } from "../extensions/re/app.ts";
import type { ReSubsystem } from "../extensions/re/app.ts";

const fakePi = { tag: "the-host" } as unknown as ExtensionAPI;

describe("composeApp", () => {
  test("applies every subsystem once, in order, with the host passed to each", async () => {
    const seen: string[] = [];
    const subs: ReSubsystem[] = [
      {
        apply: (pi) => {
          seen.push(`a:${(pi as unknown as { tag: string }).tag}`);
        },
        name: "a",
      },
      {
        apply: (pi) => {
          seen.push(`b:${(pi as unknown as { tag: string }).tag}`);
        },
        name: "b",
      },
    ];
    await composeApp(fakePi, subs);
    expect(seen).toEqual(["a:the-host", "b:the-host"]);
  });

  test("an async subsystem finishes applying before composeApp resolves", async () => {
    let done = false;
    const subs: ReSubsystem[] = [
      {
        apply: async () => {
          await sleep(20);
          done = true;
        },
        name: "slow",
      },
    ];
    await composeApp(fakePi, subs);
    // composeApp awaited the async apply
    expect(done).toBe(true);
  });

  test("each call passes its own host — two compositions don't bleed into each other", async () => {
    const piOne = { tag: "one" } as unknown as ExtensionAPI;
    const piTwo = { tag: "two" } as unknown as ExtensionAPI;
    const seenOne: string[] = [];
    const seenTwo: string[] = [];
    await composeApp(piOne, [
      {
        apply: (pi) => {
          seenOne.push((pi as unknown as { tag: string }).tag);
        },
        name: "x",
      },
    ]);
    await composeApp(piTwo, [
      {
        apply: (pi) => {
          seenTwo.push((pi as unknown as { tag: string }).tag);
        },
        name: "x",
      },
    ]);
    expect(seenOne).toEqual(["one"]);
    expect(seenTwo).toEqual(["two"]);
  });
});
