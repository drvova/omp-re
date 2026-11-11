/**
 * What is written in more than one file and must agree: the release version
 * (scripts/release.mjs writes and checks it), and what scripts/gen-protocol.ts
 * and scripts/gen-recipes.ts generate from their data. CI runs the same
 * checks as steps of their own; here they also hold for a plain `bun test`.
 */
import { expect, test } from "bun:test";
import { join } from "node:path";
import { ROOT } from "./helpers.ts";

const run = (...args: string[]) => {
	const done = Bun.spawnSync([process.execPath, ...args], { cwd: ROOT, stdout: "pipe", stderr: "pipe" });
	return { exitCode: done.exitCode, stdout: done.stdout.toString(), stderr: done.stderr.toString() };
};

test("package.json, the marketplace entry and the three .asd files carry one version", () => {
	const check = run(join("scripts", "release.mjs"), "--check-versions");
	expect(check.stderr).toBe("");
	expect(check.exitCode).toBe(0);
	const versions = check.stdout
		.trim()
		.split("\n")
		.map((line) => line.trim().split(/\s+/));
	expect(versions.map(([, file]) => file)).toEqual(["package.json", ".omp-plugin/marketplace.json", "omp-re.asd", "omp-re-stdio.asd", "nodecode-re.asd"]);
	expect(new Set(versions.map(([version]) => version)).size).toBe(1);
});

test("extensions/re/protocol.ts and the tables of docs/engine-protocol.md are current with stdio/protocol.json", () => {
	const check = run(join("scripts", "gen-protocol.ts"), "--check");
	expect(check.stderr).toBe("");
	expect(check.exitCode).toBe(0);
});
