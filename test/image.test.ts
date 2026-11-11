/**
 * How the engine process is started (extensions/re/image.ts): the image
 * `OMPRE_ENGINE_IMAGE` names, one shipped with the plugin, one built here and
 * kept in the cache, and the source. Each test starts real engines with a real
 * SBCL, in a cache directory of its own, and reads what happened from the
 * engine itself — `hello` says whether it is an image — and from the files.
 *
 * The image every other suite runs is built once before the suites
 * (test/setup.ts) and copied where a test needs a whole one, so only the tests
 * about building build.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { Engine, type HostHandlers } from "../extensions/re/engine.ts";
import { buildImage, cacheDir, ensureImage, imageName, launcher, shippedImage, sourcesIdentity } from "../extensions/re/image.ts";
import { rmDirSafe, ROOT } from "./helpers.ts";

const sbcl = Bun.which(process.env.OMPRE_SBCL_PATH?.trim() || "sbcl") !== null;
const BUILDS_MS = 120_000;
/** No image of the engine is this small: SBCL's own core is larger. */
const WHOLE_BYTES = 20 * 1024 * 1024;

let scratch = "";
/** The whole image the suites share. */
let whole = "";
const touched = ["OMPRE_CACHE_DIR", "OMPRE_ENGINE_IMAGE", "OMPRE_SBCL_PATH", "ASDF_OUTPUT_TRANSLATIONS"] as const;
const before = new Map<string, string | undefined>();

beforeAll(async () => {
	if (sbcl) whole = await ensureImage();
}, BUILDS_MS);

beforeEach(() => {
	for (const name of touched) before.set(name, process.env[name]);
	scratch = mkdtempSync(join(tmpdir(), "omp-re-image-"));
	process.env.OMPRE_CACHE_DIR = join(scratch, "cache");
});

afterEach(() => {
	for (const name of touched) {
		const value = before.get(name);
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
	rmDirSafe(scratch);
});

interface Started {
	/** What `hello` said the engine is. */
	as: "source" | "image" | undefined;
	/** The program the engine process is, where the system says (Linux). */
	program: string | undefined;
	/** What the start wrote to omp's log. */
	logged: string[];
	failure: string | undefined;
}

/** Start an engine the way omp's side does, from the plugin at `root`, ask it something, and end it. */
async function start(root = ROOT): Promise<Started> {
	const logged: string[] = [];
	const engine = new Engine({ command: launcher((line) => void logged.push(line), root), handlers: {} as HostHandlers, log: (line) => void logged.push(line) });
	const failure = await engine.request("describe", {}).then(
		() => undefined,
		(error: Error) => error.message,
	);
	let program: string | undefined;
	try {
		if (engine.pid !== undefined) program = readlinkSync(`/proc/${engine.pid}/exe`);
	} catch {
		// No /proc here.
	}
	const as = engine.startedAs;
	await engine.stop();
	return { as, program, logged, failure };
}

const cached = () => (existsSync(cacheDir()) ? readdirSync(cacheDir()).sort() : []);
const isProgram = (started: Started, image: string) => started.program === undefined || started.program === realpathSync(image);

/** A copy of what an image is built from, so a test can change a source. Its compiled files are kept out of the user's cache. */
function pluginCopy(): string {
	const root = join(scratch, "plugin");
	for (const part of ["engine", "stdio", "omp-re.asd", "omp-re-stdio.asd", "package.json", join("scripts", "build-image.lisp")]) cpSync(join(ROOT, part), join(root, part), { recursive: true });
	process.env.ASDF_OUTPUT_TRANSLATIONS = `(:output-translations (${JSON.stringify(`${root}/`)} ${JSON.stringify(`${join(scratch, "compiled")}/`)}) :inherit-configuration)`;
	return root;
}

const edit = (root: string, file: string, change: (text: string) => string) => writeFileSync(join(root, file), change(readFileSync(join(root, file), "utf8")));

describe.skipIf(!sbcl)("the engine image", () => {
	test(
		"a first start builds an image in the cache and is that image; the next start runs the same file and builds nothing",
		async () => {
			// What other sources left in the cache, oldest first, and what a build that died left.
			mkdirSync(cacheDir(), { recursive: true });
			for (const [index, name] of ["omp-re-engine-0.0.1-old", "omp-re-engine-0.0.2-old", "omp-re-engine-0.0.3-old", "omp-re-engine-0.0.4-old.1-dead.partial"].entries()) {
				writeFileSync(join(cacheDir(), name), "left over");
				utimesSync(join(cacheDir(), name), new Date(2020, 0, 1 + index), new Date(2020, 0, 1 + index));
			}

			const first = await start();
			expect(first.failure).toBeUndefined();
			expect(first.as).toBe("image");
			expect(first.logged).toEqual([]);
			const images = cached().filter((name) => !name.endsWith("-old"));
			expect(images).toHaveLength(1);
			expect(images[0]).toMatch(new RegExp(`^omp-re-engine-\\d+\\.\\d+\\.\\d+-${process.platform}-${process.arch}-[0-9a-f]{16}(\\.exe)?$`));
			const image = join(cacheDir(), images[0]!);
			expect(isProgram(first, image)).toBe(true);
			// The two other images used last are kept beside it; older ones and the dead build's file are gone.
			expect(cached().filter((name) => name.endsWith("-old") || name.endsWith(".partial"))).toEqual(["omp-re-engine-0.0.2-old", "omp-re-engine-0.0.3-old"]);

			const built = statSync(image);
			const second = await start();
			expect(second.as).toBe("image");
			expect(isProgram(second, image)).toBe(true);
			expect(second.logged).toEqual([]);
			// A build writes another file and renames it: the same inode is the same build.
			expect(statSync(image).ino).toBe(built.ino);
			expect(statSync(image).size).toBe(built.size);
			expect(cached().filter((name) => !name.endsWith("-old"))).toEqual(images);
		},
		BUILDS_MS,
	);

	test(
		"an image shipped with the plugin is run while it is this source's; a changed source passes it over and builds, and each change builds once",
		async () => {
			const root = pluginCopy();
			mkdirSync(dirname(shippedImage(root)), { recursive: true });
			cpSync(whole, shippedImage(root));
			expect(shippedImage(root)).toBe(join(root, "dist", imageName()));

			// The copy is the same source as this checkout, whose image `whole` is.
			expect(sourcesIdentity(root)).toBe(sourcesIdentity());
			const shipped = await start(root);
			expect(shipped.as).toBe("image");
			expect(isProgram(shipped, shippedImage(root))).toBe(true);
			expect(shipped.logged).toEqual([]);
			expect(cached()).toEqual([]);

			// What is not the engine's source is not its identity; a line end is not a change; a Lisp file's text is.
			const unchanged = sourcesIdentity(root);
			writeFileSync(join(root, "README.md"), "not a source");
			edit(root, "stdio/voice.lisp", (text) => text.replaceAll("\n", "\r\n"));
			expect(sourcesIdentity(root)).toBe(unchanged);
			edit(root, "stdio/voice.lisp", (text) => `${text.replaceAll("\r\n", "\n")}\n;; a change\n`);
			expect(sourcesIdentity(root)).not.toBe(unchanged);

			const changed = await start(root);
			expect(changed.failure).toBeUndefined();
			expect(changed.as).toBe("image");
			expect(changed.logged.join("\n")).toContain(`the engine image shipped at ${shippedImage(root)} did not start`);
			expect(changed.logged.join("\n")).toContain(`this engine image was built from ${unchanged}, not from ${sourcesIdentity(root)}`);
			const afterOne = cached();
			expect(afterOne).toHaveLength(1);
			expect(isProgram(changed, join(cacheDir(), afterOne[0]!))).toBe(true);

			// The same source again: the image just built, and no other.
			const again = await start(root);
			expect(again.as).toBe("image");
			expect(cached()).toEqual(afterOne);

			edit(root, "stdio/voice.lisp", (text) => `${text};; another\n`);
			const changedAgain = await start(root);
			expect(changedAgain.as).toBe("image");
			expect(cached()).toHaveLength(2);
			const newest = cached().find((name) => !afterOne.includes(name))!;
			expect(isProgram(changedAgain, join(cacheDir(), newest))).toBe(true);
		},
		BUILDS_MS,
	);

	test(
		"an image in the cache that will not run is built again, and the log says why",
		async () => {
			const image = join(cacheDir(), basename(whole));
			mkdirSync(cacheDir(), { recursive: true });
			cpSync(whole, image);

			// Cut short, as a full disk or a killed copy leaves it.
			writeFileSync(image, readFileSync(image).subarray(0, 1024 * 1024));
			const cut = await start();
			expect(cut.failure).toBeUndefined();
			expect(cut.as).toBe("image");
			expect(cut.logged.join("\n")).toContain(`the engine image at ${image} did not start (`);
			expect(cut.logged.join("\n")).toContain("building it again");
			expect(statSync(image).size).toBeGreaterThan(WHOLE_BYTES);
			expect(isProgram(cut, image)).toBe(true);

			// Not a program at all.
			writeFileSync(image, "not an image");
			chmodSync(image, 0o755);
			const garbage = await start();
			expect(garbage.as).toBe("image");
			expect(garbage.logged.join("\n")).toContain("building it again");
			expect(statSync(image).size).toBeGreaterThan(WHOLE_BYTES);
			expect(cached()).toEqual([basename(image)]);
		},
		BUILDS_MS,
	);

	test(
		"OMPRE_ENGINE_IMAGE is run as it is: with no SBCL, whatever it was built from, and nothing is built",
		async () => {
			const named = join(scratch, "an image by another name");
			await buildImage(named, "some other source");
			process.env.OMPRE_ENGINE_IMAGE = named;
			process.env.OMPRE_SBCL_PATH = join(scratch, "no-such-sbcl");
			const started = await start();
			expect(started.failure).toBeUndefined();
			expect(started.as).toBe("image");
			expect(isProgram(started, named)).toBe(true);
			expect(started.logged).toEqual([]);
			expect(cached()).toEqual([]);
		},
		BUILDS_MS,
	);

	test("OMPRE_ENGINE_IMAGE naming what is no image is the start's error, naming the variable; nothing else is tried", async () => {
		const named = join(scratch, "not-an-image");
		process.env.OMPRE_ENGINE_IMAGE = named;
		const missing = await start();
		expect(missing.failure).toContain(`omp-re: OMPRE_ENGINE_IMAGE names ${JSON.stringify(named)}, which did not start as an engine image: there is no such file.`);
		expect(missing.failure).toContain("unset it and omp-re builds its own");

		writeFileSync(named, "#!/bin/sh\necho 'not lisp' >&2\nexit 5\n");
		chmodSync(named, 0o755);
		const wrong = await start();
		expect(wrong.failure).toContain(`omp-re: OMPRE_ENGINE_IMAGE names ${JSON.stringify(named)}, which did not start as an engine image: `);
		expect(wrong.as).toBeUndefined();
		expect(cached()).toEqual([]);
	});

	test(
		"where no image can be built the engine is loaded from source, and the log says why",
		async () => {
			// A cache directory that cannot be made: its parent is a file.
			writeFileSync(join(scratch, "a-file"), "");
			process.env.OMPRE_CACHE_DIR = join(scratch, "a-file", "cache");
			const started = await start();
			expect(started.failure).toBeUndefined();
			expect(started.as).toBe("source");
			expect(started.logged).toHaveLength(1);
			expect(started.logged[0]).toStartWith(`no engine image could be built at ${join(scratch, "a-file", "cache", "omp-re-engine-")}`);
			expect(started.logged[0]).toEndWith("; loading the engine from source");
		},
		BUILDS_MS,
	);

	test(
		"two builds of one image at once leave one whole image and nothing else",
		async () => {
			const image = join(cacheDir(), "built-twice");
			await Promise.all([buildImage(image), buildImage(image)]);
			expect(cached()).toEqual(["built-twice"]);
			expect(statSync(image).size).toBeGreaterThan(WHOLE_BYTES);
			process.env.OMPRE_ENGINE_IMAGE = image;
			expect((await start()).as).toBe("image");
		},
		BUILDS_MS,
	);
});
