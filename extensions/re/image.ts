/**
 * How the engine process is started.
 *
 * The engine is Common Lisp, and SBCL can save a loaded engine as one
 * executable — an image — that is serving a few milliseconds after it is
 * started, where loading the compiled source takes a quarter of a second and
 * compiling it a few seconds. So omp's side runs an image when it can. There
 * is one rule, `launcher`, tried in this order:
 *
 *   1. the image `OMPRE_ENGINE_IMAGE` names, as it is;
 *   2. an image shipped with the plugin for this system, `dist/omp-re-engine-<platform>-<arch>[.exe]`;
 *   3. an image built here, once, from the plugin's source with the user's SBCL, and kept in the user's cache;
 *   4. the source itself, loaded by `stdio/serve.lisp`.
 *
 * A step that does not come to say `ready` hands on to the next, and the log
 * says why; only the first, which the operator asked for by name, is final.
 * Nothing is fetched from the network. docs/install.md is the operator's side
 * of this.
 */
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, utimesSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The plugin, as installed: this file's `extensions/re` is two folders into it. */
export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const IMAGE_PREFIX = "omp-re-engine-";
const EXE = process.platform === "win32" ? ".exe" : "";
/** A build is given most of the two minutes a start is (engine.ts, `startMs`), so that a build that hangs is this step's failure and not the start's. */
const BUILD_MS = 100_000;
/** How many built images the cache keeps: the one in use, and a couple of other versions or checkouts of the plugin. */
const KEPT_IMAGES = 3;

/** The SBCL the engine is loaded and built with: OMPRE_SBCL_PATH, or `sbcl` on the PATH. */
export const sbclProgram = (): string => process.env.OMPRE_SBCL_PATH?.trim() || "sbcl";

/** The command that loads the engine from source and serves. */
export function sourceCommand(root = ROOT): string[] {
	return [sbclProgram(), "--noinform", "--no-sysinit", "--no-userinit", "--disable-debugger", "--load", join(root, "stdio", "serve.lisp")];
}

/** The name of an engine image for this system, as the plugin ships one and as a release names its assets. */
export const imageName = (): string => `${IMAGE_PREFIX}${process.platform}-${process.arch}${EXE}`;

/** Where an image shipped with the plugin is. */
export const shippedImage = (root = ROOT): string => join(root, "dist", imageName());

/** The directory built images are kept in: OMPRE_CACHE_DIR, or omp-re's folder in the user's cache directory as the system has one. */
export function cacheDir(): string {
	const named = process.env.OMPRE_CACHE_DIR?.trim();
	if (named) return named;
	if (process.platform === "win32") return join(process.env.LOCALAPPDATA?.trim() || join(homedir(), "AppData", "Local"), "omp-re", "cache");
	const xdg = process.env.XDG_CACHE_HOME?.trim();
	if (xdg) return join(xdg, "omp-re");
	return process.platform === "darwin" ? join(homedir(), "Library", "Caches", "omp-re") : join(homedir(), ".cache", "omp-re");
}

/** The files an image is made of: every Lisp file of the engine and of the omp host, the wire's description, the two system definitions, and the recipe that saves it. */
function imageSources(root: string): string[] {
	const lisp = (folder: string) =>
		readdirSync(join(root, folder))
			.filter((name) => name.endsWith(".lisp"))
			.map((name) => `${folder}/${name}`);
	return [...lisp("engine"), ...lisp("stdio"), "stdio/protocol.json", "omp-re.asd", "omp-re-stdio.asd", "scripts/build-image.lisp"].sort();
}

/**
 * What an image is built from, as one hash: the name and the text of each of its sources. An image carries the
 * identity it was built with and refuses to serve under another, so an image left over from another version of the
 * plugin is never taken for this one's. Line ends are read as line feeds: a checkout that turned them into CRLF is
 * the same source.
 */
export function sourcesIdentity(root = ROOT): string {
	const hash = createHash("sha256");
	for (const file of imageSources(root)) hash.update(`${file}\0${readFileSync(join(root, file), "utf8").replaceAll("\r\n", "\n")}\0`);
	return hash.digest("hex");
}

function run(program: string, args: string[], timeout: number): Promise<string> {
	return new Promise((resolve, reject) => {
		// No shell: the arguments reach SBCL as they are on every platform.
		execFile(program, args, { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) => {
			if (!error) resolve(stdout);
			else reject(new Error(stderr.trim().split("\n").slice(-3).join(" ").trim() || error.message));
		});
	});
}

/**
 * Where the image built here from the sources `identity` is kept. Its name carries everything that makes another
 * image necessary: the plugin's version, the system, and a hash of the sources and of the SBCL that builds it
 * (`sbcl --version`), since an image holds that SBCL's runtime.
 */
export function builtImage(identity: string, sbcl: string, root = ROOT): string {
	const version = String((JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version?: unknown }).version ?? "0");
	const key = createHash("sha256").update(`${identity}\n${sbcl.trim()}\n${version}\n${process.platform}\n${process.arch}\n`).digest("hex").slice(0, 16);
	return join(cacheDir(), `${IMAGE_PREFIX}${version}-${process.platform}-${process.arch}-${key}${EXE}`);
}

/** Forget the images of other sources, oldest use first, and what a build that died left behind. */
function prune(directory: string, keep: string): void {
	const used = (name: string) => {
		try {
			return statSync(join(directory, name)).mtimeMs;
		} catch {
			return 0;
		}
	};
	const names = readdirSync(directory).filter((name) => name.startsWith(IMAGE_PREFIX));
	const stale = names.filter((name) => name.endsWith(".partial") && Date.now() - used(name) > 2 * BUILD_MS);
	const images = names.filter((name) => !name.endsWith(".partial") && join(directory, name) !== keep).sort((a, b) => used(b) - used(a));
	for (const name of [...stale, ...images.slice(KEPT_IMAGES - 1)]) rmSync(join(directory, name), { force: true });
}

/**
 * Build an image of the engine at `output`, from the plugin's source at `root`, with the user's SBCL. This is the
 * one way an image is made: omp's side calls it on a first start, and `scripts/build-image.ts` for a developer and
 * for a release. The image is written under another name and renamed when it is whole, so nobody runs half of one,
 * and two builds of one output at once leave one good file.
 */
export async function buildImage(output: string, identity = sourcesIdentity(), root = ROOT): Promise<void> {
	mkdirSync(dirname(output), { recursive: true });
	const partial = `${output}.${process.pid}-${randomBytes(4).toString("hex")}.partial`;
	try {
		await run(sbclProgram(), ["--script", join(root, "scripts", "build-image.lisp"), partial, identity], BUILD_MS);
		try {
			renameSync(partial, output);
		} catch (error) {
			// Windows will not replace an image that is running. Whoever runs it built the same one.
			if (!existsSync(output)) throw error;
		}
	} finally {
		rmSync(partial, { force: true });
	}
}

/**
 * The image of the source at `root` in the cache: where it is, built now when it was not there. `fresh`, for an
 * image that is there, is whether this call built it. Rejects when the build fails.
 */
async function cachedImage(image: string, identity: string, root: string): Promise<{ fresh: boolean }> {
	if (existsSync(image)) {
		// Its time of last use, for `prune`.
		try {
			utimesSync(image, new Date(), new Date());
		} catch {
			// Not ours to touch; it is still ours to run.
		}
		return { fresh: false };
	}
	await buildImage(image, identity, root);
	prune(dirname(image), image);
	return { fresh: true };
}

/** The user's SBCL as it names itself, or undefined when there is none to ask. */
const sbclVersion = (): Promise<string | undefined> => run(sbclProgram(), ["--version"], 10_000).catch(() => undefined);

/** The image a start would run from the cache, built now if it is not there => its path. Rejects where there is no SBCL or the build fails. */
export async function ensureImage(root = ROOT): Promise<string> {
	const version = await sbclVersion();
	if (version === undefined) throw new Error(`omp-re: SBCL was not found (tried ${JSON.stringify(sbclProgram())})`);
	const identity = sourcesIdentity(root);
	const image = builtImage(identity, version, root);
	await cachedImage(image, identity, root);
	return image;
}

const why = (failure: Error): string => (failure.cause instanceof Error ? failure.cause.message : failure.message).replace(/^omp-re: /, "");

/**
 * The ways to start the engine, one at a time: each `yield` is a command to try, and what comes back is why it did
 * not come to say `ready`. Throwing ends the start with that error.
 */
async function* starts(say: (line: string) => void, root: string): AsyncGenerator<readonly string[], never, Error> {
	const named = process.env.OMPRE_ENGINE_IMAGE?.trim();
	if (named) {
		const failure: Error = existsSync(named) ? yield [named] : new Error("there is no such file");
		throw new Error(
			`omp-re: OMPRE_ENGINE_IMAGE names ${JSON.stringify(named)}, which did not start as an engine image: ${why(failure)}. Point it at an image built for this system and this version of omp-re, or unset it and omp-re builds its own (docs/install.md).`,
		);
	}
	const identity = sourcesIdentity(root);
	const shipped = shippedImage(root);
	if (existsSync(shipped)) {
		const failure = yield [shipped, "--identity", identity];
		say(`the engine image shipped at ${shipped} did not start (${why(failure)}); going on without it`);
	}
	// With no SBCL there is nothing to build with, and the start from source is what says so.
	const version = await sbclVersion();
	if (version !== undefined) {
		const image = builtImage(identity, version, root);
		for (;;) {
			let fresh: boolean;
			try {
				({ fresh } = await cachedImage(image, identity, root));
			} catch (error) {
				say(`no engine image could be built at ${image} (${why(error as Error)}); loading the engine from source`);
				break;
			}
			const failure = yield [image, "--identity", identity];
			rmSync(image, { force: true });
			if (fresh) {
				say(`the engine image just built at ${image} did not start (${why(failure)}); loading the engine from source`);
				break;
			}
			say(`the engine image at ${image} did not start (${why(failure)}); building it again`);
		}
	}
	throw yield sourceCommand(root);
}

/** What `Engine` starts from: called for the first command to try, and again with why the last did not start. */
export function launcher(say: (line: string) => void, root = ROOT): (failed?: Error) => Promise<readonly string[]> {
	const steps = starts(say, root);
	return async (failed) => (await steps.next(failed as Error)).value;
}
