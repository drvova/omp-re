#!/usr/bin/env bun
/**
 * Builds an image of the engine: one executable that is the engine loaded and
 * ready to serve omp (docs/install.md, "The engine image"). The build itself
 * is `buildImage` of extensions/re/image.ts, the same one omp's side runs on
 * a first start; this is its command line, for a developer and for the
 * release workflow. It needs SBCL and cl-ppcre, and the image is for the
 * system it is built on.
 *
 *   bun scripts/build-image.ts            # into the cache, where a start looks for it
 *   bun scripts/build-image.ts --dist     # dist/omp-re-engine-<platform>-<arch>[.exe], as the plugin ships one
 *   bun scripts/build-image.ts <path>     # there
 *
 * Prints where the image is and its size. Exits 1, with the reason, when it
 * could not be built.
 */
import { statSync } from "node:fs";
import { resolve } from "node:path";
import { buildImage, ensureImage, shippedImage } from "../extensions/re/image.ts";

const [where, ...more] = process.argv.slice(2);
if (more.length > 0 || (where?.startsWith("--") && where !== "--dist")) {
	console.error("usage: bun scripts/build-image.ts [--dist | <path>]");
	process.exit(2);
}

try {
	let image: string;
	if (where === undefined) image = await ensureImage();
	else {
		image = where === "--dist" ? shippedImage() : resolve(where);
		await buildImage(image);
	}
	console.log(`${image}  ${(statSync(image).size / (1024 * 1024)).toFixed(1)} MB`);
} catch (error) {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
}
