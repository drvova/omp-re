/**
 * Loaded once before the bun suites (bunfig.toml). The first engine a suite
 * starts would otherwise compile the engine and save its image inside some
 * test's own time limit; here that is done before any test, so every suite
 * starts the one image. Without SBCL nothing is built, and the suites that
 * need the engine say so themselves.
 */
import { ensureImage } from "../extensions/re/image.ts";

await ensureImage().catch(() => {});
