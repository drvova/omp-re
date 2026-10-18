/**
 * The process-lifecycle backbone (runtime.ts, via the state.ts facade): the
 * per-session record is stable and synchronous, and each rizin/debug process's
 * teardown is owned by an effect on the session scope — so a respawn closes
 * the old process and disposing the session closes every process it owns.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import {
  ensureRizin,
  getState,
  rekeyState,
  shutdownState,
  spawnRizin,
  startDebug,
} from "../extensions/re/state.ts";
import { canRunRizin, logSkip, makeHarness, TEST_BINARY } from "./helpers.ts";

logSkip("runtime (process-lifecycle) tests");

describe("session record (no rizin needed)", () => {
  test("getState returns one stable, mutable record per session id", () => {
    const h = makeHarness("runtime-stable");
    const a = getState(h.ctx);
    a.binaryPath = "/tmp/x";
    a.evidenceCount = 3;
    const b = getState(h.ctx);
    expect(b).toBe(a);
    expect(b.binaryPath).toBe("/tmp/x");
    expect(b.evidenceCount).toBe(3);
    shutdownState("runtime-stable");
  });

  test("shutdown drops the record; the next getState is fresh", () => {
    const h = makeHarness("runtime-drop");
    getState(h.ctx).binaryPath = "/tmp/y";
    shutdownState("runtime-drop");
    expect(getState(h.ctx).binaryPath).toBeNull();
    shutdownState("runtime-drop");
  });

  test("rekey carries the record to a new session id", () => {
    const from = makeHarness("runtime-from");
    const rec = getState(from.ctx);
    rec.binaryPath = "/tmp/z";
    rekeyState("runtime-from", "runtime-to");
    const to = makeHarness("runtime-to");
    expect(getState(to.ctx)).toBe(rec);
    expect(getState(to.ctx).sessionId).toBe("runtime-to");
    shutdownState("runtime-to");
  });
});

describe.skipIf(!canRunRizin)(
  "process lifecycle is owned by the session scope",
  () => {
    const h = makeHarness("runtime-lifecycle");
    beforeAll(() => {
      getState(h.ctx).binaryPath = TEST_BINARY;
    });
    afterAll(() => shutdownState("runtime-lifecycle"));

    test("a respawn tears down the previous process via its effect", async () => {
      const first = await ensureRizin(h.ctx);
      expect(first.isClosed).toBe(false);
      // a fresh spawn of the same binary replaces the process; the old one's effect inverse closes it
      const { rz: second } = await spawnRizin(h.ctx, TEST_BINARY);
      expect(second).not.toBe(first);
      expect(first.isClosed).toBe(true);
      expect(second.isClosed).toBe(false);
      expect(getState(h.ctx).rz).toBe(second);
    }, 25_000);

    test("disposing the session scope closes every process it owns (static + debug)", async () => {
      const h2 = makeHarness("runtime-dispose");
      getState(h2.ctx).binaryPath = TEST_BINARY;
      const rz = await ensureRizin(h2.ctx);
      const dbg = await startDebug(h2.ctx);
      expect(rz.isClosed).toBe(false);
      expect(dbg.isClosed).toBe(false);
      // sanity: the debug process really launched (has a PC)
      const drOutput = await dbg.cmd("dr rip");
      expect(drOutput.trim()).toMatch(/rip = 0x[0-9a-f]+/u);
      shutdownState("runtime-dispose");
      expect(rz.isClosed).toBe(true);
      expect(dbg.isClosed).toBe(true);
    }, 25_000);
  }
);
