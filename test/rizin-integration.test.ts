import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  checkRizinCommand,
  isKnownCommand,
  loadCatalog,
  NOARG_DUALS,
  READ_ONLY_EXTRAS,
} from "../extensions/re/catalog.ts";
import type { RzCatalog } from "../extensions/re/catalog.ts";
import { resolveDecompiler } from "../extensions/re/decompile.ts";
import {
  RzAbortError,
  RzProtocolError,
  RzSession,
  resolveBinaryPath,
} from "../extensions/re/rizin.ts";
import {
  ensureRizin,
  getState,
  shutdownState,
  spawnRizin,
  syncAnnotationsToBranch,
} from "../extensions/re/state.ts";
import { scopedSearch, searchCommand } from "../extensions/re/tools-search.ts";
import { defineTypeLines } from "../extensions/re/tools-types.ts";
import {
  canRunRizin,
  logSkip,
  makeHarness,
  rizinPath,
  rmDirSafe,
  TEST_BINARY,
} from "./helpers.ts";

/** The hit total from a search result's header ("N hits" / "N of M hits" — M is the total). */
function hitTotal(result: {
  content: { type: string; text?: string }[];
}): number {
  const text =
    result.content[0]?.type === "text" ? (result.content[0].text ?? "") : "";
  const m = [...text.matchAll(/(\d+) hits/gu)].at(-1);
  return m ? Number(m[1]) : -1;
}

/** A flat x86-32 blob with no header: `mov eax,1; add eax,2; ret`. */
const FLAT_X86_32 = Buffer.from([
  0xb8, 0x01, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x02, 0xc3,
]);

logSkip("rizin-integration tests");

describe.skipIf(!canRunRizin)("RzSession (rizin integration)", () => {
  let session: RzSession;

  beforeAll(async () => {
    session = await RzSession.spawn(rizinPath, TEST_BINARY);
  });

  afterAll(() => {
    session.close();
  });

  test("spawn + ij returns parseable JSON describing the binary", async () => {
    const parsed = JSON.parse((await session.cmd("ij")).trim()) as {
      core?: { format?: string; file?: string };
      bin?: { arch?: string };
    };
    expect(typeof parsed.bin?.arch).toBe("string");
    expect(String(parsed.core?.format)).toMatch(/elf|pe|mach0/iu);
  });

  test("50 sequential commands in one session all return their own output", async () => {
    for (let i = 0; i < 50; i += 1) {
      const marker = `omp-re-seq-${i}`;
      expect((await session.cmd(`echo ${marker}`)).trim()).toBe(marker);
    }
  });

  test("an invalid address returns empty output and keeps the stream aligned", async () => {
    expect((await session.cmd("afij @ no_such_symbol_anywhere")).trim()).toBe(
      ""
    );
    expect(await session.cmdj("afij @ no_such_symbol_anywhere")).toBeNull();
    expect((await session.cmd("echo still-aligned")).trim()).toBe(
      "still-aligned"
    );
  });

  test("a quoted comment containing a command separator is stored literally and runs nothing", async () => {
    await session.cmd("CC- @ entry0");
    const echoed = await session.cmd("CC 'x; echo INJECTED' @ entry0");
    expect(echoed).not.toContain("INJECTED");
    expect((await session.cmd("CC. @ entry0")).trim()).toBe("x; echo INJECTED");
    await session.cmd("CC- @ entry0");
  });

  test("aborting a command rejects the caller but leaves the process usable and aligned", async () => {
    const controller = new AbortController();
    const pending = session.cmd("aflj", { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(RzAbortError);
    expect(session.isClosed).toBe(false);
    expect((await session.cmd("echo after-abort")).trim()).toBe("after-abort");
  });

  test("a tiny-timeout command rejects with RzProtocolError and closes the session", async () => {
    const slow = await RzSession.spawn(rizinPath, TEST_BINARY);
    let caught: unknown;
    try {
      await slow.cmd("!sleep 2", { timeoutMs: 200 });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(RzProtocolError);
    expect((caught as Error).message).toMatch(/timed out/u);
    expect(slow.isClosed).toBe(true);
  });

  test("aborting during analysis kills the half-analyzed process", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      RzSession.spawn(rizinPath, TEST_BINARY, { signal: controller.signal })
    ).rejects.toBeInstanceOf(RzAbortError);
  });

  test("spawn reports analysis progress through onProgress while aaa runs", async () => {
    const ticks: number[] = [];
    const s = await RzSession.spawn(rizinPath, TEST_BINARY, {
      onProgress: (ms) => ticks.push(ms),
    });
    s.close();
    // Analysis of a small binary can finish inside the first tick; progress is best-effort, never required.
    for (const ms of ticks) {
      expect(ms).toBeGreaterThan(0);
    }
  });

  test("the decompiler probe settles on pdg, pdd, or none, and caches its answer", async () => {
    const first = await resolveDecompiler(session);
    expect([null, "pdg", "pdd"]).toContain(first);
    expect(await resolveDecompiler(session)).toBe(first);
  });

  test("scopedSearch narrows a byte search to one function and leaves the global scope untouched", async () => {
    await session.cmd("aaa");
    const before = (await session.cmd("e search.in")).trim();
    const whole = hitTotal(
      await searchCommand(session, "/xj ff", "hits", { limit: 1 })
    );
    const scoped = hitTotal(
      await scopedSearch(session, "/xj ff", "hits", {
        in_function: "main",
        limit: 1,
      })
    );
    expect(whole).toBeGreaterThan(0);
    // scoping to one function returns no more hits than the whole binary (usually far fewer)
    expect(scoped).toBeGreaterThanOrEqual(0);
    expect(scoped).toBeLessThanOrEqual(whole);
    // the search scope is restored, so a later unscoped search is unaffected
    expect((await session.cmd("e search.in")).trim()).toBe(before);
    expect(
      hitTotal(await searchCommand(session, "/xj ff", "hits", { limit: 1 }))
    ).toBe(whole);
  });
});

describe.skipIf(!canRunRizin)(
  "rizin_command read-only extras (chapter B) against the real catalog",
  () => {
    let catalog: RzCatalog;
    let session: RzSession;

    beforeAll(async () => {
      catalog = await loadCatalog(rizinPath);
      session = await RzSession.spawn(rizinPath, TEST_BINARY);
    });

    afterAll(() => {
      session.close();
    });

    test("every extra and no-arg dual exists in the installed rizin (no drift in the hardcoded set)", () => {
      const absent = [...READ_ONLY_EXTRAS, ...NOARG_DUALS].filter(
        (cmd) => !isKnownCommand(catalog, cmd)
      );
      expect(absent).toEqual([]);
    });

    test("the policy accepts the new reads and the real rizin runs them without error", async () => {
      for (const command of [
        "elj",
        "ahlj",
        "aij",
        "aclj",
        "Cj",
        "Cslj",
        "tj",
        "tuj",
        "tcc",
        "Llj",
        "LDj",
      ]) {
        const check = checkRizinCommand(catalog, command);
        expect(check.ok).toBe(true);
        // A read-only command returns output or an empty frame — never a stream-desyncing error.
        const out = await session.cmd(command);
        expect((await session.cmd("echo aligned")).trim()).toBe("aligned");
        expect(out).not.toMatch(/Wrong number of arguments/u);
      }
    });

    test("`e asm.arch` reads the value through the host, `e asm.bits=32` is refused before rizin", async () => {
      const check = checkRizinCommand(catalog, "e asm.arch");
      expect(check.ok).toBe(true);
      expect((await session.cmd((check as { line: string }).line)).trim()).toBe(
        "x86"
      );
      expect(checkRizinCommand(catalog, "e asm.bits=32")).toMatchObject({
        ok: false,
      });
    });

    test("`tn` lists noreturn functions bare but is refused with an argument (which would add one)", () => {
      expect(checkRizinCommand(catalog, "tn")).toMatchObject({ ok: true });
      expect(checkRizinCommand(catalog, "tn sym.main")).toMatchObject({
        ok: false,
      });
    });

    test("define_types defines a multi-member struct through the real transport (the `;`s survive the line splitter)", async () => {
      // Unquoted, rizin's command parser would cut this on its member `;`s and reject it; defineTypeLines double-quotes it.
      await defineTypeLines(session, [
        "struct omp_re_cfg { int flags; char *name; unsigned long id; };",
      ]);
      const structs =
        (await session.cmdj<
          { name?: string; members?: Record<string, string> }[]
        >("tsj")) ?? [];
      const defined = structs.find((s) => s.name === "omp_re_cfg");
      expect(defined).toBeDefined();
      expect(Object.keys(defined?.members ?? {})).toEqual([
        "flags",
        "name",
        "id",
      ]);
    });

    test("the p= statistical/entropy histograms are allowed (despite the `=`) and run read-only", async () => {
      for (const command of ["p= 16", "p=e 16", "p==e 16", "p=rj", "p=d"]) {
        const check = checkRizinCommand(catalog, command);
        expect(check).toMatchObject({ ok: true });
        await session.cmd((check as { line: string }).line);
        // no stream desync
        expect((await session.cmd("echo aligned")).trim()).toBe("aligned");
      }
      // interactive visual variants (`…v`) and a `=`-write form stay refused
      expect(checkRizinCommand(catalog, "p==ev")).toMatchObject({ ok: false });
      expect(checkRizinCommand(catalog, "p==v")).toMatchObject({ ok: false });
      expect(checkRizinCommand(catalog, "p=e=5")).toMatchObject({ ok: false });
    });
  }
);

describe.skipIf(!canRunRizin)("load options: a raw/headerless target", () => {
  let dir: string;
  let blob: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "omp-re-raw-"));
    blob = join(dir, "blob.bin");
    writeFileSync(blob, FLAT_X86_32);
  });

  afterAll(() => {
    rmDirSafe(dir);
  });

  test("arch+bits load options disassemble a flat blob that autodetects as the wrong arch", async () => {
    // Autodetection reads the file as 64-bit (no header), so the x86-32 ret
    // would decode differently; the load options pin the real arch.
    const s = await RzSession.spawn(rizinPath, blob, {
      loadOptions: { arch: "x86", bits: 32 },
    });
    try {
      const ops = (await s.cmdj<{ opcode: string }[]>("pdj 3 @ 0"))!;
      expect(ops.map((o) => o.opcode.split(" ")[0])).toEqual([
        "mov",
        "add",
        "ret",
      ]);
    } finally {
      s.close();
    }
  });

  test("map loads a raw file at a base address (the -m form rizin wants for headerless files)", async () => {
    const s = await RzSession.spawn(rizinPath, blob, {
      loadOptions: { arch: "x86", bits: 32, map: "0x400000" },
    });
    try {
      const op = (await s.cmdj<{ opcode: string }[]>("pdj 1 @ 0x400000"))![0]!;
      expect(op.opcode).toContain("mov");
    } finally {
      s.close();
    }
  });

  test("spawnRizin stores the load options so a respawn reloads the blob the same way", async () => {
    const harness = makeHarness("rizin-integration-load");
    const { ctx, entries } = harness;
    entries.push({
      customType: "re.binary",
      data: { load: { arch: "x86", bits: 32 }, path: blob },
      id: "bin-raw",
      type: "custom",
    });
    try {
      await spawnRizin(ctx, blob, { loadOptions: { arch: "x86", bits: 32 } });
      // force a respawn with no options passed — it must reuse the stored ones
      getState(ctx).rz!.close();
      const rz = await ensureRizin(ctx);
      const op = (await rz.cmdj<{ opcode: string }[]>("pdj 1 @ 0"))![0]!;
      expect(op.opcode.split(" ")[0]).toBe("mov");
    } finally {
      shutdownState(ctx.sessionManager.getSessionId());
    }
  });
});

describe.skipIf(!canRunRizin)(
  "session state: respawn, replay, and branch sync",
  () => {
    const harness = makeHarness("rizin-integration-state");
    const { ctx, entries } = harness;
    let fnEa: string;
    let fnName: string;

    beforeAll(async () => {
      const binaryPath = await resolveBinaryPath(TEST_BINARY);
      entries.push({
        customType: "re.binary",
        data: { path: binaryPath },
        id: "bin-0",
        type: "custom",
      });
      const { rz } = await spawnRizin(ctx, binaryPath);
      const fn = (await rz.cmdj<{ offset: number; name: string }[]>(
        "aflj"
      ))![0]!;
      fnEa = `0x${fn.offset.toString(16)}`;
      fnName = fn.name;
    });

    afterAll(() => {
      shutdownState(ctx.sessionManager.getSessionId());
    });

    test("ensureRizin respawns a closed process and replays this branch's annotations", async () => {
      const state = getState(ctx);
      entries.push({
        customType: "re.annotation",
        data: {
          ea: fnEa,
          kind: "rename_function",
          newValue: "omp_re_replayed",
          oldValue: fnName,
        },
        id: "ann-0",
        type: "custom",
      });
      state.rz!.close();

      const respawned = await ensureRizin(ctx);
      expect(respawned.isClosed).toBe(false);
      expect(
        (await respawned.cmdj<{ name: string }[]>(`afij @ ${fnEa}`))![0]!.name
      ).toBe("omp_re_replayed");
    });

    test("concurrent callers after a crash share one respawn", async () => {
      getState(ctx).rz!.close();
      const [a, b] = await Promise.all([ensureRizin(ctx), ensureRizin(ctx)]);
      expect(a).toBe(b);
    });

    test("navigating to a branch without the annotation retires the process and the respawn drops the rename", async () => {
      const state = getState(ctx);
      state.appliedAnnotations = "ann-0";
      entries.splice(
        entries.findIndex((e) => e.id === "ann-0"),
        1
      );
      syncAnnotationsToBranch(ctx);
      expect(state.rz).toBeNull();

      const rz = await ensureRizin(ctx);
      expect(
        (await rz.cmdj<{ name: string }[]>(`afij @ ${fnEa}`))![0]!.name
      ).toBe(fnName);
    });

    test("a file mapped into the session is recorded and re-mapped on respawn", async () => {
      const dir = mkdtempSync(join(tmpdir(), "omp-re-map-"));
      const blob = join(dir, "overlay.bin");
      // 16 bytes
      writeFileSync(blob, "OVERLAYMAPDATA42");
      const expected = Buffer.from("OVERLAYMAPDATA42").toString("hex");
      try {
        entries.push({
          customType: "re.mapfile",
          data: { addr: "0x50000", path: blob },
          id: "map-0",
          type: "custom",
        });
        // force a respawn; replayMapFiles must re-apply the map
        getState(ctx).rz!.close();
        const rz = await ensureRizin(ctx);
        expect((await rz.cmd("p8 16 @ 0x50000")).trim().toLowerCase()).toBe(
          expected
        );
      } finally {
        entries.splice(
          entries.findIndex((e) => e.id === "map-0"),
          1
        );
        rmDirSafe(dir);
      }
    });
  }
);

describe("resolveBinaryPath", () => {
  test("rejects a nonexistent path", async () => {
    await expect(
      resolveBinaryPath("/tmp/omp-re-does-not-exist-ever.bin")
    ).rejects.toThrow("omp-re: no such binary:");
  });
});
