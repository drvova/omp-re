import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils";

import { collectEvidence } from "../extensions/re/entries.ts";
import {
  readBlob,
  rebuildEvidenceIndex,
  registerEvidenceStore,
  writeBlob,
} from "../extensions/re/evidence.ts";
import {
  collectFindings,
  registerFindingTools,
} from "../extensions/re/findings.ts";
import { getState } from "../extensions/re/state.ts";
import { makeHarness, textOf } from "./helpers.ts";

let tempDir: string;
let originalAgentDir: string;

beforeEach(async () => {
  originalAgentDir = getAgentDir();
  tempDir = await mkdtemp(join(tmpdir(), "omp-re-evidence-test-"));
  setAgentDir(tempDir);
});

afterEach(async () => {
  setAgentDir(originalAgentDir);
  await rm(tempDir, { force: true, recursive: true });
});

describe("writeBlob / readBlob", () => {
  test("round-trips content and returns a stable content-addressed hash", async () => {
    const content = "some evidence text";
    const hash = await writeBlob(content);
    expect(hash).toMatch(/^[0-9a-f]{64}$/u);
    const read = await readBlob(hash);
    expect(read).toBe(content);
  });

  test("writing identical content twice is idempotent and yields the same hash", async () => {
    const content = "duplicate blob content";
    const hash1 = await writeBlob(content);
    const hash2 = await writeBlob(content);
    expect(hash1).toBe(hash2);
    expect(await readBlob(hash1)).toBe(content);
  });

  test("readBlob on an unknown hash returns null and does not throw", async () => {
    const unknownHash = "0".repeat(64);
    await expect(readBlob(unknownHash)).resolves.toBeNull();
  });
});

describe("rebuildEvidenceIndex", () => {
  test("indexes exactly the evidence on the current branch, latest id per address", () => {
    const { ctx, entries } = makeHarness("evidence-index-session");
    entries.push(
      {
        customType: "re.evidence",
        data: { ea: "0x4DA0", id: "ev-a", summary: "", tool: "get_function" },
        id: "e1",
        type: "custom",
      },
      {
        customType: "re.evidence",
        data: {
          ea: "0x4da0",
          id: "ev-b",
          summary: "",
          tool: "decompile_function",
        },
        id: "e2",
        type: "custom",
      },
      {
        customType: "re.evidence",
        data: { id: "ev-c", summary: "", tool: "list_imports" },
        id: "e3",
        type: "custom",
      }
    );
    rebuildEvidenceIndex(ctx);
    const state = getState(ctx);
    expect(state.evidenceCount).toBe(3);
    expect(state.evidenceByAddr.get("0x4da0")).toBe("ev-b");

    // /tree navigation back to before the decompile: the index follows the branch.
    entries.splice(1);
    rebuildEvidenceIndex(ctx);
    expect(state.evidenceCount).toBe(1);
    expect(state.evidenceByAddr.get("0x4da0")).toBe("ev-a");
  });
});

describe("the tool_result evidence hook", () => {
  /** A harness whose pi.on captures the tool_result handler, so it can be driven exactly as omp would. */
  function hooked(sessionId: string) {
    const h = makeHarness(sessionId);
    let handler:
      | ((event: unknown, ctx: unknown) => Promise<unknown>)
      | undefined;
    (h.pi as unknown as { on: (name: string, fn: typeof handler) => void }).on =
      (name, fn) => {
        if (name === "tool_result") {
          handler = fn;
        }
      };
    registerEvidenceStore(h.pi as ExtensionAPI);
    const fire = (toolName: string, isError = false) =>
      handler!(
        {
          content: [
            { text: "rizin> pdf @ sym.f\nimul eax, eax, 0x21", type: "text" },
          ],
          details: { ea: "0x10" },
          input: { addr: "sym.f", command: "pdf" },
          isError,
          toolCallId: "t",
          toolName,
          type: "tool_result",
        },
        h.ctx
      ) as Promise<{ content?: { type: string; text?: string }[] } | undefined>;
    return { fire, h };
  }

  test("records an evidence-tier result and tags what the model sees with its id", async () => {
    const { h, fire } = hooked("hook-tag");
    const result = await fire("rizin_command");
    const [ev] = collectEvidence(h.entries);
    expect(ev?.tool).toBe("rizin_command");
    // the tool's own text is untouched; the tag is a separate trailing block
    expect(result?.content?.[0]?.text).toBe(
      "rizin> pdf @ sym.f\nimul eax, eax, 0x21"
    );
    expect(result?.content?.[1]?.text).toBe(
      `[evidence ${ev!.id.slice(0, 8)} — cite it in record_finding]`
    );
    // and the summary/blob were taken over the untagged output
    expect(ev?.summary).not.toContain("[evidence");
  });

  test("the tag's id is exactly what record_finding accepts", async () => {
    const { h, fire } = hooked("hook-roundtrip");
    registerFindingTools(h.pi, {
      judge: () => async (items) =>
        items.map((i) => ({
          index: i.index,
          reason: "",
          verdict: "supported" as const,
        })),
    });
    const tagged = await fire("rizin_command");
    const id = /\[evidence ([0-9a-f]{8})/u.exec(
      tagged?.content?.[1]?.text ?? ""
    )?.[1];
    const res = await h
      .tool("record_finding")
      .execute(
        "c",
        { claim: "f multiplies by 33.", evidence: [id] },
        undefined,
        undefined,
        h.ctx
      );
    expect(textOf(res)).toContain("recorded");
    expect(collectFindings(h.entries)).toHaveLength(1);
  });

  test("leaves non-evidence tools and errored calls alone", async () => {
    const { h, fire } = hooked("hook-skip");
    expect(await fire("rename_function")).toBeUndefined();
    expect(await fire("rizin_command", true)).toBeUndefined();
    expect(collectEvidence(h.entries)).toHaveLength(0);
  });
});
