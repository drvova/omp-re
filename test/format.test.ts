import { describe, expect, test } from "bun:test";

import {
  jsonResult,
  prefixedTextResult,
  textResult,
} from "../extensions/re/format.ts";
import { makeHarness, textOf, must } from "./helpers.ts";

const MAX_LINES = 2000;
const MAX_BYTES = 50 * 1024;

describe("textResult", () => {
  test("passes an under-cap body through unchanged", async () => {
    const result = await textResult("header", "line1\nline2\nline3");
    const text = textOf(result);
    expect(text).toBe("header\nline1\nline2\nline3");
    expect(text).not.toContain("[Output truncated");
    expect(result.details?.header).toBe("header");
    expect(result.details?.truncated).toBeUndefined();
  });

  test("head-truncates a body exceeding MAX_LINES and carries the truncation notice", async () => {
    const lines = Array.from({ length: MAX_LINES + 500 }, (_, i) => `line${i}`);
    const result = await textResult("header", lines.join("\n"));
    const text = textOf(result);
    expect(text).toContain("[Output truncated");
    expect(text).toContain(`${MAX_LINES} of ${MAX_LINES + 500} lines`);
    // Head-truncated: keeps the first line, drops the last.
    expect(text).toContain("line0");
    expect(text).not.toContain(`line${MAX_LINES + 499}`);
    expect(result.details?.truncated).toBe(true);
  });

  test("head-truncates a body exceeding MAX_BYTES and carries the truncation notice", async () => {
    const body = "x".repeat(MAX_BYTES + 10_000);
    const text = textOf(await textResult("header", body));
    expect(text).toContain("[Output truncated");
    expect(text.length).toBeLessThan(body.length);
  });

  test("details.summary never exceeds 512 bytes even for a far larger body", async () => {
    const result = await textResult("header", "y".repeat(MAX_BYTES * 2));
    expect(
      Buffer.byteLength(must(result.details).summary, "utf-8")
    ).toBeLessThanOrEqual(512);
  });

  test("with a tool context, truncated output is spilled to a session artifact and linked", async () => {
    const harness = makeHarness("format-spill");
    const lines = Array.from({ length: MAX_LINES + 10 }, (_, i) => `row${i}`);
    const result = await textResult("big", lines.join("\n"), {
      ctx: harness.ctx,
      tool: "list_strings",
    });
    const text = textOf(result);
    expect(result.details?.artifactId).toBe("0");
    expect(text).toContain("Full output: artifact://0");
    // The artifact holds the untruncated text, header included.
    const saved = must(harness.artifacts.get("0"));
    expect(saved.startsWith("big\nrow0\n")).toBe(true);
    expect(saved).toContain(`row${MAX_LINES + 9}`);
  });

  test("without truncation nothing is spilled", async () => {
    const harness = makeHarness("format-no-spill");
    const result = await textResult("small", "a\nb", {
      ctx: harness.ctx,
      tool: "x",
    });
    expect(result.details?.artifactId).toBeUndefined();
    expect(harness.artifacts.size).toBe(0);
  });
});

describe("prefixedTextResult", () => {
  test("places the prefix at byte 0 with no injected newline", async () => {
    const prefix = "(disassembly only — no decompiler plugin available) ";
    const text = textOf(await prefixedTextResult(prefix, "mov eax, ebx"));
    expect(text.startsWith(prefix)).toBe(true);
    expect(text).toBe(`${prefix}mov eax, ebx`);
  });

  test("still truncates and appends the notice when the body is oversized", async () => {
    const text = textOf(
      await prefixedTextResult("PFX ", "z".repeat(MAX_BYTES + 5000))
    );
    expect(text.startsWith("PFX ")).toBe(true);
    expect(text).toContain("[Output truncated");
  });
});

describe("jsonResult", () => {
  test("round-trips an object and sets ea when supplied", async () => {
    const result = await jsonResult(
      "header",
      { foo: "bar", n: 42 },
      { ea: "0x401d80" }
    );
    const text = textOf(result);
    expect(text).toContain('"foo": "bar"');
    expect(text).toContain('"n": 42');
    expect(must(result.details).ea).toBe("0x401d80");
  });

  test("omits ea when not supplied", async () => {
    const result = await jsonResult("header", { a: 1 });
    expect(must(result.details).ea).toBeUndefined();
  });
});
