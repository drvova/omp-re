import { describe, expect, test } from "bun:test";

import { decompileAt } from "../extensions/re/decompile.ts";
import type { RzSession } from "../extensions/re/rizin.ts";

/** Stub session whose cmd() replays canned replies; only what decompileAt needs. */
function stubRz(replies: Record<string, string>): RzSession {
  const cmd = (command: string) => {
    const key = command.trim().split(/\s+/u)[0];
    return Promise.resolve(replies[key] ?? "");
  };
  const cmdj = (command: string) => {
    const raw = (replies[command.trim().split(/\s+/u)[0]] ?? "").trim();
    return Promise.resolve(raw ? JSON.parse(raw) : null);
  };
  return { cmd, cmdj } as unknown as RzSession;
}

describe("decompileAt", () => {
  test("normalizes CRLF from a Windows rizin before handing code to the renderer", async () => {
    const rz = stubRz({
      // probe reply (non-empty = plugin available)...
      "pdg?": "Usage: pdg",
      // ...and a decompile reply with Windows line endings and leading blanks.
      pdg: "\r\n\r\n// WARNING: overlap\r\n\r\nundefined8 sym.main(void)\r\n{\r\n    return;\r\n}\r\n",
    });
    const outcome = await decompileAt(rz, "0x1400014c9");
    expect(outcome?.kind).toBe("pdg");
    expect(outcome?.code).toBe(
      "// WARNING: overlap\n\nundefined8 sym.main(void)\n{\n    return;\n}\n"
    );
    expect(outcome?.code).not.toContain("\r");
  });

  test("keeps the disassembly fallback when the decompiler output is empty", async () => {
    const rz = stubRz({
      pdfj: JSON.stringify({
        name: "sym.main",
        ops: [{ disasm: "push rbp", offset: 0x1_40_00_14_c9 }],
      }),
      pdg: "",
      "pdg?": "Usage: pdg",
    });
    const outcome = await decompileAt(rz, "0x1400014c9");
    expect(outcome?.kind).toBe("disasm");
  });
});
