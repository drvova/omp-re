import { describe, expect, test } from "bun:test";

import type { RzSession } from "../extensions/re/rizin.ts";
import {
  getBinaryInfo,
  listClassRows,
  listEntryPointRows,
  listFlagRows,
  listRelocationRows,
} from "../extensions/re/tools-info.ts";

function stubRz(replies: Record<string, string>) {
  const ran: string[] = [];
  const cmdj = <T>(command: string) => {
    ran.push(command);
    const raw = (replies[command] ?? "").trim();
    return Promise.resolve(raw ? (JSON.parse(raw) as T) : null);
  };
  return {
    ran,
    rz: {
      cmdj,
      cmd: (c: string) => Promise.resolve(replies[c] ?? ""),
      cmdWithStderr: (c: string) =>
        Promise.resolve({ output: replies[c] ?? "", stderr: "" }),
    } as unknown as RzSession,
  };
}

const text = (r: { content: { type: string; text?: string }[] }) =>
  r.content[0].type === "text" ? (r.content[0].text ?? "") : "";

describe("getBinaryInfo", () => {
  test("adds the base address as a formatted EA", async () => {
    const { rz } = stubRz({
      iIj: JSON.stringify({
        arch: "x86",
        baddr: 5368709120,
        bintype: "pe",
        bits: 64,
        compiler: "Linker 0",
      }),
    });
    const result = await getBinaryInfo(rz);
    const t = text(result);
    expect(t).toContain('"arch": "x86"');
    expect(t).toContain("0x140000000");
  });
});

describe("listEntryPointRows", () => {
  test("maps vaddr to ea and keeps the entry type", async () => {
    const { rz } = stubRz({
      iej: JSON.stringify([
        {
          baddr: 5368709120,
          haddr: 168,
          laddr: 0,
          paddr: 2330,
          type: "program",
          vaddr: 5368714010,
        },
      ]),
    });
    const result = await listEntryPointRows(rz);
    const t = text(result);
    expect(t).toContain("0x14000131a");
    expect(t).toContain('"type":"program"');
  });
});

describe("listRelocationRows", () => {
  test("paginates reloc rows", async () => {
    const relocs = Array.from({ length: 4 }, (_, i) => ({
      is_ifunc: false,
      name: `reloc.${i}`,
      paddr: 17920 + i * 8,
      sym_va: 0,
      type: "IMAGE_REL_BASED_DIR64",
      vaddr: 20480 + i * 8,
    }));
    const { rz } = stubRz({ irj: JSON.stringify(relocs) });
    const result = await listRelocationRows(rz, { limit: 2, offset: 1 });
    const t = text(result);
    expect(t).toContain("2 of 4 relocations (offset=1");
    expect(t).toContain("0x5008");
  });
});

describe("listFlagRows", () => {
  test("filters flag names case-insensitively", async () => {
    const flags = [
      { name: "entry0", offset: 5368714010, size: 16 },
      { name: "reloc.pe_00005000", offset: 20480, size: 0 },
    ];
    const { rz } = stubRz({ flj: JSON.stringify(flags) });
    const result = await listFlagRows(rz, { filter: "RELOC" });
    const t = text(result);
    expect(t).toContain("reloc.pe_00005000");
    expect(t).not.toContain("entry0");
  });
});

describe("listClassRows", () => {
  test("passes class rows through and filters on name", async () => {
    const classes = [
      {
        addr: 4194304,
        methods: [{ name: "push_back", addr: 4194350 }],
        name: "std::vector<int>",
      },
      { addr: 4194600, name: "CFoo" },
    ];
    const { rz } = stubRz({ icj: JSON.stringify(classes) });
    const result = await listClassRows(rz, { filter: "vector" });
    const t = text(result);
    expect(t).toContain("push_back");
    expect(t).not.toContain("CFoo");
  });
});
