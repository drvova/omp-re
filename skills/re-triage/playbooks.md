# omp-re playbooks

Task-shaped recipes that compose the one observational tool (`rizin_command`),
the stateful tools, and `rizin_emulate` into the analyses other suites ship as
single buttons — deep-function review, vulnerability hunting, crackme solving,
IOC extraction, exploit-dev recon, shellcode and file-format triage, diffing.

Each is a **starting line, not a script**: adapt from what the binary shows.
Every `rizin_command` read returns an `[evidence xxxxxxxx]` tag — cite those ids
in `record_finding` so the conclusion reaches the report. Look up a command's
exact arguments for the installed rizin with `rizin_help`; the grounding rules
in `SKILL.md` still hold (only addresses from tool output, hedge hypotheses,
disassembly is not decompiled C).

The parse helper from `SKILL.md` (`const rows = (r) => JSON.parse(r.text.split("\n").slice(1, -1).join("\n"));`)
is assumed below.

## Deep function analysis

Everything known about one function, grounded:

```js
const at = "sym.target";                                        // an address/name from aflj
const info = rows(await tool.rizin_command({ command: "afij", addr: at }))[0]; // sig, nargs, callers
const cc   = rows(await tool.rizin_command({ command: "afcrj", addr: at }));   // ret reg + arg regs
const vars = rows(await tool.rizin_command({ command: "afvlj", addr: at }));   // locals/args (afvlj, not afvj)
const to   = rows(await tool.rizin_command({ command: "axtj", addr: at }));    // who calls it
print((await tool.rizin_command({ command: "pdg", addr: at }).catch(() => tool.rizin_command({ command: "pdf", addr: at }))).text);
```

If argument recovery looks wrong, `set_calling_convention` then re-read. Name
what you learn with `rename_variable` / `set_comment` so it is recorded.

## Vulnerability patterns

Dangerous call sites and the binary's own hardening — the two halves of a
"find-vulnerabilities" pass:

```js
const imp = rows(await tool.rizin_command({ command: "iij" }));
const risky = /^(gets|strcpy|strcat|sprintf|scanf|system|exec|popen|memcpy|alloca|vsprintf)/i;
for (const i of imp.filter((x) => risky.test(x.name ?? "")))
  print(i.name + " -> " + rows(await tool.rizin_command({ command: "axtj", addr: i.plt ?? i.vaddr })).length + " call sites");
```

Mitigations (checksec) come from `ij` — the `bin` object carries `nx`, `pie`,
`canary`, `relro`, `stripped`, `fortify_source`. A format-string bug is a
`printf`-family call whose format argument is non-constant: follow the arg
register (`afcrj`) back with `axfj`/`pdg`. Record each as a hedged finding
tying the sink to its caller; absence ("no unchecked `strcpy`, canary + full
RELRO present") is itself a finding.

## Crackme / constraint recovery

Find the check, then let the RzIL VM do the arithmetic instead of guessing:

1. Locate the comparison — xrefs into `strcmp`/`memcmp`/`strncmp` (`axtj @`), or
   a run of `cmp`/`test` in the validator (`pdf @ <fn>`).
2. Read the decompiled check (`pdg @ <fn>`) for the shape (length gate, byte
   math, lookup table).
3. Emulate the computation with `rizin_emulate` — `init` at the function,
   `set_var` the input pointer/registers, `step`, and watch the `var_write` /
   `pc_write` events to see which branch a candidate takes. The step output is a
   full per-instruction trace already.
4. For a single transform (xor/add/rotate of a constant), `ae <rpn>` evaluates
   it directly: `ae 0x41,0x13,^` → the transformed byte, no VM needed.

Record the recovered constraint/key as a finding citing the emulate and
decompile evidence.

## IOC extraction

Strings plus the imports that use them:

```js
const s = rows(await tool.rizin_command({ command: "izzj" }));   // izzj = whole file; izj = data only
const pat = {
  url:    /\bhttps?:\/\/[^\s"']+/i,
  ip:     /\b\d{1,3}(?:\.\d{1,3}){3}\b/,
  domain: /\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/i,
  path:   /(?:[A-Za-z]:\\|\/(?:etc|tmp|usr|home)\/)[^\s"']+/,
};
for (const [k, re] of Object.entries(pat))
  for (const row of s.filter((x) => re.test(x.string ?? "")).slice(0, 20)) print(k + "\t" + row.string);
```

Cross-reference a hit with `axtj @ <vaddr>` to prove it is *used* (a reachable
IOC), not just present. Network imports (`iij`) corroborate C2 strings.

## Exploit-dev reconnaissance

What a "exploit-hunter" surfaces, as observations — never weaponized:

- Mitigations from `ij` (`nx`, `pie`, `canary`, `relro`) decide the technique
  space; state them first.
- ROP gadgets: `/Rj pop` (filter by suffix) lists gadgets with their addresses;
  `/Rj` alone is large, so filter.
- Writable + executable regions and the GOT/PLT: `iSj` (section perms), `irj`
  (relocations). An RWX segment or non-full RELRO is the finding.

Keep this descriptive: report the primitives present, not an exploit.

## Raw bytes & shellcode

For a blob with no container (shellcode, a carved region):

- Disassemble bytes directly with `rizin_cli` → `rz-asm` (`-d` to disassemble,
  `-a <arch> -b <bits>`), or `map_file` the blob as raw (`format: "any"`) and
  `pdf`/`pd`.
- `ph entropy @!4096` over the blob flags packed/encrypted spans.
- Emulate a decoder stub with `rizin_emulate` to recover the plaintext it
  builds, then `px` the VM memory it wrote.

## File-format & packer triage

- `rz-bin` via `rizin_cli` (`-I` info, `-H` fields, `-S` sections, `-l` libs)
  parses the container without full analysis — fast and good for malformed
  files.
- Overlay / appended data: compare `iSj` section extents against the file size
  from `ij` (`core.size`); bytes past the last section are an overlay.
- High whole-file entropy (`ph entropy`) with few imports (`iij`) and few
  strings (`izj`) is the classic packed shape — say "resembles a packer",
  hedged, and look for the unpacking stub at the entry (`pdf @ entry0`).

## Diffing two binaries

omp-re already bridges rizin's differ — no second session needed:

```js
await tool.rizin_cli({ tool: "rz-diff", args: ["-t", "functions", "-A", "old.bin", "new.bin"] });
```

`-t` picks the dimension (`functions`, `imports`, `symbols`, `strings`,
`sections`, `bytes`); `-A` matches by analysis, add `-B` for full analysis
first. Use it for patch analysis (what changed between two versions) or to
confirm two samples share a family.

## Emulation & computation

The RzIL VM and ESIL calculator, both reachable today:

- **`rizin_emulate`** drives rizin's RzIL VM: `init` at an address, `set_var`
  the registers/stack, `step` (returns the per-instruction read/write trace),
  `step_until` an address, `vars` for the full state. No OS process runs — safe
  for decryptor loops and argument computation. (ESIL *stepping*, `aes`, is
  unreliable through rizin's pipe in 0.9.1; RzIL is the live replacement.)
- **`ae <rpn>`** through `rizin_command` is a stateless ESIL calculator for
  one-off math: `ae 0xdead,0xbeef,^`, `ae 1,20,<<`. No VM, no target code.
- **`aoj` / `ao`** through `rizin_command` lifts an instruction and shows both
  its `esil` and `rzil` forms (`ao` is the IL AST view) — use it to understand
  one opcode's semantics without stepping.
