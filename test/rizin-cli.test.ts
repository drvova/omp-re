/**
 * The rizin CLI bridge: catalog.ts's command policy and help search, checked
 * against a small synthetic catalog (no rizin needed), then rizin_help,
 * rizin_command, and the required-command compatibility check against the
 * installed rizin's real `?*j` catalog.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";

import {
  checkRizinCommand,
  isKnownCommand,
  isRunnable,
  loadCatalog,
  missingRequiredCommands,
  REQUIRED_COMMANDS,
  searchCatalog,
} from "../extensions/re/catalog.ts";
import type { RzCatalog, RzCommandSpec } from "../extensions/re/catalog.ts";
import {
  addrOf,
  eaFromOffset,
  RzSession,
  resolveBinaryPath,
} from "../extensions/re/rizin.ts";
import { getState, shutdownState } from "../extensions/re/state.ts";
import {
  cleanStderr,
  registerRizinTools,
} from "../extensions/re/tools-rizin.ts";
import {
  canRunRizin,
  captureError,
  logSkip,
  makeHarness,
  rizinAvailable,
  rizinPath,
  TEST_BINARY,
  textOf,
  must,
} from "./helpers.ts";

logSkip("rizin CLI integration tests");

const CORE_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  "%$": { summary: "Print Rizin variables and their values" },
  "%B": {
    summary:
      "There are multiple search modes in Rizin that can be listed using the command `e search.in=?`. This command can be used to get boundaries of those search modes.",
  },
  "%Bj": {
    summary:
      "There are multiple search modes in Rizin that can be listed using the command `e search.in=?`. This command can be used to get boundaries of those search modes.",
  },
  "%Bt": {
    summary:
      "There are multiple search modes in Rizin that can be listed using the command `e search.in=?`. This command can be used to get boundaries of those search modes.",
  },
  "%P": { summary: "Convert physical to virtual address" },
  "%X": { summary: "Show evaluated expression <expr> in hex" },
  "%b": { summary: "Print <expr> in binary format" },
  "%b64": { summary: "Encode <str> in Base64" },
  "%btw": { summary: "Check if <middle> number is between <first> and <last>" },
  "%f": {
    summary:
      "Treat given string as bitstring and get selected characters from bitstring using given value. Bits that are flagged in value are used to get characters from given string. Bitstring is treated in big-endian format",
  },
  "%h": { summary: "Print hash value of string <str>" },
  "%j": { summary: "Evaluate numerical expression <expr> (JSON mode)" },
  "%l": {
    summary:
      "Calculate length of string <str>. Quiet mode stores value in `$?` register.",
  },
  "%lq": {
    summary:
      "Calculate length of string <str>. Quiet mode stores value in `$?` register. (quiet mode)",
  },
  "%o": { summary: "Print <expr> in octal format" },
  "%p": { summary: "Virtual to physical address conversion" },
  "%s": {
    summary:
      "Generate sequence of numbers from <start> to <stop> with <step> increments",
  },
  "%u": { summary: "Convert <expr> to K, M, G, T etc... units" },
  "%v": { summary: "Show last expression ($?) or currently evaluated <expr>" },
  "%vi": {
    summary:
      "Show last expression ($?) or currently evaluated <expr> as integer",
  },
  "%vi1": {
    summary:
      "Show last expression ($?) or currently evaluated <expr> as 1 byte integer",
  },
  "%vi2": {
    summary:
      "Show last expression ($?) or currently evaluated <expr> as 2 bytes integer",
  },
  "%vi4": {
    summary:
      "Show last expression ($?) or currently evaluated <expr> as 4 bytes integer",
  },
  "%vi8": {
    summary:
      "Show last expression ($?) or currently evaluated <expr> as 8 bytes integer",
  },
  "%w": { summary: "Get references of given address" },
  "%x": { summary: "ASCII string to hex string" },
  "/F": {
    args: [{ name: "file", required: true, type: "string" }],
    args_str: " <file>",
    summary: "Search the content of a file.",
  },
  "/R": {
    args_str: " [<re>]",
    description: "Find gadgets ending in ret",
    summary: "Search rop gadgets",
  },
  "/Rk": {
    args: [{ name: "key=value", type: "string" }],
    args_str: " <key>[=<val>] ...",
    summary: "Query ROP Gadgets by providing constraints",
  },
  "/m": {
    args: [{ name: "magic-file", type: "string" }],
    args_str: " [<magic-file>]",
    summary: "Magic constants search.",
  },
  "/x": {
    args: [{ name: "hex", required: true, type: "string" }],
    args_str: " <hex>",
    summary: "Search hex string",
  },
  "C.": { summary: "Show all meta information at current address" },
  "C.j": {
    summary: "Show all meta information at current address (JSON mode)",
  },
  "C.l": {
    summary: "Show all meta information at current address (verbose mode)",
  },
  CC: { summary: "Add comment" },
  aL: {
    summary:
      "List all asm/analysis plugins (e asm.arch=?) or CPU details for a plugin.",
  },
  aLc: { summary: "Shows the CPU details for a specific plugin." },
  aLj: {
    summary:
      "List all asm/analysis plugins (e asm.arch=?) or CPU details for a plugin. (JSON mode)",
  },
  aai: { summary: "Print preformed analysis details" },
  aaij: { summary: "Print preformed analysis details (JSON mode)" },
  aau: { summary: "Print memory areas not covered by functions" },
  afbr: { summary: "Show addresses of instructions which leave the function" },
  afcl: { summary: "List all available calling conventions" },
  afclj: { summary: "List all available calling conventions (JSON mode)" },
  afclk: { summary: "List all available calling conventions (sdb mode)" },
  afcll: { summary: "List all available calling conventions (verbose mode)" },
  afcr: { summary: "Show register usage for the current function" },
  afcrj: {
    summary: "Show register usage for the current function (JSON mode)",
  },
  afd: { summary: "Show function + delta for given offset" },
  afn: { summary: "Rename function" },
  afns: {
    summary: "Print all strings referenced by the function in current seek",
  },
  afnsj: {
    summary:
      "Print all strings referenced by the function in current seek (JSON mode)",
  },
  afsb: {
    summary:
      "Outputs the function signature bytes, mask and search mask at current address",
  },
  afsbj: {
    summary:
      "Outputs the function signature bytes, mask and search mask at current address (JSON mode)",
  },
  afvc: {
    summary: "List value constraints of all variables / of the given one",
  },
  afvcj: {
    summary:
      "List value constraints of all variables / of the given one (JSON mode)",
  },
  afvf: { summary: "Show BP relative stackframe variables" },
  afx: { summary: "Info all fcn variables/args" },
  agc: { args_str: " [<format>]", summary: "Global callgraph" },
  agw: { summary: "Write graph to file" },
  aoe: { summary: "Emulate op" },
  as: { summary: "Show syscall and arguments" },
  asl: { summary: "List syscalls" },
  aslj: { summary: "List syscalls (JSON mode)" },
  asn: { summary: "Returns the syscall number by the name" },
  asr: { summary: "Returns the syscall name by the number" },
  av: { summary: "search for vtables in data sections and show results" },
  avgc: { summary: "List value constraints of all globals / of the given one" },
  avgcj: {
    summary:
      "List value constraints of all globals / of the given one (JSON mode)",
  },
  avgl: { summary: "show/list global variables" },
  avglj: { summary: "show/list global variables (JSON mode)" },
  avglq: { summary: "show/list global variables (quiet mode)" },
  avglt: { summary: "show/list global variables (table mode)" },
  avgp: { summary: "print the global variable value" },
  avgx: { summary: "print all xrefs to the global variable" },
  avgxj: { summary: "print all xrefs to the global variable (JSON mode)" },
  avgxq: { summary: "print all xrefs to the global variable (quiet mode)" },
  avj: {
    summary: "search for vtables in data sections and show results (JSON mode)",
  },
  avrD: { summary: "demangle a class name from RTTI" },
  avx: { summary: "Show the addresses of calls to the virtual function." },
  avxt: {
    summary:
      "Show the addresses of calls to the virtual function. (table mode)",
  },
  axg: { summary: "Show xrefs graph to reach function at current seek" },
  axgj: {
    summary: "Show xrefs graph to reach function at current seek (JSON mode)",
  },
  axl: { summary: "List all xrefs" },
  axlj: { summary: "List all xrefs (JSON mode)" },
  axlq: { summary: "List all xrefs (quiet mode)" },
  cX: {
    summary:
      "Compare hexdump of data of block size at <addr> with the data at current offset using hexdiff output",
  },
  cXj: {
    summary:
      "Compare hexdump of data of block size at <addr> with the data at current offset using hexdiff output (JSON mode)",
  },
  cc: {
    summary:
      "Compare hexdump of data of block size at <addr> with the data at current offset",
  },
  ccc: {
    summary:
      "Show different lines between hexdump of a block of data at <addr> wth the data at current offset",
  },
  ccd: {
    summary:
      "Compare disassembly of block size at <addr> and at the current offset",
  },
  cfj: {
    summary:
      "Compare the contents of <file> with the data at current offset (JSON mode)",
  },
  cu: { summary: "Compare data at <offset> with the current offset" },
  cu1: { summary: "Compare bytes at <offset> with the current offset" },
  cu2: {
    summary: "Compare words (16-bit) at <offset> with the current offset",
  },
  cu4: {
    summary: "Compare dwords (32-bit) at <offset> with the current offset",
  },
  cu8: {
    summary: "Compare qwords (64-bit) at <offset> with the current offset",
  },
  cud: { summary: "Compare disassembly at <offset> with the current offset" },
  e: { summary: "Get/set config" },
  "f.l": { summary: "List the local flags for the function" },
  "f.lj": { summary: "List the local flags for the function (JSON mode)" },
  "f.lq": { summary: "List the local flags for the function (quiet mode)" },
  fL: { summary: "Show the flag length / Set the flag length" },
  fN: {
    summary: "Show the realname of the flag / Set the realname of the flag",
  },
  "fd.": { summary: "Describe flags for the current offset" },
  fg: { summary: "Show the flag graph" },
  fi: { summary: "Show the flags in the block or custom range" },
  fij: { summary: "Show the flags in the block or custom range (JSON mode)" },
  fiq: { summary: "Show the flags in the block or custom range (quiet mode)" },
  fit: { summary: "Show the flags in the block or custom range (table mode)" },
  fl: { summary: "List all flags" },
  "fl.": { summary: "List all flags at the current offset" },
  flj: { summary: "List all flags (JSON mode)" },
  flq: { summary: "List all flags (quiet mode)" },
  flt: { summary: "List all flags (table mode)" },
  fs: { summary: "Select flagspace" },
  fsl: { summary: "Display flagspaces" },
  fslj: { summary: "Display flagspaces (JSON mode)" },
  fslq: { summary: "Display flagspaces (quiet mode)" },
  fssl: { summary: "Display flagspace stack" },
  fsslj: { summary: "Display flagspace stack (JSON mode)" },
  ftl: { summary: "List all flag tags" },
  ftlj: { summary: "List all flag tags (JSON mode)" },
  ftll: { summary: "List all flag tags (verbose mode)" },
  "fz.": { summary: "Show around flag zone context" },
  fzl: { summary: "List all flag zones" },
  fzlj: { summary: "List all flag zones (JSON mode)" },
  id: { summary: "Show DWARF source lines information" },
  idj: { summary: "Show DWARF source lines information (JSON mode)" },
  idp: { summary: "Load PDB file information" },
  idq: { summary: "Show DWARF source lines information (quiet mode)" },
  izj: { summary: "List strings in data sections (JSON mode)" },
  kj: {
    summary:
      "List all namespaces under 'analysis/' and sdb databases in JSON format (SDB).",
  },
  md: {
    summary:
      "Displays information about marks. Without arguments, it describes all marks that contain the current offset. With a <name> argument, it shows details of that mark and the distance in bytes from the current offset to reach the mark. If the mark begins after the current offset, it shows <name> - <bytes> (distance from current offset to  start of the mark). If the mark ends before the current offset, it shows  <name> + <bytes> (distance from current offset to the end of the mark).",
  },
  mdj: {
    summary:
      "Displays information about marks. Without arguments, it describes all marks that contain the current offset. With a <name> argument, it shows details of that mark and the distance in bytes from the current offset to reach the mark. If the mark begins after the current offset, it shows <name> - <bytes> (distance from current offset to  start of the mark). If the mark ends before the current offset, it shows  <name> + <bytes> (distance from current offset to the end of the mark).",
  },
  mdt: {
    summary:
      "Displays information about marks. Without arguments, it describes all marks that contain the current offset. With a <name> argument, it shows details of that mark and the distance in bytes from the current offset to reach the mark. If the mark begins after the current offset, it shows <name> - <bytes> (distance from current offset to  start of the mark). If the mark ends before the current offset, it shows  <name> + <bytes> (distance from current offset to the end of the mark).",
  },
  mi: {
    summary: "Show marks in the current block or in the next <size> bytes.",
  },
  mij: {
    summary:
      "Show marks in the current block or in the next <size> bytes. (JSON mode)",
  },
  miq: {
    summary:
      "Show marks in the current block or in the next <size> bytes. (quiet mode)",
  },
  mit: {
    summary:
      "Show marks in the current block or in the next <size> bytes. (table mode)",
  },
  ml: { summary: "List all marks." },
  mlj: { summary: "List all marks. (JSON mode)" },
  mlq: { summary: "List all marks. (quiet mode)" },
  mlt: { summary: "List all marks. (table mode)" },
  o: { summary: "Open file" },
  obl: { summary: "List opened binary files" },
  oblj: { summary: "List opened binary files (JSON mode)" },
  oblq: { summary: "List opened binary files (quiet mode)" },
  oblt: { summary: "List opened binary files (table mode)" },
  ol: { summary: "List opened files" },
  olj: { summary: "List opened files (JSON mode)" },
  olq: { summary: "List opened files (quiet mode)" },
  olt: { summary: "List opened files (table mode)" },
  oml: {
    summary: "List maps of all file descriptor or only the specified <fd>",
  },
  omlQ: {
    summary:
      "List maps of all file descriptor or only the specified <fd> (quietest mode)",
  },
  omlj: {
    summary:
      "List maps of all file descriptor or only the specified <fd> (JSON mode)",
  },
  omlq: {
    summary:
      "List maps of all file descriptor or only the specified <fd> (quiet mode)",
  },
  omlt: {
    summary:
      "List maps of all file descriptor or only the specified <fd> (table mode)",
  },
  p6d: { args_str: " [<n>]", summary: "Base64 decoding" },
  pd: {
    args: [{ name: "n", type: "number" }],
    args_str: " [<n>]",
    summary: "Disassemble N instructions",
  },
  pdf: { args_str: "", summary: "Disassemble a function" },
  pdsf: { args_str: "", summary: "Summarize the current function" },
  pf: { summary: "Show data using given format string" },
  "pf.": { summary: "Show data using given named format" },
  "pf.j": { summary: "Show data using given named format (JSON mode)" },
  "pf.q": { summary: "Show data using given named format (quiet mode)" },
  pfc: { summary: "Show data using given format string with C syntax" },
  pfd: { summary: "Show data using given format string as DOT" },
  pfj: { summary: "Show data using given format string (JSON mode)" },
  pfq: { summary: "Show data using given format string (quiet mode)" },
  pfs: { summary: "Print the size of format in bytes" },
  pfv: { summary: "Print the value for named format" },
  pfw: { summary: "Write a format" },
  ph: {
    args: [
      {
        choices: ["md5", "entropy"],
        name: "algo",
        required: true,
        type: "choice",
      },
    ],
    args_str: " <algo>",
    summary:
      "Prints a hash/message digest or entropy (use @! to change the block size)",
  },
  pm: {
    args: [{ name: "file/directory", type: "string" }],
    args_str: " [<file/directory>]",
    summary: "Search magics and print the long description of them.",
  },
  pmj: {
    args: [{ name: "file/directory", type: "string" }],
    args_str: " [<file/directory>]",
    summary:
      "Search magics and print the long description of them. (JSON mode)",
  },
  pr: { args_str: " [<n>]", summary: "Print raw bytes" },
  prx: { args_str: " [<n>]", summary: "Printable chars with real offset" },
  px: {
    args: [{ name: "n", type: "number" }],
    args_str: " [<n>]",
    summary: "Show hexdump",
  },
  s: { summary: "Seek" },
  sh: { summary: "List undo seek history" },
  shj: { summary: "List undo seek history (JSON mode)" },
  tp: { summary: "Print formatted type casted to the address or variable" },
  tpv: { summary: "Print formatted type casted to the value" },
  tpx: { summary: "Print formatted type casted to the hexadecimal sequence" },
  ts: {
    summary:
      "List loaded structures / Show pf format string for given structure",
  },
  tsc: { summary: "Show structure in the C output format with newlines" },
  tsd: { summary: "Show structure in the C output format without newlines" },
  tsj: {
    summary:
      "List loaded structures / Show pf format string for given structure (JSON mode)",
  },
  tsl: {
    summary:
      "List loaded structures / Show pf format string for given structure (verbose mode)",
  },
  wx: { summary: "Write hex" },
  x: { summary: "Alias for 'px' (print hexdump)." },
  xc: { summary: "Alias for 'pxc' (show hexdump with comments)." },
  xj: { summary: "Alias for 'px' (print hexdump). (JSON mode)" },
  y: { summary: "Yank bytes / Show yank contents" },
  yj: { summary: "Yank bytes / Show yank contents (JSON mode)" },
  yq: { summary: "Yank bytes / Show yank contents (quiet mode)" },
  ys: { summary: "Print contents of clipboards as string" },
  yx: { summary: "Print contents of clipboard in hexadecimal" },
};

// --- read-only extras (chapter B) --- (`e` is defined above)
// Configuration
const CONFIG_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  "e-": { summary: "Reset config variables" },
  ec: { summary: "List eval colors and keys" },
  ecr: { summary: "Set random palette" },
  el: {
    args: [{ name: "key", type: "string" }],
    summary: "List config variables with their descriptions",
  },
  elj: {
    args: [{ name: "key", type: "string" }],
    summary: "List config variables with their descriptions (JSON mode)",
  },
  es: { summary: "List all config variable spaces" },
  et: {
    args: [{ name: "key", type: "string" }],
    summary: "Show type of given config variable <key>",
  },
};

// Analysis hints (list only)
const HINT_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  aha: { summary: "Set arch hint" },
  ahl: { summary: "List all analysis hints" },
  ahlj: { summary: "List all analysis hints (JSON mode)" },
};

// Address info
const ADDRESS_INFO_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  ai: { summary: "show address information" },
  aii: { summary: "list/add global import (like afii, but global)" },
  aij: { summary: "show address information (JSON mode)" },
};

// Classes
const CLASS_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  aci: {
    args: [{ name: "class_name", type: "string" }],
    summary: "Show information of class",
  },
  acl: { summary: "List all classes" },
  aclj: { summary: "List all classes (JSON mode)" },
  acn: { summary: "Rename class" },
  acvf: {
    args: [{ name: "offset", type: "string" }],
    summary: "Lookup function address on vtable offset",
  },
};

// Metadata & strings
const METADATA_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  C: { summary: "List all meta information" },
  Cd: { summary: 'Set the "data" mark to the current address' },
  Cj: { summary: "List all meta information (JSON mode)" },
  Cl: { summary: "List all meta information (verbose mode)" },
  Cs: { summary: "Add string (autodetects the encoding)" },
  "Cs.": { summary: "Show string at the current address" },
  Csl: { summary: "List all strings" },
  Cslj: { summary: "List all strings (JSON mode)" },
  Csp: { summary: "Add Pascal-style string with the size" },
};

// Types
const TYPE_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  t: { summary: "List all types / Show type information" },
  "t-": { summary: "Remove the type" },
  tc: {
    args: [{ name: "type", type: "string" }],
    summary: "List loaded types in C format with newlines",
  },
  tcc: { summary: "List all calling conventions" },
  te: {
    args: [{ name: "enum", type: "string" }],
    summary: "List loaded enums / Show enum member",
  },
  tfc: {
    args: [
      { name: "name", type: "string" },
      { name: "cc", type: "string" },
    ],
    summary: "Show or set function calling convention",
  },
  tk: {
    args: [{ name: "type", type: "string" }],
    summary: "Show the typeclass of the given type",
  },
  tks: {
    args: [
      { name: "type", type: "string" },
      { name: "typeclass", type: "string" },
    ],
    summary: "Set the typeclass of a type",
  },
  tl: {
    args: [{ name: "type", type: "string" }],
    summary: "List all types / Show type information (verbose mode)",
  },
  to: {
    args: [{ name: "file", type: "string" }],
    summary: "Open C header file and load types from it",
  },
  tu: { summary: "List loaded unions / Show pf format string for given union" },
  tx: {
    args: [{ name: "type", type: "string" }],
    summary: "List functions using the type",
  },
};

// Plugin listings
const PLUGIN_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  L: {
    args: [{ name: "file", type: "string" }],
    summary: "Load a plugin from file",
  },
  LD: { summary: "List the demanglers plugins (alias for iDl)" },
  La: { summary: "List the arch plugins" },
  Ll: { summary: "List the lang plugins" },
};

// Positional duals
const POSITIONAL_DUAL_SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  Ld: {
    args: [{ name: "handler", type: "string" }],
    summary: "List debug plugins / Set debug backend (e dbg.backend)",
  },
  Ldj: {
    args: [{ name: "handler", type: "string" }],
    summary:
      "List debug plugins / Set debug backend (e dbg.backend) (JSON mode)",
  },
  Lo: {
    args: [{ name: "path", type: "string" }],
    summary: "List IO plugins / Register IO plugin from <path>",
  },
  tn: {
    args: [{ name: "name", type: "string" }],
    summary: "List all noreturn references / Add a noreturn function",
  },
  tnj: {
    args: [{ name: "name", type: "string" }],
    summary:
      "List all noreturn references / Add a noreturn function (JSON mode)",
  },
};

const SPECS: Record<string, Omit<RzCommandSpec, "cmd">> = {
  ...CORE_SPECS,
  ...CONFIG_SPECS,
  ...HINT_SPECS,
  ...ADDRESS_INFO_SPECS,
  ...CLASS_SPECS,
  ...METADATA_SPECS,
  ...TYPE_SPECS,
  ...PLUGIN_SPECS,
  ...POSITIONAL_DUAL_SPECS,
};
const CATALOG: RzCatalog = new Map(
  Object.entries(SPECS).map(([cmd, spec]) => [cmd, { ...spec, cmd }])
);

const refusal = (command: string, addr?: string): string => {
  const check = checkRizinCommand(CATALOG, command, addr);
  if (check.ok) {
    throw new Error(
      `expected ${JSON.stringify(command)} to be refused, got line ${JSON.stringify(check.line)}`
    );
  }
  return check.reason;
};

describe("checkRizinCommand (no rizin needed)", () => {
  test("allows read-only commands and appends addr as the only seek", () => {
    expect(checkRizinCommand(CATALOG, "pdsf")).toEqual({
      line: "pdsf",
      name: "pdsf",
      ok: true,
    });
    expect(checkRizinCommand(CATALOG, "  px 64 ", "main")).toEqual({
      line: "px 64 @ main",
      name: "px",
      ok: true,
    });
    expect(checkRizinCommand(CATALOG, "/x 4889e5")).toMatchObject({
      line: "/x 4889e5",
      ok: true,
    });
    expect(checkRizinCommand(CATALOG, "agc ascii", "0x401000")).toMatchObject({
      line: "agc ascii @ 0x401000",
      ok: true,
    });
    // rizin lists `iz` only as its mode variants; the group name still counts as known.
    expect(checkRizinCommand(CATALOG, "iz")).toMatchObject({
      line: "iz",
      ok: true,
    });
  });

  test("allows the one `@` modifier, a temporary block size", () => {
    expect(checkRizinCommand(CATALOG, "ph entropy @!4096")).toMatchObject({
      line: "ph entropy @!4096",
      ok: true,
    });
    expect(checkRizinCommand(CATALOG, "ph md5 @!0x100", "main")).toMatchObject({
      line: "ph md5 @!0x100 @ main",
      ok: true,
    });
  });

  test("allows table-query specs on allowed commands, with a word-shaped grammar", () => {
    expect(checkRizinCommand(CATALOG, "pd:*/head/10")).toMatchObject({
      line: "pd:*/head/10",
      ok: true,
    });
    expect(checkRizinCommand(CATALOG, "px:csv")).toMatchObject({ ok: true });
    expect(
      checkRizinCommand(CATALOG, "pd:xrefsTo/sort:csv", "main")
    ).toMatchObject({ ok: true });
    expect(refusal("pd:bad=spec")).toMatch(/table spec parts/u);
    expect(refusal("pdzz:size/sort")).toBe(
      'omp-re: rizin_command: this rizin has no command "pdzz" — look it up with rizin_help'
    );
    // file commands keep their bare-only rule even through a spec
    expect(refusal("pm:csv /tmp/magic")).toBe(
      "omp-re: rizin_command: pm reads <file/directory> from disk; run it without arguments or not at all"
    );
  });

  test("refuses every way out of a single read-only command", () => {
    for (const [command, label] of [
      ["px 16; !id", "`;`"],
      ["px 16 | sh", "`|`"],
      ["px 16 > /tmp/x", "redirection"],
      ["px 16 < /etc/passwd", "redirection"],
      ["px `!id`", "backticks"],
      ["px $(id)", "substitution"],
      [`px \${HOME}`, "substitution"],
      ["izj~password", "`~`"],
      ["pdf @@ sym.*", "`@` modifiers"],
      ["pdf @ main", "`@` modifiers"],
      ["px @f:/etc/passwd", "`@` modifiers"],
      ["px @e:io.cache=0", "`@` modifiers"],
      // temp-block-replace modifier
      ["px @x:9090 @ main", "`@` modifiers"],
      // seek-to-register modifier
      ["px @r:rsp", "`@` modifiers"],
      ["ph entropy @!4096x", "`@` modifiers"],
      // stderr redirect
      ["iij 2> /tmp/x", "redirection"],
      // html redirect
      ["iij H> /tmp/x", "redirection"],
      ['"px 16 !id"', "double quotes"],
      ["px #!pipe sh", "`#`"],
      ["px 16\\x3b", "backslashes"],
      ["px 16\n!id", "line breaks"],
    ] as const) {
      expect(refusal(command)).toContain(label);
    }
  });

  test("refuses every non-read-only command head, including the task (`&`) and shell (`!`) operators", () => {
    // Validated against rizin's documented prompt grammar (book: first_steps/commandline_rizin).
    for (const command of [
      "!id",
      "!!id",
      "& dc",
      "&t dc",
      "&= 0",
      "3 px",
      "wx 90",
      "o /etc/passwd",
      "s main",
      "afn evil",
      "CC note",
      "pfw x",
      "agw /tmp/g",
      "idp /tmp/x.pdb",
      "$a=!id",
      ".!id",
      "(m;!id)",
    ]) {
      const reason = refusal(command);
      expect(reason).toMatch(
        /is not available here|is not allowed in a command/u
      );
    }
    expect(refusal("afn evil")).toContain("rename_function");
  });

  test("inside ax, only the read-only listings run; adds, deletes, and copies stay refused", () => {
    for (const command of ["axl", "axlj", "axlq", "axg", "axgj"]) {
      expect(checkRizinCommand(CATALOG, command)).toMatchObject({
        name: command,
        ok: true,
      });
    }
    for (const command of [
      "ax 0x40",
      "axc 0x40",
      "axC 0x40",
      "axd 0x40",
      "axs 0x40",
      "ax- 0x40",
      "ax-*",
      "axm 0x40",
    ]) {
      expect(refusal(command)).toMatch(/is not available here/u);
    }
  });

  test("verified read-only listings run; get/set duals and PDB loads stay refused", () => {
    for (const command of [
      "aai",
      "aaij",
      "aau",
      "afbr",
      "afns",
      "afnsj",
      "afsb",
      "afsbj",
      "afcl",
      "afclj",
      "afcr",
      "afcrj",
      "afd",
      "afvf",
      "afvc",
      "id",
      "idj",
      "idq",
      "fl",
      "flj",
      "flq",
      "flt",
      "fl.",
      "f.l",
      "f.lj",
      "fi",
      "fij",
      "fit",
      "fg",
      "fsl",
      "fslj",
      "fssl",
      "fsslj",
      "ftl",
      "ftlj",
      "ftll",
      "fz.",
      "fzl",
      "fzlj",
      "cc",
      "ccc",
      "ccd",
      "cX",
      "cXj",
      "cu",
      "cu1",
      "cu2",
      "cu4",
      "cu8",
      "cud",
      "%v",
      "%vi",
      "%vi4",
      "%X",
      "%x",
      "%b64",
      "%b",
      "%o",
      "%u",
      "%l",
      "%lq",
      "%h",
      "%f",
      "%s",
      "%btw",
      "%P",
      "%p",
      "%w",
      "%B",
      "%Bj",
      "%Bt",
      "%$",
      "%j",
      "y",
      "yj",
      "yq",
      "ys",
      "yx",
      "as",
      "asl",
      "aslj",
      "asn",
      "asr",
      "ol",
      "olj",
      "olq",
      "olt",
      "obl",
      "oblj",
      "oml",
      "omlj",
      "omlQ",
      "omlt",
      "md",
      "mdj",
      "mdt",
      "mi",
      "mij",
      "miq",
      "mit",
      "ml",
      "mlj",
      "mlq",
      "mlt",
      "C.",
      "C.j",
      "C.l",
      "sh",
      "shj",
      "x",
      "xj",
      "xc",
      "aL",
      "aLj",
      "aLc",
      "pf",
      "pfj",
      "pfq",
      "pf.",
      "pf.j",
      "pf.q",
      "pfc",
      "pfd",
      "pfs",
      "pfv",
      "av",
      "avj",
      "avx",
      "avxt",
      "avrD",
      "avgl",
      "avglj",
      "avglq",
      "avglt",
      "avgp",
      "avgx",
      "avgxj",
      "avgxq",
      "avgc",
      "avgcj",
      "tp",
      "tpv",
      "tpx",
      "ts",
      "tsj",
      "tsl",
      "tsc",
      "tsd",
      "kj",
      "pm",
      "pmj",
    ]) {
      expect(checkRizinCommand(CATALOG, command)).toMatchObject({
        name: command,
        ok: true,
      });
    }
    // get/set duals: bare form reads, but the same name with an argument writes
    for (const command of [
      "fL",
      "fN",
      "fs x",
      "fc x",
      "fC x",
      "ft x",
      "afvs",
      "afvr",
      "afs",
      "afsj",
      "aezv",
      "ar",
      "arj",
      "arr",
      "shu",
      "shr",
      "yy",
      "yt",
      "yz",
      "om /tmp/x",
      "asca",
      "m x",
      "pfa x",
      "pfo /tmp/f",
      "pfn fmt body",
      "cf /etc/passwd",
      "cfj /etc/passwd",
      "%= 1",
      "%0",
      "L /tmp/p.dll",
      "yp",
      "yf",
      "p6d 16",
      "avD",
      "avr",
      "avra",
      "avrr",
      "avga",
      "avgn",
      "avgd",
      "avgm",
      "avgcs",
      "avg /tmp/x",
    ]) {
      expect(refusal(command)).toMatch(/is not available here/u);
    }
    // DWARF line info reads, but PDB loading/downloading stays out
    expect(refusal("idp /tmp/x.pdb")).toMatch(/is not available here/u);
    expect(refusal("idpd")).toMatch(/is not available here/u);
  });

  test("chapter B: read-only extras (config, hints, meta, classes, types, plugin lists) run", () => {
    for (const command of [
      // Configuration: read a value / list / type / spaces
      "el",
      "elj",
      "et asm.arch",
      "es",
      // Analysis hints (list)
      "ahl",
      "ahlj",
      // Address info
      "ai",
      "aij",
      // Classes (list/show/graph/lookup with the query arg they require)
      "acl",
      "aclj",
      "aci SomeClass",
      "acvf 8",
      // Metadata & strings (list/show)
      "C",
      "Cj",
      "Cl",
      "Csl",
      "Cslj",
      "Cs.",
      // Types (list, union, enum, calling conventions, type xrefs, typeclass)
      "t",
      "tl int",
      "tc int",
      "te MyEnum",
      "tu",
      "tcc",
      "tx int",
      "tk int",
      // Plugin listings
      "Ll",
      "La",
      "LD",
    ]) {
      expect(checkRizinCommand(CATALOG, command)).toMatchObject({ ok: true });
    }
  });

  test("chapter B: `e <key>` reads a value, but `e key=value` (set) is refused", () => {
    expect(checkRizinCommand(CATALOG, "e asm.arch")).toMatchObject({
      line: "e asm.arch",
      ok: true,
    });
    expect(refusal("e asm.bits=32")).toContain("setting config variables");
    expect(refusal("e io.cache=true")).toContain("setting config variables");
    // a seek addr is still fine and does not count as `=`
    expect(checkRizinCommand(CATALOG, "e asm.arch", "main")).toMatchObject({
      line: "e asm.arch @ main",
      ok: true,
    });
  });

  test("chapter B: positional duals list with no argument and are refused with one", () => {
    for (const bare of ["tn", "tnj", "Ld", "Ldj"]) {
      expect(checkRizinCommand(CATALOG, bare)).toMatchObject({
        line: bare,
        ok: true,
      });
    }
    expect(refusal("tn sym.main")).toContain("read-only only with no argument");
    expect(refusal("Ld gdb")).toContain("read-only only with no argument");
    // Lo also has a <path> arg, so either guard may fire — but it must be refused with one.
    expect(checkRizinCommand(CATALOG, "Lo")).toMatchObject({ ok: true });
    expect(refusal("Lo /tmp/plugin.so")).toMatch(
      /read-only only with no argument|reads <path> from disk/u
    );
  });

  test("chapter B: the type/class/hint writers next to the new reads stay refused", () => {
    for (const command of [
      "e-",
      "ec",
      "ecr",
      "aha 0",
      "aii",
      "acn Old New",
      "Cs hello",
      "Csp 4",
      "Cd",
      "t- int",
      "tfc main cdecl",
      "tks int basic",
      "to /tmp/h.h",
      "L /tmp/p.so",
    ]) {
      expect(refusal(command)).toMatch(
        /is not available here|read-only only with no argument|setting config/u
      );
    }
  });

  test("chapter B: the gadget-constraint queries keep their `=` arguments (not caught by the config guard)", () => {
    // `/Rk reg=rax` is a read-only ROP query; only `e` treats `=` as a write.
    expect(checkRizinCommand(CATALOG, "/Rk reg=rax")).toMatchObject({
      line: "/Rk reg=rax",
      ok: true,
    });
  });

  test("refuses raw-byte printers, which would break the NUL-framed pipe", () => {
    expect(refusal("pr 64")).toContain("is not available here");
    expect(refusal("p6d 16")).toContain("is not available here");
    expect(checkRizinCommand(CATALOG, "prx 32")).toMatchObject({ ok: true });
  });

  test("refuses commands that would read a file from disk", () => {
    expect(refusal("/F /etc/passwd")).toContain("is not available here");
    expect(refusal("/m /tmp/magic")).toBe(
      "omp-re: rizin_command: /m reads <magic-file> from disk; run it without arguments or not at all"
    );
    expect(checkRizinCommand(CATALOG, "/m")).toMatchObject({
      line: "/m",
      ok: true,
    });
    // `pm` joined the same bare-only rule: its catalog arg is <file/directory>.
    expect(refusal("pm /tmp/magic")).toBe(
      "omp-re: rizin_command: pm reads <file/directory> from disk; run it without arguments or not at all"
    );
    expect(checkRizinCommand(CATALOG, "pm")).toMatchObject({
      line: "pm",
      ok: true,
    });
  });

  test("refuses commands this rizin doesn't have, and interactive modes", () => {
    expect(refusal("pdzz")).toBe(
      'omp-re: rizin_command: this rizin has no command "pdzz" — look it up with rizin_help'
    );
    expect(refusal("agc interactive")).toContain("keyboard input");
    expect(refusal("   ")).toBe("omp-re: rizin_command: empty command");
  });

  test("validates addr with the same allowlist as every other tool", () => {
    expect(() => checkRizinCommand(CATALOG, "px 16", "main;!id")).toThrow(
      "omp-re: invalid address or expression"
    );
  });

  test("isRunnable and isKnownCommand", () => {
    expect(
      [
        "pdf",
        "pdsf",
        "px",
        "ph",
        "/x",
        "/R",
        "agc",
        "aoe",
        "izj",
        "prx",
        "e",
        "acl",
        "ahl",
        "tu",
        "Ll",
        "tn",
      ].every(isRunnable)
    ).toBe(true);
    // `e` is runnable now (the get form); `e-` (reset) and the other writers are not.
    expect(
      [
        "pr",
        "prz",
        "p6d",
        "pfw",
        "wx",
        "e-",
        "afn",
        "CC",
        "/F",
        "ps+",
        "iz-",
        "tfc",
        "tks",
        "aha",
        "acn",
      ].some(isRunnable)
    ).toBe(false);
    expect(isKnownCommand(CATALOG, "iz")).toBe(true);
    expect(isKnownCommand(CATALOG, "pdzz")).toBe(false);
  });

  test("the p= histogram family is runnable despite its `=`, but the interactive `…v` and `=`-write forms are not", () => {
    expect(
      ["p=", "p==", "p=e", "p==e", "p=rj", "p=d", "p=A", "p=C"].every(
        isRunnable
      )
    ).toBe(true);
    // `…v` is the interactive ncurses variant (would block the pipe); `p=e=5` smuggles a second `=`.
    expect(["p==v", "p==ev", "p==Av", "p=e=5", "p=e;x"].some(isRunnable)).toBe(
      false
    );
  });
});

describe("searchCatalog (no rizin needed)", () => {
  test("an exact command shows its usage and typed arguments, then its family", () => {
    const { header, lines } = searchCatalog(CATALOG, "pd");
    expect(header).toBe("rizin help: pd (3 commands)");
    expect(lines[0]).toBe("pd [<n>] — Disassemble N instructions");
    expect(lines[1]).toBe("  <n>: number, optional");
    expect(lines).toContain("related:");
    expect(lines).toContain("pdf — Disassemble a function");
  });

  test("choices and required flags are spelled out", () => {
    const { lines } = searchCatalog(CATALOG, "ph");
    expect(lines[1]).toBe("  <algo>: choice, required, one of: md5, entropy");
  });

  test("commands rizin_command refuses are marked", () => {
    const { lines } = searchCatalog(CATALOG, "pr");
    expect(lines[0]).toBe(
      "pr [<n>] — Print raw bytes  [not runnable via rizin_command]"
    );
    expect(lines).toContain("prx [<n>] — Printable chars with real offset");
  });

  test("keywords search summaries first, then descriptions", () => {
    const { header, lines } = searchCatalog(CATALOG, "gadgets");
    // Both /R and /Rk carry "gadgets" in their summary; the shorter command ranks first.
    expect(header).toBe('rizin help search: "gadgets" (2 matches)');
    expect(lines[0]).toBe("/R [<re>] — Search rop gadgets");
    expect(lines).toContain(
      "/Rk <key>[=<val>] ... — Query ROP Gadgets by providing constraints"
    );
    expect(searchCatalog(CATALOG, "zzz nothing").lines[0]).toStartWith(
      "no command matches"
    );
  });
});

describe("missingRequiredCommands and cleanStderr (no rizin needed)", () => {
  test("names each required command a catalog lacks", () => {
    const full: RzCatalog = new Map(
      REQUIRED_COMMANDS.map((cmd) => [cmd, { cmd }])
    );
    expect(missingRequiredCommands(full)).toEqual([]);
    const partial = new Map(full);
    partial.delete("afvlj");
    partial.delete("%v");
    expect(missingRequiredCommands(partial)).toEqual(["afvlj", "%v"]);
  });

  test("drops terminal control sequences and blank lines, keeps messages", () => {
    expect(cleanStderr("\u001B[2K\r\u001B[2K\r")).toBe("");
    expect(
      cleanStderr("\u001B[2K\rERROR: Flag combination '4' is invalid.\n")
    ).toBe("ERROR: Flag combination '4' is invalid.");
  });
});

describe.skipIf(!rizinAvailable)("the installed rizin's catalog", () => {
  test("has every command omp-re's own tools send", async () => {
    const catalog = await loadCatalog(rizinPath);
    expect(catalog.size).toBeGreaterThan(1000);
    expect(missingRequiredCommands(catalog)).toEqual([]);
  });

  test("rizin_help answers from it, with argument detail", async () => {
    const catalog = await loadCatalog(rizinPath);
    const { header, lines } = searchCatalog(catalog, "ph");
    expect(header).toStartWith("rizin help: ph (");
    expect(lines[0]).toStartWith("ph ");
    expect(lines.some((line) => line.startsWith("  <"))).toBe(true);
  });
});

const harness = makeHarness("rizin-cli-test-session");
const { ctx } = harness;
const run = (name: string, params: Record<string, unknown>) =>
  harness.tool(name).execute(`t-${name}`, params, undefined, undefined, ctx);

describe.skipIf(!canRunRizin)(
  "rizin_help and rizin_command against rizin",
  () => {
    let session: RzSession;
    let mainEa: string;

    beforeAll(async () => {
      const binaryPath = await resolveBinaryPath(TEST_BINARY);
      session = await RzSession.spawn(rizinPath, binaryPath);
      const state = getState(ctx);
      state.rz = session;
      state.binaryPath = binaryPath;
      registerRizinTools(harness.pi);
      const rawFns = await session.cmd("aflj");
      const fns = JSON.parse(rawFns.trim()) as {
        name: string;
        offset?: number;
        addr?: number;
      }[];
      const main = fns.find((fn) => fn.name === "main");
      if (!main) {
        throw new Error(
          `rizin-cli.test setup: fixture ${TEST_BINARY} has no function named 'main'`
        );
      }
      mainEa = eaFromOffset(must(addrOf(main)));
    });

    afterAll(() => {
      shutdownState(ctx.sessionManager.getSessionId());
    });

    test("rizin_help is read-tier; rizin_command asks for exec approval naming the command", () => {
      expect(harness.tool("rizin_help").approval).toBe("read");
      const approval = harness.tool("rizin_command").approval as (
        args: unknown
      ) => { tier: string; reason: string };
      expect(approval({ addr: "main", command: "px 16" })).toEqual({
        reason: 'Run the rizin command "px 16 @ main" on the open binary.',
        tier: "exec",
      });
    });

    test("rizin_help looks up a family and searches keywords", async () => {
      expect(textOf(await run("rizin_help", { query: "/R" }))).toStartWith(
        "rizin help: /R ("
      );
      const search = textOf(await run("rizin_help", { query: "entropy" }));
      expect(search).toStartWith('rizin help search: "entropy"');
      expect(search).toContain("ph ");
    });

    test("rizin_command output matches rizin's own, at the given address", async () => {
      const rawExpected = await session.cmd(`px 32 @ ${mainEa}`);
      const expected = rawExpected.replace(/\n+$/u, "");
      const result = await run("rizin_command", {
        addr: mainEa,
        command: "px 32",
      });
      expect(textOf(result)).toBe(`rizin> px 32 @ ${mainEa}\n${expected}`);
      expect(result.details?.ea).toBe(mainEa);
    });

    test("rizin_command runs function summaries and block-size-scoped entropy", async () => {
      expect(
        textOf(
          await run("rizin_command", { addr: "main", command: "pdsf" })
        ).split("\n").length
      ).toBeGreaterThan(1);
      const entropy = textOf(
        await run("rizin_command", {
          addr: "main",
          command: "ph entropy @!4096",
        })
      );
      expect(entropy).toMatch(/^rizin> ph entropy @!4096 @ main\n\d+\.\d+$/u);
    });

    test("a search with no hits is empty output, not an error", async () => {
      const result = await run("rizin_command", {
        command: "/x deadbeefcafebabe1337",
      });
      expect(textOf(result)).toBe(
        "rizin> /x deadbeefcafebabe1337\n(no output)"
      );
      expect(result.isError).toBeFalsy();
    });

    test("rizin's own error text comes back when it rejects the arguments", async () => {
      const result = await run("rizin_command", {
        command: "/z nosuchstring 4 20",
      });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("(no output; rizin said:)");
      expect(textOf(result)).toContain("ERROR:");
    });

    test("a refused command never reaches rizin, and the session survives every case", async () => {
      const err = await captureError(
        run("rizin_command", { command: "pr 64" })
      );
      expect(err.message).toContain('"pr" is not available here');
      const echoOutput = await session.cmd("echo alive");
      expect(echoOutput.trim()).toBe("alive");
      expect(session.isClosed).toBe(false);
    });
  }
);
