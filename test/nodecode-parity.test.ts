/**
 * The nodecode cell carries its own Lisp engine (nodecode/*.lisp), ported
 * from this TypeScript one. Two engines that share a record format and a
 * security policy must not drift, so this suite holds them to each other:
 *
 *  - nodecode/policy-data.lisp — the read-only command policy's patterns and
 *    command lists — is generated from catalog.ts and must be current;
 *  - for the same inputs, both engines agree on which commands
 *    `rizin_command` runs and on every refusal's words, on quoting and
 *    validation, and on the canonical/shift hashes, SHA-256 and HMAC that
 *    evidence, `/re verify`, `/re carry` and the audit log rest on.
 *
 * The comparison needs SBCL and cl-ppcre (the Lisp side) and is skipped,
 * loudly, without them. With rizin present the whole installed command
 * catalog is judged by both; without it, a fixed set of command names.
 */
import { describe, expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { checkDebugOnHitCommand, checkRizinCommand, forbiddenSyntaxReason, isRunnable, loadCatalog, NOARG_DUALS, READ_ONLY_EXTRAS, REQUIRED_COMMANDS, searchCatalog, type RzCatalog, type RzCommandSpec } from "../extensions/re/catalog.ts";
import { canonicalExcerpt, canonicalHash, canonicalizeRizinOutput, formatJson, shiftHash, textResult } from "../extensions/re/format.ts";
import { normalizeAddr, rzQuote, validateAddr, validateIdent, validateTypeLike } from "../extensions/re/rizin.ts";
import { rizinAvailable, rmDirSafe } from "./helpers.ts";

const ROOT = resolve(import.meta.dir, "..");

function lispAvailable(): boolean {
	if (Bun.which("sbcl") === null) return false;
	const probe = Bun.spawnSync(["sbcl", "--non-interactive", "--eval", "(require :asdf)", "--eval", '(asdf:load-system "cl-ppcre")'], { stdout: "ignore", stderr: "ignore" });
	return probe.exitCode === 0;
}

const canRunLisp = lispAvailable();
if (!canRunLisp) console.log("omp-re: skipping the nodecode parity comparison — needs sbcl and cl-ppcre");

/** What a function returns, or `{ error }` for what it throws — the shape parity.lisp answers. */
function answer<T>(run: () => T): T | { error: string } {
	try {
		return run();
	} catch (err) {
		return { error: err instanceof Error ? err.message : String(err) };
	}
}

const ESC = "\x1b";
const FIXED_NAMES = [
	...READ_ONLY_EXTRAS,
	...NOARG_DUALS,
	...REQUIRED_COMMANDS,
	..."p pd pdf pdfj pdg pdd px pxw p8 pr prx prc prz prg po pw pkill p6d p6e pf pfj pf. pf.j pfc pfd pfs pfv pfa pfo pfw pfn pf- pm pmj p= p== p=e p==e p=ev p=rj ph i ij iz izj iI iIj ii iij id idj idq idp idpd / /x /xj /R /Rj /F /m ag agc agcj age agn agw ao aoj ab abj ax axt axtj axf axfj axl axlj axlq axg axgj axc axC axd axs ax- axm aai aaij aau aa aaa afbr afns afnsj afsb afsbj afcl afclj afcll afclk afcr afcrj afd afvf afvc afvcj afl aflj aflt afi afij afb afbj afbc afbe afx afvl afvlj afvx afvR afvW afvd afo afM afn afvn afvt afs afii CC CC. CCl CCf CC- fd fdj cc ccc ccd cX cXj cu cu1 cu8 cud cf cfj av avj avx avxt avrD avr avra avD avgl avglj avgp avgx avgc tp tpv tpx ts tsj tsl tsc tsd kj k %v %vi %vi8 %X %x %b64 %b %o %u %l %lq %h %f %s %btw %P %p %w %B %Bj %$ %j %= %== %+ %- %! %% %0 %i y yj yq yx ys yp yy yt as asl aslj asn asr asc asca ol olj oml omlQ om obl md mdj mi ml C. C.j C.l sh shj shu x xj xc aL aLj aLc e el elj et es w wx wa o oo d dc db dr s sr ! !! . ( #! L Ll Ld Ldj Lo tn tnj t tj td tdf tfc tks to tr t- Flt Fc ica q".split(" "),
];
// In JavaScript `$` is the very end; a pattern engine where it also matches before a final newline would let these through.
const NEWLINE_NAMES = ["aflj\n", "p=e\n", "pf.\n", "tsj\n", "aflj\n!id", "\naflj"];
const LINES = [
	"aflj", "px 64", "ph entropy @!4096", "ph entropy @!0x1000", "pd 4 @ main", "pd @@ sym.*", "afl~main", "izj | sh", "px > /tmp/x", "px < /tmp/x",
	"pd `iI`", "px $(id)", "px ${x}", 'px "a"', "pd #x", "px \\x", "px\n!id", "px\r", "px\0q", "aflj;!id", "e asm.arch", "ph md5 @!16 extra", "px @!", "px @!abc",
];
const COMMANDS = [
	{ command: "aflj" }, { command: "  pdf  ", addr: "main" }, { command: "pdf", addr: "sym.main+0x10" }, { command: "pdf", addr: "main;!id" }, { command: "pdf", addr: "0x10 @@ x" },
	{ command: "" }, { command: "   " }, { command: "wx 90" }, { command: "afn x" }, { command: "CC hello" }, { command: "e asm.arch" }, { command: "e asm.arch=arm" }, { command: "el" },
	{ command: "tn" }, { command: "tn exit" }, { command: "Ld" }, { command: "Ld native" }, { command: "aflt:size/sort/dec:name/head/5" }, { command: "aflt:$x" }, { command: "aflt:a b" },
	{ command: "pzzzq" }, { command: "pd 4" }, { command: "agc interactive" }, { command: "/m" }, { command: "/m /etc/magic" }, { command: "pm" }, { command: "pm /etc" },
	{ command: "izj~x" }, { command: "px 16;!id" }, { command: "p=e" }, { command: "p=ev" }, { command: "ph entropy 4096" }, { command: "ph entropy @!4096" }, { command: "/xj 4889e5" },
	{ command: "%v main" }, { command: "%= 1" }, { command: "dr" }, { command: "o /etc/passwd" }, { command: "!id" }, { command: "aai" }, { command: "afvlj", addr: "entry0" }, { command: "cf /etc/passwd" }, { command: "pdf", addr: "main\n" }, { command: "aflt:name\n" }, { command: "aflj\n!id" },
];
const ON_HIT = ["drj", "dr rax=0", "dmj", "dbtj", "dmhg", "dc", "dpa 1", "px 16", "wx 90", "", "drj;!id", "dm=", "pd 2", "dkl", "ddl", "dd /etc/passwd"];
const QUERIES = ["afl", "pd", "/R", "entropy", "rop gadgets", "call graph", "zzzznothing", "px", "", "CC."];
const TEXTS = ["plain", "x; !id", "it's", "back\\slash", "a'b\\c'", "semi;colon", "pipe|x", "amp&x", "tick`x", "dollar$x", "new\nline", "cr\rx", "nul\0x", "int (*)(char *, ...)", "unsigned long long", "héllo — λ", "@ ~ # > <"];
const ADDRS = ["0x1100", "0X01100", "0x1100 ", "0x", "0x0", "0x000", "main", "Main", "sym.main+0x10", "$$", "entry0", "main;!id", "a b", "x@y", "x~y", "(x)", "", "fcn.00001100", "0x00000000deadBEEF", "_start", "9lives", "a.b.c", "a-b", "main\n", "main\n!id", "\nmain", "main\r"];
const OUTPUTS = [
	"",
	"0x00001000  call 0x2000\n0x00001005  mov eax, 0x10\n",
	`${ESC}[31m/tmp/sample bin${ESC}[0m loaded  \r\nline two\t \r\n\r\n\r\n`,
	"  ;-- main:\n| 0x00401000  lea rax, [rip + 0x2f31]  ; 0x403f38\n| 0x00401007  call sym.imp.puts  ; int puts(const char *s)\n\\ 0x0040100c  jmp 0x401020\n",
	"0x1000 jne 0x1010\n0x1002 bl 0x4000\n0x1004 b.ne 0x5000\n0x1006 cbz x0, 0x6000\n0x1008 loopne 0x1000\n0x100a call fcn.000011fd ; XREF from main @ 0x1234\n",
	"[{\"offset\":4096,\"name\":\"main\"}]\n",
	"plain text with no addresses at all\n\n",
	"héllo — λ unicode ☃\n",
	"x".repeat(3000),
	Array.from({ length: 40 }, (_, i) => `line ${i} @ 0x${(0x1000 + i).toString(16)}`).join("\n"),
];
const JSON_TEXTS = ["[]", "{}", "[1,2,3]", '{"a":1,"b":[true,false,null],"c":{"d":"x\\ny"}}', '[{"offset":4096,"name":"main","size":12},{"offset":8192,"name":"fcn.00002000"}]', '"s"', "42", "-2.5", "[[],[{}]]", '{"u":"\\u00e9\\ud83d\\ude00","q":"\\"\\\\/"}'];
const LONG = [
	Array.from({ length: 2500 }, (_, i) => `row ${i}`).join("\n"),
	Array.from({ length: 900 }, (_, i) => `${"y".repeat(80)} ${i}`).join("\n"),
	"z".repeat(60 * 1024),
	"short\nbody",
	Array.from({ length: 2000 }, (_, i) => `r${i}`).join("\n"),
	`${Array.from({ length: 2001 }, (_, i) => `r${i}`).join("\n")}\n`,
];

test("nodecode/policy-data.lisp is generated from catalog.ts and current", () => {
	const check = Bun.spawnSync(["bun", join(ROOT, "scripts", "gen-nodecode-policy.ts"), "--check"], { stdout: "pipe", stderr: "pipe" });
	expect(check.stderr.toString()).toBe("");
	expect(check.exitCode).toBe(0);
});

test("the recipe tables in both hosts are generated from recipes/tables.json and current", () => {
	const check = Bun.spawnSync(["bun", join(ROOT, "scripts", "gen-recipes.ts"), "--check"], { stdout: "pipe", stderr: "pipe" });
	expect(check.stderr.toString()).toBe("");
	expect(check.exitCode).toBe(0);
});

describe.skipIf(!canRunLisp)("the Lisp engine agrees with this one", () => {
	let lisp: Record<string, unknown[]>;
	let catalog: RzCatalog;
	let names: string[];

	test("runs the same cases", async () => {
		// With rizin, the installed catalog — every command this build has; without, an empty one (then only the catalog-independent refusals are compared) plus the fixed names.
		const real = rizinAvailable ? await loadCatalog() : new Map<string, RzCommandSpec>();
		catalog = real;
		names = [...new Set([...FIXED_NAMES, ...NEWLINE_NAMES, ...real.keys()])];
		const dir = mkdtempSync(join(tmpdir(), "omp-re-parity-"));
		const input = join(dir, "in.json");
		const output = join(dir, "out.json");
		writeFileSync(input, JSON.stringify({ catalog: [...real.values()], names, lines: LINES, commands: COMMANDS, onHit: ON_HIT, queries: QUERIES, texts: TEXTS, addrs: ADDRS, outputs: OUTPUTS, json: JSON_TEXTS, long: LONG }));
		const run = Bun.spawnSync(["sbcl", "--non-interactive", "--load", join(ROOT, "test", "nodecode", "parity.lisp"), input, output], { stdout: "pipe", stderr: "pipe" });
		if (run.exitCode !== 0) console.error(run.stdout.toString().slice(-3000), run.stderr.toString().slice(-3000));
		expect(run.exitCode).toBe(0);
		lisp = JSON.parse(readFileSync(output, "utf8")) as Record<string, unknown[]>;
		rmDirSafe(dir);
	}, 300_000);

	test("which command names rizin_command runs", () => {
		const mine = names.map((name) => isRunnable(name));
		const disagreements = names.filter((_, i) => mine[i] !== lisp.runnable![i]);
		expect(disagreements).toEqual([]);
		expect(names.length).toBeGreaterThan(400);
	});

	test("forbidden syntax, and the words that name it", () => {
		expect(lisp.forbidden).toEqual(LINES.map((line) => forbiddenSyntaxReason(line) ?? null));
	});

	test("the command check: the exact line sent to rizin, or the exact refusal", () => {
		// A bad `addr` throws from validateAddr rather than returning a refusal; either way it is a refusal with the same words.
		const mine = COMMANDS.map((c) =>
			answer(() => {
				const check = checkRizinCommand(catalog, c.command, c.addr);
				return check.ok ? { line: check.line, name: check.name } : { error: check.reason };
			}),
		);
		expect(lisp.check).toEqual(mine);
	});

	test("the breakpoint on-hit command check", () => {
		const mine = ON_HIT.map((command) => {
			const check = checkDebugOnHitCommand(catalog, command);
			return check.ok ? { line: check.line } : { error: check.reason };
		});
		expect(lisp.onHit).toEqual(mine);
	});

	test("rizin_help: the header and every line", () => {
		expect(lisp.help).toEqual(QUERIES.map((query) => searchCatalog(catalog, query)));
	});

	test("quoting and the validators", () => {
		expect(lisp.quote).toEqual(TEXTS.map((text) => answer(() => rzQuote(text))));
		expect(lisp.typeLike).toEqual(TEXTS.map((text) => answer(() => validateTypeLike("type", text))));
		expect(lisp.addr).toEqual(ADDRS.map((text) => answer(() => validateAddr(text))));
		expect(lisp.ident).toEqual(ADDRS.map((text) => answer(() => validateIdent("name", text))));
		expect(lisp.normalize).toEqual(ADDRS.map(normalizeAddr));
	});

	test("the canonical projection and the hashes evidence is verified by", () => {
		const binary = "/tmp/sample bin";
		expect(lisp.canonical).toEqual(OUTPUTS.map((text) => canonicalizeRizinOutput(text, binary)));
		expect(lisp.canonicalHash).toEqual(OUTPUTS.map((text) => canonicalHash(text, binary)));
		expect(lisp.shiftHash).toEqual(OUTPUTS.map((text) => shiftHash(text, binary)));
		expect(lisp.excerpt).toEqual(OUTPUTS.map((text) => canonicalExcerpt(text, binary)));
		expect(lisp.sha256).toEqual(OUTPUTS.map((text) => createHash("sha256").update(text, "utf8").digest("hex")));
		expect(lisp.hmac).toEqual(OUTPUTS.map((text) => createHmac("sha256", "audit key").update(text).digest("base64")));
	});

	test("JSON as it is written to records, and as it is shown to the model", () => {
		expect(lisp.json).toEqual(JSON_TEXTS.map((text) => JSON.stringify(JSON.parse(text))));
		expect(lisp.formatJson).toEqual(JSON_TEXTS.map((text) => formatJson(JSON.parse(text))));
	});

	test("truncation: the same lines kept and the same note", async () => {
		// No session on either side, so neither can spill an artifact: the note is the plain one.
		const mine = await Promise.all(LONG.map(async (text) => (await textResult("head", text)).content.map((block) => (block.type === "text" ? block.text : "")).join("")));
		expect(lisp.truncate).toEqual(mine);
	});
});
