# Contributing

## Setup

```bash
bun install --ignore-scripts
```

`--ignore-scripts` matters: don't run lifecycle scripts from dependencies
without reviewing them first.

You also need SBCL, cl-ppcre and rizin: the engine is Common Lisp, and every
test starts it. `sudo apt install sbcl cl-ppcre` on Debian and Ubuntu; on a
Linux box without a current rizin package, `scripts/install-rizin.sh` builds
rizin 0.9.1 and rz-ghidra. See [`docs/install.md`](docs/install.md).

## Where things are

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) has the shape and a table of
where a typical change lands. In short: behaviour lives in `engine/` (Common
Lisp), and is tested by the Lisp suite. `extensions/re/` is a shim: it
registers nothing a model calls, passes on what a cell of omp's `eval` asks,
and draws what the engine sends. A new tool or line needs no TypeScript and
no change to the libraries in `skills/re-triage/`.

## Before opening a PR

```bash
bun run check          # tsc-ts (native TypeScript 7 build) --noEmit — must exit 0
                       # (bun run check:tsc runs the stock tsc as a fallback)
bun run check:warnings # the three Lisp systems compile from scratch with no warning
bun run test:engine    # the Lisp suite: the engine and both hosts' Lisp
bun test test/         # the extension through omp's SDK, the engine behind it
bun run check:recipes  # the recipes' generated blocks are current
bun run check:api      # the verbs' generated blocks and nodecode's verb-forms.lisp are current
bun run check:protocol # the shim's types and the protocol page's tables are current
bun run cover:engine   # the Lisp suite again under sb-cover: what it does not run
```

CI runs all of these on Linux with rizin installed. One tier is manual:
`bash test/live-model.sh` drives a real `omp` with a real model. Nothing
drives a real omp terminal; see [`docs/testing.md`](docs/testing.md) for what
each tier needs and what none of them proves.

A tool is declared once, with `define-tool` in `engine/`: its parameters,
what it does, whether a result is evidence. Both hosts reach it through the
`call` verb and list it from the declaration; nothing else changes.

The verbs the model calls from eval — `open`, `cmd`, `json`, `call`, `tools`,
`doc`, `slash`, `status` — are described once, in `recipes/api.json`. To
change one, change it there and run `bun run gen:api`, which rewrites the
marked blocks of `skills/re-triage/recipes.js` and `recipes.py` and the whole
of `nodecode/verb-forms.lisp`. Never edit those by hand, and never give one
host a verb the others lack without saying so in the description (`hosts`).

A function a host may call is exported from `engine/package.lisp` and
declared, beside its definition, in the types of `engine/types.lisp`
(`declaim ftype`); one that must never signal is made with `define-surface`.
`bun run check:warnings` is what holds callers to those types: a compiler
warning or style warning anywhere in the three systems fails it, and the fix
is the code, not a muffled warning. The engine's package is locked: a host
or a test that needs the engine to behave otherwise answers a service of
the port (`with-host-service`), it does not define into `omp-re`.

`bun run cover:engine` prints, after the table, every definition no part of
which the suite ran. A new one on that list wants a check, or a reason.

Every rizin command a tool sends is built from values that went through
`validate-addr`, `validate-ident` or `rz-quote` (`engine/util.lisp`);
annotation commands are built only by `annotation-commands`
(`engine/annotate.lisp`), which the forward tools, the line `undo` and replay
all share. Keep it that way.

The messages between omp and the engine are described once, in
`stdio/protocol.json`. To change one, change it there and run
`bun run gen:protocol`, which rewrites `extensions/re/protocol.ts` and the
tables of [`docs/engine-protocol.md`](docs/engine-protocol.md); the type check
then points at every use in the shim, and the Lisp server refuses at load a
method it has no handler for. Update the page's prose in the same commit. When
you change `recipes/tables.json`, run `bun run gen:recipes` and commit what it
writes.

What the plugin stands on in omp's `eval` — that a kernel is a child process
of omp's, what it is told of its session, that a cell's timeout hangs up its
connection — is in no documentation of omp's. [`docs/omp-eval.md`](docs/omp-eval.md)
writes it down from omp's source and `test/omp-eval-contract.test.ts` pins
each claim against the installed omp. When you come to rely on one more such
fact, add it to both.

## Versioning and releases

The version is **not** hand-edited. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/), and on every
merge to `main` the `Release` workflow (`.github/workflows/release.yml`, via
`scripts/release.mjs`) picks the bump from the commits that landed, writes
the one version to `package.json`, `.omp-plugin/marketplace.json` and the
three `.asd` files, stamps a dated section in `CHANGELOG.md`, commits
`chore(release): vX.Y.Z`, and tags it. `bun run check:versions` (a CI step)
fails when those five files disagree.

| Commit | Bump |
| --- | --- |
| `feat: …` | minor |
| `feat!: …` / any `!` / any `BREAKING CHANGE:` footer | major (capped to **minor** while the version is still `0.x`) |
| anything else (`fix:`, `perf:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, `style:`, `build:`, or no prefix) | patch |
| `chore(release): …` | none — the workflow's own commit |

The highest level across the merged commits wins, so every merge to `main`
ships a version. Keep the
`## [Unreleased]` section of `CHANGELOG.md` current as you work — the workflow
only renames it to the new version and date, it does not write your entries.
Preview a range locally without changing anything:

```bash
node scripts/release.mjs <baseRef> <headRef> --dry-run
```

## Style

- No emojis in commits, code, or PR descriptions.
- Keep PR descriptions technical and direct — what changed and why, not
  marketing language.
- Match the file's existing patterns before introducing a new one; this
  project has a strict "one canonical way to do X" convention throughout
  (see e.g. the single `find-by-id` lookup in `engine/evidence.lisp` that
  the lines `evidence` and `cite` and the findings tools share).
- Comments and docs say why, or how to operate; they do not restate the code.
  A list that mirrors `ls` rots.
