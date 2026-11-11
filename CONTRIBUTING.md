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
Lisp), and is tested by the Lisp suite. `extensions/re/` is a shim that
registers what the engine describes and draws what it sends; a new tool or
`/re` subcommand needs no TypeScript.

## Before opening a PR

```bash
bun run check          # tsc-ts (native TypeScript 7 build) --noEmit — must exit 0
                       # (bun run check:tsc runs the stock tsc as a fallback)
bun run test:engine    # the Lisp suite: the engine and both hosts' Lisp
bun test test/         # the extension through omp's SDK, the engine behind it
bun run check:recipes  # the recipes' generated blocks are current
bun run check:protocol # the shim's types and the protocol page's tables are current
bash test/tui.sh       # fast tmux smoke test
bun run qa:tui         # full tmux QA pass
```

CI runs the first five on Linux with rizin installed. The last two are manual
tiers: they need tmux, `omp`, a test binary (`/bin/ls` unless
`OMPRE_TEST_BINARY` names another), and for `qa:tui` a working model; no
workflow runs them, so run them yourself when you change what the terminal
shows. See [`docs/testing.md`](docs/testing.md) for what each tier needs and
what none of them proves.

A tool is declared once, with `define-tool` in `engine/`: its parameters, its
approval tier, the sentence its approval prompt shows (`:reason`) and how a
transcript draws its result (`:render`). Give a new tool all four; the omp
shim and the nodecode verbs read the declaration and need no change.

Every rizin command a tool sends is built from values that went through
`validate-addr`, `validate-ident` or `rz-quote` (`engine/util.lisp`);
annotation commands are built only by `annotation-commands`
(`engine/annotate.lisp`), which the forward tools, `/re undo` and replay all
share. Keep it that way.

The messages between omp and the engine are described once, in
`stdio/protocol.json`. To change one, change it there and run
`bun run gen:protocol`, which rewrites `extensions/re/protocol.ts` and the
tables of [`docs/engine-protocol.md`](docs/engine-protocol.md); the type check
then points at every use in the shim, and the Lisp server refuses at load a
method it has no handler for. Update the page's prose in the same commit. When
you change `recipes/tables.json`, run `bun run gen:recipes` and commit what it
writes.

## Two hard rules `test/tui-qa.sh` depends on

1. **The assertion-count drift guard.** `test/tui-qa.sh` pins its own total
   assertion count in a literal near the end of the script (currently `-eq
   100`). Any PR that adds or removes an assertion **must** update that
   literal in the same commit — the guard exists to catch a branch that
   forgot to report an assertion and would otherwise still exit 0.
2. **Every conditional assertion needs a mirror on every other branch it
   could take.** If an assertion only runs inside an `if [ -n "$SOME_ID" ]`
   block, the corresponding `else` branch (and any outer failure branch)
   must report the same assertion: `fail '<same assertion name> (<why>)'`
   when the thing it tests should have been there — a model turn that did
   not finish is a failure, not a skip — and `skip '<same assertion name>'
   '<reason>'` only when the fixture has nothing to show it on. Otherwise
   the total differs between branches and the drift guard fails a healthy
   run.

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
  `/re evidence`, `/re cite` and the findings tools share).
- Comments and docs say why, or how to operate; they do not restate the code.
  A list that mirrors `ls` rots.
