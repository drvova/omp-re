# Contributing

## Setup

```bash
bun install --ignore-scripts
```

`--ignore-scripts` matters: don't run lifecycle scripts from dependencies
without reviewing them first.

## Before opening a PR

```bash
bun run check      # tsc --noEmit — must exit 0
bun test           # unit + integration tests; the rizin suites run against
                    # /bin/ls when rizin is on PATH and skip otherwise —
                    # see docs/testing.md
bash test/tui.sh   # fast tmux smoke test, ~30s
bun run qa:tui     # full tmux QA pass, 99 assertions
```

Run `bun test` with rizin installed before opening a PR that touches
`extensions/re/` — CI cannot run the rizin suites. The last two need tmux,
`omp`, rizin, a fixture (`OMPRE_TEST_BINARY`), and for `qa:tui` a working
model. See [`docs/testing.md`](docs/testing.md) for what each tier actually
needs and the exact PASS/SKIP matrix.

Every rizin command an RE tool sends goes through `validateAddr`,
`validateIdent`, or `rzQuote` (`extensions/re/rizin.ts`); annotation commands
are built only by `annotationCommands` (`extensions/re/annotations.ts`),
which the forward tools, `/re undo`, and replay all share. Keep it that way.

## Two hard rules `test/tui-qa.sh` depends on

1. **The assertion-count drift guard.** `test/tui-qa.sh` pins its own total
   assertion count in a literal near the end of the script (currently `-eq
   99`). Any PR that adds or removes an assertion **must** update that
   literal in the same commit — the guard exists specifically to catch a
   silent count drift (e.g. a model-outage skip cascade) that would
   otherwise still exit 0.
2. **Every conditional assertion needs a `skip` mirror on every other branch
   it could take.** If an assertion only runs inside an `if [ -n "$SOME_ID"
   ]` block, the corresponding `else` branch (and any outer failure branch)
   must call `skip '<same assertion name>' '<reason>'` — otherwise the total
   assertion count differs between branches, and the drift guard fails a
   run that is actually healthy.

## Style

- No emojis in commits, code, or PR descriptions.
- Keep PR descriptions technical and direct — what changed and why, not
  marketing language.
- Match the file's existing patterns before introducing a new one; this
  project has a strict "one canonical way to do X" convention throughout
  (see e.g. the single `findEvidence` prefix-match lookup shared by `/re
  evidence` and `/re cite`).
