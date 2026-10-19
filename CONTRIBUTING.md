# Contributing

## Setup

```bash
bun install --ignore-scripts
```

`--ignore-scripts` matters: don't run lifecycle scripts from dependencies without reviewing them first.

## Before opening a PR

```bash
bun run check      # tsc-ts (native TypeScript 7 build) --noEmit — must exit 0
                    # (bun run check:tsc runs the stock tsc as a fallback)
bun run fix        # Ultracite: Oxfmt formatting + Oxlint safe fixes
bunx ultracite check  # Oxlint (Ultracite core preset) + Oxfmt check — must exit 0;
                    # fix findings rather than disabling rules
bun test           # unit + integration tests; the rizin suites run against
                    # /bin/ls when rizin is on PATH and skip otherwise —
                    # see docs/testing.md
bash test/tui.sh   # fast tmux smoke test, ~30s
bun run qa:tui     # full tmux QA pass, 99 assertions
```

The website ([drvova.github.io/omp-re](https://drvova.github.io/omp-re/)) is generated from `README.md` and `docs/` by the Rust crate in `site/` and deployed from `main` by `.github/workflows/pages.yml`. Preview it with `cargo run --manifest-path site/Cargo.toml` and open `site/dist/index.html`; add a new doc page to `PAGES` in `site/src/main.rs`.

Run `bun test` with rizin installed before opening a PR that touches `extensions/re/` — CI cannot run the rizin suites. The last two need tmux, `omp`, rizin, a fixture (`OMPRE_TEST_BINARY`), and for `qa:tui` a working model. See [`docs/testing.md`](docs/testing.md) for what each tier actually needs and the exact PASS/SKIP matrix.

Declare each tool's parameter schema as a named `const` before `pi.registerTool({...})`, never inline: omp 18's `pi.zod` builder only lets TypeScript infer `params` from a schema declared outside the call. Give every tool both renderer pairs via `reRenderers(...)` (`renderCall`/`renderResult` for the ANSI transcript, `describeCall`/`describeResult` for Tern).

Every rizin command an RE tool sends goes through `validateAddr`, `validateIdent`, or `rzQuote` (`extensions/re/rizin.ts`); annotation commands are built only by `annotationCommands` (`extensions/re/annotations.ts`), which the forward tools, `/re undo`, and replay all share. Keep it that way.

## Two hard rules `test/tui-qa.sh` depends on

1. **The assertion-count drift guard.** `test/tui-qa.sh` pins its own total assertion count in a literal near the end of the script (currently `-eq 99`). Any PR that adds or removes an assertion **must** update that literal in the same commit — the guard exists specifically to catch a silent count drift (e.g. a model-outage skip cascade) that would otherwise still exit 0.
2. **Every conditional assertion needs a `skip` mirror on every other branch it could take.** If an assertion only runs inside an `if [ -n "$SOME_ID" ]` block, the corresponding `else` branch (and any outer failure branch) must call `skip '<same assertion name>' '<reason>'` — otherwise the total assertion count differs between branches, and the drift guard fails a run that is actually healthy.

## Versioning and releases

The version is **not** hand-edited. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), and on every merge to `main` the `Release` workflow (`.github/workflows/release.yml`, via `scripts/release.mjs`) picks the bump from the commits that landed, updates `package.json` and `.omp-plugin/marketplace.json` together, stamps a dated section in `CHANGELOG.md`, commits `chore(release): vX.Y.Z`, and tags it.

| Commit | Bump |
| --- | --- |
| `feat: …` | minor |
| `fix: …`, `perf: …` | patch |
| `feat!: …` / any `BREAKING CHANGE:` footer | major (capped to **minor** while the version is still `0.x`) |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, `style:`, `build:` | none — no release on their own |

The highest level across the merged commits wins; a push with no release-worthy commits leaves the version untouched. Keep the `## [Unreleased]` section of `CHANGELOG.md` current as you work — the workflow only renames it to the new version and date, it does not write your entries. Preview a range locally without changing anything:

```bash
node scripts/release.mjs <baseRef> <headRef> --dry-run
```

## Style

- No emojis in commits, code, or PR descriptions.
- Keep PR descriptions technical and direct — what changed and why, not marketing language.
- Match the file's existing patterns before introducing a new one; this project has a strict "one canonical way to do X" convention throughout (see e.g. the single `findEvidence` prefix-match lookup shared by `/re evidence` and `/re cite`).
