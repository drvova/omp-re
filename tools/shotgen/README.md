# omp-re shotgen

Renders real `omp-re` TUI captures to PNG for `README.md` and the GitHub release body. Standalone dev tool, isolated from the plugin's own `package.json`/`bun.lock` — never referenced from the root manifest.

## Regenerating the screenshots

```bash
bun install --ignore-scripts
bash capture.sh            # FIXTURE defaults to /bin/ls
bun render.ts
```

The committed `docs/img/*.png` are real captures of `/bin/ls` — it exists on every Linux box, so anyone can reproduce them without a malware fixture. Rerunning the steps here regenerates them against your rizin install. The functions panel ranks matches with omp's fuzzy matcher (best first), so filtering for `main` puts the real `main` on top; `DECOMPILE_DOWN` exists only for a fixture whose target isn't the best match.

Then, with an agent that has the `browser` tool, open each `out/<scene>.html` and screenshot the `#shot` element. Measured fact: the capture path emits **1024px-wide** PNGs regardless of the requested viewport/scale (1040px viewport / `scale: 2` requested, 1024px delivered) — target roughly that width for a visual match with any headless-Chrome equivalent. Save the result to `../../docs/img/<scene>.png`.

`capture.sh` requires tmux, `omp`, a real rizin (`OMPRE_RIZIN_PATH` if it isn't on PATH), and a fixture binary (`FIXTURE`, default `/bin/ls`). Set `DECOMPILE_FN` and `REPORT_ADDR` together when using a different fixture. With rz-ghidra installed the decompile scene shows typed C; without it, the labeled disassembly fallback — both are truthful captures.

`out/` is intermediate output — ANSI captures and rendered HTML — and is git-ignored. Only the final PNGs under `docs/img/` are committed.

Any headless-Chrome equivalent (Puppeteer, Playwright, `chrome --headless=new --screenshot`) works in place of the `browser` tool for the last step; this repo does not add one as a dependency since screenshotting is a one-off dev task, not something the plugin itself needs at runtime.
