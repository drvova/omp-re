#!/usr/bin/env bash
# End-to-end check of /re carry --inherit in a real omp TUI under tmux.
#
# Builds two versions of the sample fixture (v2 renames `fib` and changes
# `checksum`'s multiplier), records three findings on v1 with
# test/e2e/make-carry-manifest.ts (real rizin evidence, no model), then
# starts omp on v2 with the extension loaded explicitly (-e) and drives
# the slash commands a user would type. It checks that two findings are
# re-proven (one relocated), that the drifted one lands in the editor as
# an agenda, that the status band and /re status count the inherited
# findings, and that the v2 report carries them with provenance.
#
# No model round-trip: every assertion is on a rendered notify, the band,
# or a written file. Skips (exit 0) when tmux, rizin, a C compiler, or omp
# is missing.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SESSION="ompre-carry-e2e"
FAIL=0
log() { printf '%s\n' "$*"; }
pass() { log "PASS: $*"; }
fail() {
	log "FAIL: $*"
	FAIL=1
}

for tool in tmux "${OMPRE_RIZIN_PATH:-rizin}" omp bun; do
	command -v "$tool" >/dev/null 2>&1 || {
		log "SKIP: $tool not found on PATH"
		exit 0
	}
done
CC="$(command -v cc || command -v gcc || command -v clang || true)"
[ -n "$CC" ] || {
	log "SKIP: no C compiler"
	exit 0
}

WORK="$(mktemp -d)"
cleanup() {
	tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
tmux kill-session -t "$SESSION" >/dev/null 2>&1 || true

# --- fixtures ----------------------------------------------------------------
cp "$REPO_DIR/test/fixtures/sample.c" "$WORK/v1.c"
sed -e 's/h \* 33u/h * 31u/' -e 's/\bfib\b/fibonacci/g' "$REPO_DIR/test/fixtures/sample.c" >"$WORK/v2.c"
"$CC" -O0 -o "$WORK/v1" "$WORK/v1.c" && "$CC" -O0 -o "$WORK/v2" "$WORK/v2.c" || {
	fail "compiling the fixtures"
	exit 1
}
(cd "$REPO_DIR" && bun test/e2e/make-carry-manifest.ts "$WORK/v1" "$WORK/v1.md") >/dev/null || {
	fail "recording the v1 findings"
	exit 1
}
MANIFEST="$WORK/v1.md.manifest.json"
REPORT="$WORK/v2.md"

# --- launch --------------------------------------------------------------------
tmux new-session -d -s "$SESSION" -x 200 -y 60 -c "$REPO_DIR"
tmux send-keys -t "$SESSION" "omp -e '$REPO_DIR/extensions/re' --binary '$WORK/v2' --approval-mode yolo --no-session" Enter

pane() { tmux capture-pane -t "$SESSION" -p -S -200; }
wait_for() {
	local i
	for ((i = 0; i < ${2:-20}; i++)); do
		pane | grep -Eq -- "$1" && return 0
		# A fresh profile opens omp's setup wizard first; skip it (no provider is needed here).
		pane | grep -q "Setup step" && tmux send-keys -t "$SESSION" Escape
		sleep 1
	done
	return 1
}

wait_for "\\[re: opened .*v2\\]" 240 || fail "readiness: binary-opened announcement never rendered"
wait_for '[1-9][0-9]* fn · 0 findings' 60 && pass "band starts at 0 findings" || fail "band at start"

READY=0
for _ in $(seq 1 8); do
	tmux send-keys -t "$SESSION" C-u
	sleep 1
	tmux send-keys -t "$SESSION" "/re findings" Enter
	if wait_for "no findings on this branch yet" 10; then
		READY=1
		break
	fi
done
[ "$READY" -eq 1 ] && pass "/re findings answers (empty)" || fail "/re findings never answered"

# --- carry --inherit ----------------------------------------------------------
tmux send-keys -t "$SESSION" C-u
sleep 1
tmux send-keys -t "$SESSION" "/re carry $MANIFEST --inherit" Enter
wait_for "inherit: 2 finding\\(s\\) re-proven" 90 && pass "two findings re-proven" || fail "inherit summary never rendered"
wait_for "1 hold, 1 relocated, 1 drifted, 0 BROKEN" 5 && pass "carry statuses: hold / relocated / drifted" || fail "carry statuses"
wait_for "These findings from the earlier report" 10 && pass "agenda placed in the editor" || fail "agenda not in the editor"
wait_for "\\+ .*sub   eax, edx" 5 && pass "agenda carries the checksum diff" || fail "agenda diff"
wait_for '[1-9][0-9]* fn · 2 findings' 20 && pass "band refreshed to 2 findings" || fail "band not refreshed"

# Clear the multi-line agenda from the editor before the next command.
for _ in $(seq 1 40); do
	tmux send-keys -t "$SESSION" C-u
	tmux send-keys -t "$SESSION" BSpace
done
sleep 1
tmux send-keys -t "$SESSION" "/re status" Enter
wait_for "findings on this branch: 2 \\(2 inherited\\)" 20 && pass "/re status counts inherited findings" || fail "/re status"

tmux send-keys -t "$SESSION" C-u
sleep 1
tmux send-keys -t "$SESSION" "/re report $REPORT --no-audit" Enter
for _ in $(seq 1 30); do
	[ -f "$REPORT" ] && break
	sleep 1
done
if [ -f "$REPORT" ] && grep -q "## Findings" "$REPORT" && grep -q "re-verified on this build (relocated: sym.fib" "$REPORT" && ! grep -q "checksum is a djb2" "$REPORT"; then
	pass "v2 report: inherited findings with provenance; the drifted one left out"
else
	fail "v2 report contents"
fi

[ "$FAIL" -eq 0 ] && log "tui-carry: ALL PASS" || log "tui-carry: FAILURES"
exit "$FAIL"
