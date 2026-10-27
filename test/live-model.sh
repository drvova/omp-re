#!/usr/bin/env bash
# Live-model test of the findings loop: the half no deterministic test reaches.
#
# A real model, driving real omp (print mode) with the extension loaded, on two
# builds of the sample fixture (v2 renames `fib`, changes `checksum`'s multiplier):
#
#   A. on v1: the model reads sym.checksum and sym.fib with rizin_command, records
#      a finding for each citing the `[evidence xxxxxxxx]` tags, then attempts an
#      overreaching claim — the support auditor should refuse it. /re report.
#   B. on v2, fresh session: /re carry <v1 manifest> --resolve — the holding
#      finding is re-proven and recorded. Headless, a command cannot start a
#      model turn, so --resolve prints the agenda (the drifted checksum finding
#      with its diff) instead of sending it.
#   C. same session continued: the agenda goes to the model as a prompt, and
#      the model should revise the drifted finding; then /re report on v2.
#
# Asserts only on recorded state (session entries, report files), never on model
# prose. Model choice: OMPRE_LIVE_MODEL (default minimax-code/MiniMax-M3, which
# reads MINIMAX_CODE_API_KEY). Skips (exit 0) without a key, omp, rizin, bun or
# a C compiler. Costs real tokens; not run in CI.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL="${OMPRE_LIVE_MODEL:-minimax-code/MiniMax-M3}"
FAIL=0
log() { printf '%s\n' "$*"; }
pass() { log "PASS: $*"; }
fail() {
	log "FAIL: $*"
	FAIL=1
}

if [ -z "${OMPRE_LIVE_MODEL:-}" ] && [ -z "${MINIMAX_CODE_API_KEY:-}" ]; then
	log "SKIP: set MINIMAX_CODE_API_KEY (or OMPRE_LIVE_MODEL plus that provider's key)"
	exit 0
fi
for tool in omp bun "${OMPRE_RIZIN_PATH:-rizin}"; do
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

WORK="${OMPRE_LIVE_WORKDIR:-$(mktemp -d)}"
mkdir -p "$WORK"
log "workdir: $WORK (logs: a.log b.log c.log)"
cp "$REPO_DIR/test/fixtures/sample.c" "$WORK/v1.c"
sed -e 's/h \* 33u/h * 31u/' -e 's/\bfib\b/fibonacci/g' "$REPO_DIR/test/fixtures/sample.c" >"$WORK/v2.c"
"$CC" -O0 -o "$WORK/v1" "$WORK/v1.c" && "$CC" -O0 -o "$WORK/v2" "$WORK/v2.c" || {
	fail "compiling the fixtures"
	exit 1
}

# stdin from /dev/null on every call: with a non-terminal stdin, omp -p waits to read a piped prompt.
OMP=(omp -e "$REPO_DIR/extensions/re" --model "$MODEL" --approval-mode yolo)

# --- A: analyse v1, record findings, try an overreach, write the report -------
PROMPT_A="You are reverse engineering the open binary with the omp-re tools. Work only with tools; keep prose short.
1. Call rizin_command with command \"pdf\" and addr \"sym.checksum\". Work out exactly what the function computes.
2. Call record_finding with that conclusion (addr sym.checksum, confidence confirmed), citing the 8-character id from the [evidence ...] tag at the end of that tool result.
3. Do the same for sym.fib: rizin_command pdf @ sym.fib, then record_finding.
4. Then call record_finding once more with exactly this claim, citing the checksum evidence: \"checksum authenticates the program's network traffic to a C2 server.\" Do not override the auditor if it refuses. Report what the tool answered."
rm -rf "$WORK/s1" "$WORK/s2" "$WORK"/v1.md* "$WORK"/v2.md*
timeout 900 "${OMP[@]}" --binary "$WORK/v1" --session-dir "$WORK/s1" -p "$PROMPT_A" "/re report $WORK/v1.md" </dev/null >"$WORK/a.log" 2>&1
log "phase A exit: $?"

S1="$(ls -t "$WORK"/s1/*.jsonl 2>/dev/null | head -1)"
if [ -n "$S1" ] && [ -f "$WORK/v1.md.manifest.json" ]; then
	pass "phase A wrote the v1 report and manifest"
else
	fail "phase A: no session file or manifest (see a.log)"
fi
# grep -c prints 0 AND exits 1 on no match, so never chain it with `|| echo 0`.
count() {
	local n=0
	[ -n "$2" ] && [ -f "$2" ] && n="$(grep -c -- "$1" "$2" 2>/dev/null)"
	echo "${n:-0}"
}
FINDINGS_A="$(count '"customType":"re.finding"' "$S1")"
[ "$FINDINGS_A" -ge 2 ] && pass "model recorded $FINDINGS_A finding(s) on v1" || fail "model recorded $FINDINGS_A finding(s) on v1 (want >= 2)"
if [ "$FINDINGS_A" -eq 0 ]; then
	log "NOTE: overreach check skipped — no findings were recorded at all"
elif grep -q '"customType":"re.finding".*C2 server' "$S1"; then
	fail "the overreaching C2 claim was recorded"
else
	pass "the overreaching C2 claim was not recorded"
fi
grep -q "NOT recorded — the support auditor" "$S1" 2>/dev/null && pass "the auditor refused something with a reason" || log "NOTE: no auditor refusal in the transcript (auditor unavailable, or the model skipped step 4)"
grep -q "## Findings" "$WORK/v1.md" 2>/dev/null && pass "v1 report has a Findings section" || fail "v1 report Findings section"

# --- B: carry onto v2 with --resolve -----------------------------------------
timeout 900 "${OMP[@]}" --binary "$WORK/v2" --session-dir "$WORK/s2" -p "/re carry $WORK/v1.md.manifest.json --resolve" </dev/null >"$WORK/b.log" 2>&1
log "phase B exit: $?"
grep -q "inherit: [1-9][0-9]* finding(s) re-proven" "$WORK/b.log" && pass "carry --resolve re-proved finding(s) on v2" || fail "no inherit summary (see b.log)"
# The agenda is everything from its opening line to the end of b.log.
AGENDA="$(sed -n '/^These findings from the earlier report do not carry over unchanged/,$p' "$WORK/b.log")"
[ -n "$AGENDA" ] && pass "carry --resolve printed the agenda for the next prompt" || log "NOTE: no agenda printed (no finding drifted?)"

# --- C: resolve the agenda, then write the v2 report, in the same session ------
if [ -n "$AGENDA" ]; then
	timeout 900 "${OMP[@]}" --binary "$WORK/v2" --session-dir "$WORK/s2" -c -p "$AGENDA" "/re report $WORK/v2.md" </dev/null >"$WORK/c.log" 2>&1
else
	timeout 600 "${OMP[@]}" --binary "$WORK/v2" --session-dir "$WORK/s2" -c -p "/re report $WORK/v2.md" </dev/null >"$WORK/c.log" 2>&1
fi
log "phase C exit: $?"
S2="$(ls -t "$WORK"/s2/*.jsonl 2>/dev/null | head -1)"
grep -q "re-verified on this build" "$WORK/v2.md" 2>/dev/null && pass "v2 report carries inherited finding(s)" || fail "v2 report has no inherited finding"
FINDINGS_B="$(count '"customType":"re.finding"' "$S2")"
INHERITED_B="$(count '"customType":"re.finding".*"inherited"' "$S2")"
log "v2 session: $FINDINGS_B finding entr(ies), $INHERITED_B inherited — $((FINDINGS_B - INHERITED_B)) recorded by the model while resolving the agenda"

[ "$FAIL" -eq 0 ] && log "live-model: ALL PASS" || log "live-model: FAILURES"
exit "$FAIL"
