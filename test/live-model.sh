#!/usr/bin/env bash
# Live-model test of the findings loop: the half no deterministic test reaches.
#
# A real model, driving real omp (print mode) with the plugin loaded, on two
# builds of the sample fixture (v2 renames `fib`, changes `checksum`'s multiplier).
# The plugin registers no tool and no command, so everything the model does it
# does in omp's eval, through the library of the re-triage skill:
#
#   A. on v1: the model loads the library, opens the binary, reads sym.checksum
#      and sym.fib, records a finding for each citing the evidence ids, then
#      attempts an overreaching claim — the support auditor should refuse it —
#      and writes the report (the line `report <path>`).
#   B. on v2, fresh session: the model opens the new build, carries v1's
#      manifest onto it with --inherit — the holding finding is re-proven and
#      recorded, and the agenda of what drifted comes back to it under the
#      summary — revises the drifted finding, and writes the v2 report.
#
# Asserts only on recorded state (session entries, report files), never on model
# prose. The model is the caller's to name: OMPRE_LIVE_MODEL, in the form omp's
# --model takes (<provider>/<model>), with that provider's key in the
# environment as omp reads it. There is no default: without it this exits 2.
# Skips (exit 0) without omp, rizin, sbcl or a C compiler. Costs real tokens;
# a manual tier, run in no workflow.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL="${OMPRE_LIVE_MODEL:-}"
FAIL=0
log() { printf '%s\n' "$*"; }
pass() { log "PASS: $*"; }
fail() {
	log "FAIL: $*"
	FAIL=1
}

if [ -z "$MODEL" ]; then
	log "live-model: set OMPRE_LIVE_MODEL to the model to drive, as omp's --model takes it (<provider>/<model>), and that provider's API key. This tier calls a real model and names none itself."
	exit 2
fi
for tool in omp "${OMPRE_SBCL_PATH:-sbcl}" "${OMPRE_RIZIN_PATH:-rizin}"; do
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
log "workdir: $WORK (logs: a.log b.log)"
cp "$REPO_DIR/test/fixtures/sample.c" "$WORK/v1.c"
sed -e 's/h \* 33u/h * 31u/' -e 's/\bfib\b/fibonacci/g' "$REPO_DIR/test/fixtures/sample.c" >"$WORK/v2.c"
"$CC" -O0 -o "$WORK/v1" "$WORK/v1.c" && "$CC" -O0 -o "$WORK/v2" "$WORK/v2.c" || {
	fail "compiling the fixtures"
	exit 1
}

# stdin from /dev/null on every call: with a non-terminal stdin, omp -p waits to read a piped prompt.
# The plugin is loaded from its root, as README.md says a checkout is, so omp finds the skill beside the extension.
OMP=(omp -e "$REPO_DIR" --model "$MODEL" --approval-mode yolo)
LIBRARY="$REPO_DIR/skills/re-triage/recipes.js"

# --- A: analyse v1, record findings, try an overreach, write the report -------
PROMPT_A="You are reverse engineering one binary with omp-re. Everything goes through the eval tool, in JavaScript cells; keep prose short.
0. Run a cell that holds only this line: %load $LIBRARY
   Then, in a cell with timeout 300: await re.open(\"$WORK/v1\")
1. print(await re.cmd(\"pdf\", \"sym.checksum\")). Work out exactly what the function computes.
2. Record that conclusion: await re.call(\"record_finding\", { claim, evidence: [id], addr: \"sym.checksum\", confidence: \"confirmed\" }), id being the 8 characters of the [evidence ...] tag that ended the read.
3. Do the same for sym.fib: re.cmd pdf at sym.fib, then record_finding.
4. Then call record_finding once more with exactly this claim, citing the checksum evidence: \"checksum authenticates the program's network traffic to a C2 server.\" Do not override the auditor if it refuses. Say what the call answered.
5. Last: print(await re.slash(\"report $WORK/v1.md\"))"
rm -rf "$WORK/s1" "$WORK/s2" "$WORK"/v1.md* "$WORK"/v2.md*
timeout 900 "${OMP[@]}" --session-dir "$WORK/s1" -p "$PROMPT_A" </dev/null >"$WORK/a.log" 2>&1
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

# --- B: carry onto v2, resolve the agenda, write the v2 report ---------------
PROMPT_B="You are carrying an earlier report onto a new build of the same program with omp-re. Everything goes through the eval tool, in JavaScript cells; keep prose short.
0. Run a cell that holds only this line: %load $LIBRARY
   Then, in a cell with timeout 300: await re.open(\"$WORK/v2\")
1. print(await re.slash(\"carry $WORK/v1.md.manifest.json --inherit\")). It answers what holds here, and under that an agenda of findings that no longer hold as written.
2. Work through the agenda: read what it names on this build, and for each finding record the revised claim with record_finding (supersedes, where it says so) or leave it out if it is no longer true.
3. Last: print(await re.slash(\"report $WORK/v2.md\"))"
timeout 900 "${OMP[@]}" --session-dir "$WORK/s2" -p "$PROMPT_B" </dev/null >"$WORK/b.log" 2>&1
log "phase B exit: $?"
S2="$(ls -t "$WORK"/s2/*.jsonl 2>/dev/null | head -1)"
grep -q "inherit: [1-9][0-9]* finding(s) re-proven" "$S2" 2>/dev/null && pass "carry --inherit re-proved finding(s) on v2" || fail "no inherit summary in the session (see b.log)"
grep -q "These findings from the earlier report do not carry over unchanged" "$S2" 2>/dev/null && pass "the carry handed the model the agenda" || log "NOTE: no agenda in the session (no finding drifted?)"
grep -q "re-verified on this build" "$WORK/v2.md" 2>/dev/null && pass "v2 report carries inherited finding(s)" || fail "v2 report has no inherited finding"
FINDINGS_B="$(count '"customType":"re.finding"' "$S2")"
INHERITED_B="$(count '"customType":"re.finding".*"inherited"' "$S2")"
log "v2 session: $FINDINGS_B finding entr(ies), $INHERITED_B inherited — $((FINDINGS_B - INHERITED_B)) recorded by the model while resolving the agenda"

[ "$FAIL" -eq 0 ] && log "live-model: ALL PASS" || log "live-model: FAILURES"
exit "$FAIL"
