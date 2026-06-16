#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_all_tests.sh [OPTIONS] [SOURCE] [WORK_DIR] [OUT_DIR] [OPT_LEVEL]

  Run the end-to-end extraction + verify + rules pipeline on a single
  C source file and print a diagnostics and rules summary.

Options:
  -h, --help      Show this help message and exit.

Positional arguments (all optional, defaults shown):
  SOURCE          C source file to extract from.
                  Default: samples/sources/memory_int.c
  WORK_DIR        Build artifacts directory (object files, etc.).
                  Default: /tmp/angr-rule-learning-review/work
  OUT_DIR         Output directory for candidates JSONL, diagnostics,
                  rules, and rules diagnostics.
                  Default: /tmp/angr-rule-learning-review
  OPT_LEVEL       Clang optimization level (0, 1, 2, 3, s).
                  Default: 0

Output files written to OUT_DIR:
  candidates.jsonl              Extracted verification candidates.
  diagnostics.json              Mining diagnostics (counts, skip reasons).
  rules.txt                     Generalized text rules.
  rules_diagnostics.json        Rule generalization diagnostics (aggregate).
  rules_debug_diagnostics.json  Per-skipped-rule detailed diagnostics.
  skip_patterns.json            Skip pattern analysis report.

Examples:
  # Use defaults
  ./scripts/run_all_tests.sh

  # Custom source, keep defaults for everything else
  ./scripts/run_all_tests.sh samples/sources/smoke_int.c

  # Full customisation
  ./scripts/run_all_tests.sh samples/sources/my_sample.c \
    /tmp/my-work /tmp/my-out 0
EOF
}

# ── Help ────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
  esac
done

# ── Arguments ───────────────────────────────────────────────────
SOURCE="${1:-samples/sources/memory_int.c}"
WORK_DIR="${2:-/tmp/angr-rule-learning-review/work}"
OUT_DIR="${3:-/tmp/angr-rule-learning-review}"
OPT="${4:-0}"

CANDIDATES="${OUT_DIR}/candidates.jsonl"
DIAGNOSTICS="${OUT_DIR}/diagnostics.json"
RULES="${OUT_DIR}/rules.txt"
RULES_DIAGNOSTICS="${OUT_DIR}/rules_diagnostics.json"
RULES_DEBUG_DIAGNOSTICS="${OUT_DIR}/rules_debug_diagnostics.json"
SKIP_PATTERNS="${OUT_DIR}/skip_patterns.json"

# ── Pipeline ────────────────────────────────────────────────────
echo "=== extraction pipeline (${SOURCE}) ==="
uv run angr-rule-learning extract "${SOURCE}" \
  --work-dir                "${WORK_DIR}" \
  --output                  "${CANDIDATES}" \
  --diagnostics             "${DIAGNOSTICS}" \
  --optimization            "${OPT}" \
  --verify \
  --rules-output            "${RULES}" \
  --rules-diagnostics       "${RULES_DIAGNOSTICS}" \
  --rules-debug-diagnostics "${RULES_DEBUG_DIAGNOSTICS}"

echo ""
echo "=== skip pattern analysis (${SOURCE}) ==="
uv run angr-rule-learning diagnose-skips "${SOURCE}" \
  --work-dir    "${WORK_DIR}-skips" \
  --output      "${SKIP_PATTERNS}" \
  --optimization "${OPT}"

# ── Summaries ───────────────────────────────────────────────────
echo ""
echo "=== diagnostics ==="
python3 -c "
import json
d = json.load(open('${DIAGNOSTICS}'))
print(f'  functions:               {d[\"functions\"]}')
print(f'  windows_emitted:         {d[\"windows_emitted\"]}')
print(f'  windows_verified_pass:   {d[\"windows_verified_pass\"]}')
print(f'  surface_kinds:           {d[\"surface_kinds\"]}')
print('  skip_reasons:')
for reason, count in sorted(d['skip_reasons'].items()):
    print(f'    {reason}: {count}')
"

echo ""
echo "=== rules (first 40 lines) ==="
head -40 "${RULES}"

echo ""
echo "=== rules diagnostics ==="
python3 -c "
import json
rd = json.load(open('${RULES_DIAGNOSTICS}'))
print(f'  considered: {rd[\"rules_considered\"]}')
print(f'  emitted:    {rd[\"rules_emitted\"]}')
print(f'  skipped:    {rd[\"rules_skipped\"]}')
for reason, count in sorted(rd['skip_reasons'].items()):
    print(f'    {reason}: {count}')
"

echo ""
echo "=== rules debug diagnostics ==="
python3 -c "
import json
rdd = json.load(open('${RULES_DEBUG_DIAGNOSTICS}'))
print(f'  skipped_rules records: {len(rdd.get(\"skipped_rules\", []))}')
reasons = {}
for s in rdd.get('skipped_rules', []):
    reasons.setdefault(s['reason'], 0)
    reasons[s['reason']] += 1
for reason, count in sorted(reasons.items()):
    print(f'    {reason}: {count}')
"

echo ""
echo "=== skip patterns ==="
python3 -c "
import json
sp = json.load(open('${SKIP_PATTERNS}'))
print(f'  selected_skips:  {sp[\"totals\"][\"selected_skips\"]}')
for detail, payload in sorted(sp['details'].items()):
    print(f'  {detail}: {payload[\"total\"]}')
    if 'by_arch_mnemonic' in payload:
        top = sorted(payload['by_arch_mnemonic'].items(), key=lambda x: -x[1])[:5]
        for k, v in top:
            print(f'    {k}: {v}')
    if 'by_stage' in payload:
        top_stage = sorted(payload['by_stage'].items(), key=lambda x: -x[1])[:3]
        for k, v in top_stage:
            print(f'    stage {k}: {v}')
"

echo ""
echo "Done — output in ${OUT_DIR}/"
