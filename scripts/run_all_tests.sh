#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_all_tests.sh [OPTIONS] [WORK_DIR] [OUT_DIR] [OPT_LEVEL] [GUEST_ARCH] [HOST_ARCH]

  Run the IR-kernel constructive learning pipeline and print diagnostics
  plus a rules summary.

Options:
  -h, --help      Show this help message and exit.

Positional arguments (all optional, defaults shown):
  WORK_DIR        Build artifacts directory for generated IR/object files.
                  Default: /tmp/angr-rule-learning-review/work
  OUT_DIR         Output directory for candidates, reports, diagnostics,
                  rules, and rule diagnostics.
                  Default: /tmp/angr-rule-learning-review
  OPT_LEVEL       Clang optimization level (0, 1, 2, 3, s).
                  Default: 1
  GUEST_ARCH      Guest architecture.
                  Default: aarch64
  HOST_ARCH       Host architecture.
                  Default: x86-64

Output files written to OUT_DIR:
  candidates.jsonl              Constructed verification candidates.
  reports.jsonl                 Verification reports.
  diagnostics.json              Kernel learning diagnostics.
  rules.txt                     Generalized text rules.
  rules_diagnostics.json        Rule generalization diagnostics (aggregate).
  rules_debug_diagnostics.json  Per-skipped-rule detailed diagnostics.

Examples:
  # Use defaults
  ./scripts/run_all_tests.sh

  # Custom work/output directories
  ./scripts/run_all_tests.sh /tmp/my-work /tmp/my-out

  # Reverse direction
  ./scripts/run_all_tests.sh /tmp/rev-work /tmp/rev-out 1 x86-64 aarch64

Underlying command:
  uv run angr-rule-learning learn --work-dir WORK_DIR --rules-output OUT_DIR/rules.txt ...
EOF
}

# ── Help ────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
  esac
done

# ── Arguments ───────────────────────────────────────────────────
WORK_DIR="${1:-/tmp/angr-rule-learning-review/work}"
OUT_DIR="${2:-/tmp/angr-rule-learning-review}"
OPT="${3:-1}"
GUEST_ARCH="${4:-aarch64}"
HOST_ARCH="${5:-x86-64}"

CANDIDATES="${OUT_DIR}/candidates.jsonl"
REPORTS="${OUT_DIR}/reports.jsonl"
DIAGNOSTICS="${OUT_DIR}/diagnostics.json"
RULES="${OUT_DIR}/rules.txt"
RULES_DIAGNOSTICS="${OUT_DIR}/rules_diagnostics.json"
RULES_DEBUG_DIAGNOSTICS="${OUT_DIR}/rules_debug_diagnostics.json"

mkdir -p "${OUT_DIR}"

# ── Pipeline ────────────────────────────────────────────────────
echo "=== IR-kernel constructive learning pipeline ==="
echo "  guest: ${GUEST_ARCH}"
echo "  host:  ${HOST_ARCH}"
echo "  opt:   ${OPT}"

uv run angr-rule-learning learn \
  --work-dir                 "${WORK_DIR}" \
  --rules-output             "${RULES}" \
  --diagnostics              "${DIAGNOSTICS}" \
  --candidates-output        "${CANDIDATES}" \
  --reports-output           "${REPORTS}" \
  --rules-diagnostics        "${RULES_DIAGNOSTICS}" \
  --rules-debug-diagnostics  "${RULES_DEBUG_DIAGNOSTICS}" \
  --optimization             "${OPT}" \
  --guest-arch               "${GUEST_ARCH}" \
  --host-arch                "${HOST_ARCH}"

# ── Summaries ───────────────────────────────────────────────────
echo ""
echo "=== diagnostics ==="
python3 -c "
import json
d = json.load(open('${DIAGNOSTICS}'))
print(f'  kernels_total:     {d[\"kernels_total\"]}')
print(f'  candidates_total:  {d[\"candidates_total\"]}')
print(f'  reports_total:     {d[\"reports_total\"]}')
print(f'  verified_pass:     {d[\"verified_pass\"]}')
print(f'  rules_emitted:     {d[\"rules_emitted\"]}')
print('  records:')
for record in d['records']:
    rule_id = record.get('rule_id', '-')
    reason = record.get('reason', '')
    suffix = f' ({reason})' if reason else ''
    print(f'    {record[\"kernel_id\"]}: {record[\"status\"]}, rule={rule_id}{suffix}')
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
print(f'  subsumed:   {rd[\"rules_subsumed\"]}')
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
for skipped in rdd.get('skipped_rules', []):
    reasons.setdefault(skipped['reason'], 0)
    reasons[skipped['reason']] += 1
for reason, count in sorted(reasons.items()):
    print(f'    {reason}: {count}')
"

echo ""
echo "Done — output in ${OUT_DIR}/"
