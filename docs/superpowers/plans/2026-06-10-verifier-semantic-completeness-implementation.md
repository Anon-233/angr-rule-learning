# Verifier Semantic Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the verifier core from the current memory/register MVP into an ISA-agnostic semantic checker with shared SMT relation logic, stronger memory correctness, explicit flag checks, terminal branch guard checks, and four-state diagnostics.

**Architecture:** Keep the verifier API-first. Add a small verifier kernel made of shared execution context, relation checking, and report-building utilities; keep semantic extraction surface-specific for register, memory, flag, and branch checks. Do not introduce a generic symbolic execution framework or instruction-family-specific semantics.

**Tech Stack:** Python dataclasses, angr, Claripy, pytest, ruff, uv.

---

## Design Inputs

Read these documents before starting:

- `docs/superpowers/specs/2026-06-10-verifier-semantic-completeness-design.md`
- `docs/superpowers/specs/2026-06-09-verifier-first-design.md`
- `CLAUDE.md`

Current known baseline:

- `main` contains the verifier memory MVP.
- JSON parsing lives under `src/angr_rule_learning/io/`.
- Core typed verifier models live under `src/angr_rule_learning/verification/`.
- Current status values are `pass`, `fail`, and `unsupported`; this plan adds `error`.
- Current memory checks do not yet use a shared relation checker.
- Current flags and terminal branch guards are unsupported.

## Target File Structure

Create these files:

- `src/angr_rule_learning/verification/context.py`: internal `CheckContext` and check helper data structures.
- `src/angr_rule_learning/verification/relations.py`: shared SMT relation checker and counterexample creation.
- `src/angr_rule_learning/verification/addressing.py`: memory binding expression parser for `reg`, `reg + const`, `reg - const`.
- `src/angr_rule_learning/verification/flags.py`: explicit output flag checker.
- `src/angr_rule_learning/verification/branches.py`: terminal branch guard extraction and checker.
- `src/angr_rule_learning/arch/flags.py`: architecture-specific flag expression extraction.
- `tests/test_relation_checker.py`: shared SMT relation tests.
- `tests/test_report_taxonomy.py`: four-state report and summary tests.
- `tests/test_memory_correctness.py`: memory binding/disjoint/constraint/counterexample tests.
- `tests/test_verifier_flags.py`: explicit flag output tests.
- `tests/test_verifier_branches.py`: terminal branch guard tests.

Modify these files:

- `src/angr_rule_learning/verification/report.py`: add status validation, `metadata`, and JSON-shaped immutable data.
- `src/angr_rule_learning/io/schema.py`: serialize `metadata`, `error` status, and report shape changes.
- `src/angr_rule_learning/verification/batch.py`: add `by_kind` and top reason aggregation.
- `src/angr_rule_learning/verification/config.py`: add `fail_fast`.
- `src/angr_rule_learning/verification/checks.py`: migrate register checks to `RelationChecker`.
- `src/angr_rule_learning/verification/memory.py`: use address binding parser and detect alias contradictions.
- `src/angr_rule_learning/verification/memory_checks.py`: use `CheckContext` and `RelationChecker`.
- `src/angr_rule_learning/verification/execution.py`: expose successor/guard information needed by branch checks.
- `src/angr_rule_learning/verification/verifier.py`: orchestrate kernel/context/checkers and four-state reports.
- `src/angr_rule_learning/verification/__init__.py`: export only stable public API; keep internals unexported.
- `README.md` and `docs/architecture.md`: update public behavior after report/flag/branch changes.

## Fixture Encoding Rule

Tests may use concrete AArch64 and x86-64 instructions as fixtures, but verifier support is defined by semantic surfaces, not instruction families.

When adding flag or branch fixtures, first verify the bytes with angr disassembly:

```bash
uv run python - <<'PY'
import logging

logging.getLogger("angr.engines.unicorn").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

import angr

from angr_rule_learning.arch.registry import angr_arch_name

fixtures = [
    ("aarch64-cmp-branch", "aarch64", "1f0001eb40000054", 0x10000),
    ("x86-cmp-je", "x86-64", "4839c87402", 0x8048000),
]
for name, arch, code_hex, addr in fixtures:
    project = angr.load_shellcode(
        bytes.fromhex(code_hex),
        arch=angr_arch_name(arch),
        load_address=addr,
    )
    print(name)
    for insn in project.factory.block(addr).capstone.insns:
        print(" ", insn.mnemonic, insn.op_str)
PY
```

If a fixture disassembles differently than the test name claims, replace the bytes before writing assertions and add a short source comment naming the intended instruction sequence.

---

## Task 1: Four-State Report Taxonomy and Batch Summary

**Files:**
- Modify: `src/angr_rule_learning/verification/report.py`
- Modify: `src/angr_rule_learning/io/schema.py`
- Modify: `src/angr_rule_learning/verification/batch.py`
- Test: `tests/test_report_taxonomy.py`
- Test: `tests/test_schema.py`
- Test: `tests/test_batch_cli.py`

- [ ] **Step 1: Write failing report taxonomy tests**

Create `tests/test_report_taxonomy.py`:

```python
import pytest

from angr_rule_learning.io.schema import report_to_json
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def test_check_result_preserves_json_metadata() -> None:
    check = CheckResult(
        kind="memory",
        status="fail",
        guest="mem0",
        host="mem0",
        reason="memory_address_mismatch",
        counterexample={"x1": 0x70000004},
        metadata={"event_index": 0, "width": 4, "address": "x1 + 4"},
    )

    assert check.metadata["event_index"] == 0
    assert check.metadata["width"] == 4


def test_report_supports_error_status_without_equivalence() -> None:
    report = VerificationReport(
        candidate_id="bad",
        status="error",
        checks=(
            CheckResult(
                kind="execution",
                status="error",
                guest="guest",
                host="host",
                reason="angr_execution_error",
                metadata={"detail": "boom"},
            ),
        ),
    )

    assert not report.equivalent
    assert report.failure_reasons == {"angr_execution_error": 1}
    assert report_to_json(report)["checks"][0]["metadata"] == {"detail": "boom"}


def test_report_rejects_unknown_status() -> None:
    with pytest.raises(ValueError, match="unsupported report status"):
        VerificationReport(candidate_id="bad", status="maybe")


def test_batch_summary_counts_by_kind_and_top_reasons() -> None:
    reports = [
        VerificationReport(
            candidate_id="r0",
            status="fail",
            checks=(
                CheckResult(
                    "register",
                    "fail",
                    "x0",
                    "rax",
                    reason="register_mismatch",
                ),
            ),
        ),
        VerificationReport(
            candidate_id="r1",
            status="unsupported",
            checks=(
                CheckResult(
                    "flag",
                    "unsupported",
                    "nzcv.p",
                    "pf",
                    reason="unsupported_flag",
                ),
            ),
        ),
    ]

    summary = BatchVerifier.summarize(reports).to_json()

    assert summary["statuses"] == {"fail": 1, "unsupported": 1}
    assert summary["by_kind"] == {
        "flag": {"unsupported": 1},
        "register": {"fail": 1},
    }
    assert summary["top_reasons"] == {
        "register_mismatch": 1,
        "unsupported_flag": 1,
    }
```

- [ ] **Step 2: Run taxonomy tests and confirm failure**

Run:

```bash
uv run pytest tests/test_report_taxonomy.py -v
```

Expected:

```text
FAILED tests/test_report_taxonomy.py::test_check_result_preserves_json_metadata
```

- [ ] **Step 3: Implement report model changes**

Update `src/angr_rule_learning/verification/report.py`:

```python
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


REPORT_STATUSES = {"pass", "fail", "unsupported", "error"}
CHECK_STATUSES = REPORT_STATUSES


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class CheckResult:
    kind: str
    status: str
    guest: str
    host: str
    reason: str = ""
    counterexample: Mapping[str, int] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in CHECK_STATUSES:
            raise ValueError(f"unsupported check status: {self.status}")
        object.__setattr__(self, "counterexample", _freeze_mapping(self.counterexample))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))


@dataclass(frozen=True)
class VerificationReport:
    candidate_id: str
    status: str
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    unsupported_features: tuple[str, ...] = field(default_factory=tuple)
    events: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.status not in REPORT_STATUSES:
            raise ValueError(f"unsupported report status: {self.status}")
        object.__setattr__(self, "checks", tuple(self.checks))
        object.__setattr__(self, "unsupported_features", tuple(self.unsupported_features))
        object.__setattr__(
            self,
            "events",
            tuple(_freeze_mapping(event) for event in self.events),
        )

    @property
    def equivalent(self) -> bool:
        return self.status == "pass" and all(
            check.status == "pass" for check in self.checks
        )

    @property
    def failure_reasons(self) -> dict[str, int]:
        reasons = Counter(check.reason for check in self.checks if check.reason)
        reasons.update(self.unsupported_features)
        return dict(reasons)
```

- [ ] **Step 4: Update report JSON serialization**

In `src/angr_rule_learning/io/schema.py`, add `metadata` to each serialized check:

```python
{
    "kind": check.kind,
    "status": check.status,
    "guest": check.guest,
    "host": check.host,
    "reason": check.reason,
    "counterexample": _json_value(
        check.counterexample, f"checks[{index}].counterexample"
    ),
    "metadata": _json_value(check.metadata, f"checks[{index}].metadata"),
}
```

- [ ] **Step 5: Update batch summary**

In `src/angr_rule_learning/verification/batch.py`, replace `BatchSummary` with:

```python
@dataclass(frozen=True)
class BatchSummary:
    total: int
    statuses: dict[str, int]
    failure_reasons: dict[str, int]
    by_kind: dict[str, dict[str, int]]
    top_reasons: dict[str, int]

    def to_json(self) -> dict[str, object]:
        return {
            "total": self.total,
            "statuses": dict(sorted(self.statuses.items())),
            "failure_reasons": dict(sorted(self.failure_reasons.items())),
            "by_kind": {
                kind: dict(sorted(statuses.items()))
                for kind, statuses in sorted(self.by_kind.items())
            },
            "top_reasons": dict(sorted(self.top_reasons.items())),
        }
```

Update `BatchVerifier.summarize()`:

```python
    @staticmethod
    def summarize(reports: Iterable[VerificationReport]) -> BatchSummary:
        reports = list(reports)
        statuses = Counter(report.status for report in reports)
        failure_reasons: Counter[str] = Counter()
        by_kind: dict[str, Counter[str]] = {}
        for report in reports:
            failure_reasons.update(report.failure_reasons)
            for check in report.checks:
                by_kind.setdefault(check.kind, Counter()).update((check.status,))
        return BatchSummary(
            total=len(reports),
            statuses=dict(statuses),
            failure_reasons=dict(failure_reasons),
            by_kind={kind: dict(counter) for kind, counter in by_kind.items()},
            top_reasons=dict(failure_reasons),
        )
```

- [ ] **Step 6: Update existing tests for summary shape**

In `tests/test_batch_cli.py`, update summary assertions so they allow the new keys:

```python
assert summary["total"] == 1
assert summary["statuses"] == {"pass": 1}
assert summary["by_kind"]["register"] == {"pass": 1}
```

In `tests/test_schema.py`, update expected report JSON checks to include `"metadata": {}` for each check.

- [ ] **Step 7: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_report_taxonomy.py tests/test_schema.py tests/test_batch_cli.py -v
git diff --check
git add src/angr_rule_learning/verification/report.py src/angr_rule_learning/io/schema.py src/angr_rule_learning/verification/batch.py tests/test_report_taxonomy.py tests/test_schema.py tests/test_batch_cli.py
git commit -m "Add four-state verifier report taxonomy"
```

Expected:

```text
All checks passed!
```

---

## Task 2: Shared Check Context and Relation Checker

**Files:**
- Create: `src/angr_rule_learning/verification/context.py`
- Create: `src/angr_rule_learning/verification/relations.py`
- Modify: `src/angr_rule_learning/verification/checks.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Test: `tests/test_relation_checker.py`
- Test: `tests/test_verifier_registers.py`

- [ ] **Step 1: Write failing relation checker tests**

Create `tests/test_relation_checker.py`:

```python
import claripy

from angr_rule_learning.verification.relations import RelationChecker


def test_relation_checker_passes_when_difference_is_unsat() -> None:
    x = claripy.BVS("x", 64)
    checker = RelationChecker(symbols={"x": x})

    result = checker.check_equal(
        kind="register",
        guest="x0",
        host="rax",
        guest_expr=x + 1,
        host_expr=x + 1,
        mismatch_reason="register_mismatch",
    )

    assert result.status == "pass"
    assert result.reason == ""


def test_relation_checker_fails_with_counterexample() -> None:
    x = claripy.BVS("x", 64)
    y = claripy.BVS("y", 64)
    checker = RelationChecker(symbols={"x": x, "y": y})

    result = checker.check_equal(
        kind="register",
        guest="x0",
        host="rax",
        guest_expr=x + y,
        host_expr=x,
        mismatch_reason="register_mismatch",
    )

    assert result.status == "fail"
    assert result.reason == "register_mismatch"
    assert "y" in result.counterexample


def test_relation_checker_aligns_widths() -> None:
    x32 = claripy.BVS("x32", 32)
    x64 = claripy.ZeroExt(32, x32)
    checker = RelationChecker(symbols={"x32": x32})

    result = checker.check_equal(
        kind="register",
        guest="w0",
        host="rax",
        guest_expr=x32,
        host_expr=x64,
        mismatch_reason="register_mismatch",
    )

    assert result.status == "pass"
```

- [ ] **Step 2: Run relation checker tests and confirm failure**

Run:

```bash
uv run pytest tests/test_relation_checker.py -v
```

Expected:

```text
FAILED tests/test_relation_checker.py::test_relation_checker_passes_when_difference_is_unsat
```

- [ ] **Step 3: Create CheckContext**

Create `src/angr_rule_learning/verification/context.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

import claripy

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.memory import MemoryEvent, MemoryLayout


@dataclass(frozen=True)
class CheckContext:
    candidate: VerificationCandidate
    guest_state: object
    host_state: object
    symbols: Mapping[str, claripy.ast.BV]
    memory_layout: MemoryLayout
    memory_events: tuple[MemoryEvent, ...] = field(default_factory=tuple)

    @property
    def constraints(self) -> tuple[object, ...]:
        return (
            tuple(self.guest_state.solver.constraints)
            + tuple(self.host_state.solver.constraints)
        )
```

- [ ] **Step 4: Create RelationChecker**

Create `src/angr_rule_learning/verification/relations.py`:

```python
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import claripy

from angr_rule_learning.smt.solver import align_widths
from angr_rule_learning.verification.report import CheckResult


class RelationChecker:
    def __init__(
        self,
        *,
        symbols: Mapping[str, claripy.ast.BV],
        constraints: tuple[object, ...] = (),
    ) -> None:
        self._symbols = symbols
        self._constraints = constraints

    def check_equal(
        self,
        *,
        kind: str,
        guest: str,
        host: str,
        guest_expr: claripy.ast.BV,
        host_expr: claripy.ast.BV,
        mismatch_reason: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> CheckResult:
        guest_expr, host_expr = align_widths(guest_expr, host_expr)
        difference = guest_expr != host_expr
        solver = claripy.Solver()
        if self._constraints:
            solver.add(*self._constraints)
        if not solver.satisfiable(extra_constraints=(difference,)):
            return CheckResult(kind, "pass", guest, host, metadata=metadata or {})
        return CheckResult(
            kind=kind,
            status="fail",
            guest=guest,
            host=host,
            reason=mismatch_reason,
            counterexample=self._counterexample(difference),
            metadata=metadata or {},
        )

    def _counterexample(self, extra_constraint: object) -> dict[str, int]:
        solver = claripy.Solver()
        if self._constraints:
            solver.add(*self._constraints)
        return {
            name: solver.eval(symbol, 1, extra_constraints=(extra_constraint,))[0]
            for name, symbol in self._symbols.items()
        }
```

- [ ] **Step 5: Migrate register check to RelationChecker**

Replace `check_register_pair()` in `src/angr_rule_learning/verification/checks.py` with:

```python
from __future__ import annotations

from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.execution import read_reg
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


def check_register_pair(
    context: CheckContext,
    guest_reg: str,
    host_reg: str,
) -> CheckResult:
    checker = RelationChecker(
        symbols=context.symbols,
        constraints=context.constraints,
    )
    return checker.check_equal(
        kind="register",
        guest=guest_reg,
        host=host_reg,
        guest_expr=read_reg(context.guest_state, guest_reg),
        host_expr=read_reg(context.host_state, host_reg),
        mismatch_reason="register_mismatch",
    )
```

- [ ] **Step 6: Update SemanticVerifier to build CheckContext**

In `src/angr_rule_learning/verification/verifier.py`, after execution succeeds, build:

```python
context = CheckContext(
    candidate=candidate,
    guest_state=guest_executed.state,
    host_state=host_executed.state,
    symbols=symbols,
    memory_layout=layout,
    memory_events=tuple(recorder.events),
)
```

Then call:

```python
check = check_register_pair(context, guest_reg, host_reg)
```

- [ ] **Step 7: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_relation_checker.py tests/test_verifier_registers.py tests/test_verifier_memory.py -v
git diff --check
git add src/angr_rule_learning/verification/context.py src/angr_rule_learning/verification/relations.py src/angr_rule_learning/verification/checks.py src/angr_rule_learning/verification/verifier.py tests/test_relation_checker.py tests/test_verifier_registers.py
git commit -m "Add shared SMT relation checker"
```

Expected:

```text
All checks passed!
```

---

## Task 3: Verifier Error Status, Configurable Fail-Fast, and Kernel Orchestration

**Files:**
- Modify: `src/angr_rule_learning/verification/config.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Modify: `src/angr_rule_learning/verification/execution.py`
- Test: `tests/test_verifier_errors.py`
- Test: `tests/test_verifier_registers.py`

- [ ] **Step 1: Write failing verifier error tests**

Create `tests/test_verifier_errors.py`:

```python
from angr_rule_learning.verification.candidate import CodeFragment, VerificationCandidate
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.verifier import SemanticVerifier


def test_verifier_reports_unknown_output_register_as_error() -> None:
    candidate = VerificationCandidate(
        candidate_id="bad-register",
        guest=CodeFragment("aarch64", 0x10000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x8048000, "48 8d 04 11", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("not_a_register", "rax"),),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "error"
    assert report.checks[0].kind == "execution"
    assert report.checks[0].status == "error"
    assert report.checks[0].reason == "verifier_internal_error"


def test_config_defaults_to_collecting_all_checks() -> None:
    config = VerificationConfig()

    assert config.fail_fast is False
```

- [ ] **Step 2: Run error tests and confirm failure**

Run:

```bash
uv run pytest tests/test_verifier_errors.py -v
```

Expected:

```text
FAILED tests/test_verifier_errors.py::test_verifier_reports_unknown_output_register_as_error
```

- [ ] **Step 3: Add fail_fast config**

Modify `src/angr_rule_learning/verification/config.py`:

```python
@dataclass(frozen=True)
class VerificationConfig:
    max_successors: int = 1
    emit_events: bool = False
    memory_base: int = 0x70000000
    memory_stride: int = 0x1000
    fail_fast: bool = False
```

- [ ] **Step 4: Add report helpers in verifier**

In `src/angr_rule_learning/verification/verifier.py`, add private helpers:

```python
def _unsupported(candidate_id: str, kind: str, reason: str, guest: str = "", host: str = "") -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "unsupported",
        checks=(CheckResult(kind, "unsupported", guest, host, reason=reason),),
        unsupported_features=(reason,),
    )


def _error(candidate_id: str, reason: str, detail: str) -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "error",
        checks=(
            CheckResult(
                "execution",
                "error",
                "guest",
                "host",
                reason=reason,
                metadata={"detail": detail},
            ),
        ),
    )
```

Use `_unsupported()` for `flag_outputs`, `preconditions`, `unsupported_may_alias`, and `multi_successor_unsupported`.

- [ ] **Step 5: Catch unexpected verifier exceptions**

Wrap the core body of `SemanticVerifier.verify()`:

```python
    def verify(self, candidate: VerificationCandidate) -> VerificationReport:
        try:
            return self._verify(candidate)
        except Exception as exc:
            return _error(candidate.candidate_id, "verifier_internal_error", str(exc))
```

Move the current implementation into `_verify()`.

- [ ] **Step 6: Collect checks by default and honor fail_fast**

In `_verify()`, replace early fail return inside register loop with:

```python
checks.append(check)
if check.status != "pass" and self.config.fail_fast:
    return VerificationReport(candidate.candidate_id, check.status, checks=tuple(checks))
```

At the end, compute status with:

```python
return VerificationReport(
    candidate.candidate_id,
    _overall_status(checks),
    checks=tuple(checks),
)
```

Add:

```python
def _overall_status(checks: list[CheckResult]) -> str:
    statuses = {check.status for check in checks}
    if "error" in statuses:
        return "error"
    if "unsupported" in statuses:
        return "unsupported"
    if "fail" in statuses:
        return "fail"
    return "pass"
```

- [ ] **Step 7: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_verifier_errors.py tests/test_verifier_registers.py tests/test_verifier_memory.py -v
git diff --check
git add src/angr_rule_learning/verification/config.py src/angr_rule_learning/verification/verifier.py tests/test_verifier_errors.py tests/test_verifier_registers.py
git commit -m "Add verifier error status handling"
```

Expected:

```text
All checks passed!
```

---

## Task 4: Memory Correctness Upgrade

**Files:**
- Create: `src/angr_rule_learning/verification/addressing.py`
- Modify: `src/angr_rule_learning/verification/memory.py`
- Modify: `src/angr_rule_learning/verification/memory_checks.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Test: `tests/test_memory_correctness.py`
- Test: `tests/test_verifier_memory.py`

- [ ] **Step 1: Write failing memory correctness tests**

Create `tests/test_memory_correctness.py`:

```python
import pytest

from angr_rule_learning.verification.addressing import parse_address_binding
from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import FragmentExecutor
from angr_rule_learning.verification.memory import MemoryInitializer
from angr_rule_learning.verification.verifier import SemanticVerifier


def test_parse_address_binding_supports_register_plus_minus_constant() -> None:
    assert parse_address_binding("x1").register == "x1"
    assert parse_address_binding("x1 + 4").offset == 4
    assert parse_address_binding("rcx - 8").offset == -8


def test_parse_address_binding_rejects_complex_expression() -> None:
    with pytest.raises(ValueError, match="unsupported address expression"):
        parse_address_binding("x1 + x2")


def test_memory_initializer_binds_register_for_positive_offset() -> None:
    candidate = VerificationCandidate(
        candidate_id="offset-load",
        guest=CodeFragment("aarch64", 0x10000, "20 04 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 41 04", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 4", "rcx + 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)

    layout = MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )

    assert guest_state.solver.eval(guest_state.regs.x1) == layout.slot_base("mem0") - 4
    assert host_state.solver.eval(host_state.regs.rcx) == layout.slot_base("mem0") - 4


def test_conflicting_alias_declarations_report_error() -> None:
    candidate = VerificationCandidate(
        candidate_id="bad-alias",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
            alias=(
                AliasDeclaration(("mem0", "mem1"), "must_alias"),
                AliasDeclaration(("mem0", "mem1"), "disjoint"),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "error"
    assert report.checks[0].reason == "invalid_alias_declaration"
```

- [ ] **Step 2: Run memory correctness tests and confirm failure**

Run:

```bash
uv run pytest tests/test_memory_correctness.py -v
```

Expected:

```text
FAILED tests/test_memory_correctness.py::test_parse_address_binding_supports_register_plus_minus_constant
```

- [ ] **Step 3: Implement address binding parser**

Create `src/angr_rule_learning/verification/addressing.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
import re


ADDRESS_RE = re.compile(r"^\s*(?P<register>[A-Za-z][A-Za-z0-9_]*)\s*(?:(?P<op>[+-])\s*(?P<offset>0x[0-9a-fA-F]+|\d+))?\s*$")


@dataclass(frozen=True)
class AddressBinding:
    register: str
    offset: int = 0


def parse_address_binding(expression: str) -> AddressBinding:
    match = ADDRESS_RE.match(expression)
    if match is None:
        raise ValueError(f"unsupported address expression: {expression}")
    register = match.group("register").lower()
    offset_text = match.group("offset")
    if offset_text is None:
        return AddressBinding(register)
    offset = int(offset_text, 0)
    if match.group("op") == "-":
        offset = -offset
    return AddressBinding(register, offset)
```

- [ ] **Step 4: Use address bindings during memory initialization**

In `src/angr_rule_learning/verification/memory.py`, replace direct binding register writes with:

```python
from angr_rule_learning.verification.addressing import parse_address_binding


def _write_bound_address(state: angr.SimState, expression: str, base: int) -> None:
    binding = parse_address_binding(expression)
    register_value = base - binding.offset
    write_reg(state, binding.register, claripy.BVV(register_value, state.arch.bits))
```

Then in `MemoryInitializer.initialize()`:

```python
for binding in candidate.memory.bindings:
    base = bases[binding.slot]
    _write_bound_address(guest_state, binding.guest_addr, base)
    _write_bound_address(host_state, binding.host_addr, base)
```

- [ ] **Step 5: Detect alias contradictions**

In `src/angr_rule_learning/verification/memory.py`, add:

```python
def validate_alias_declarations(candidate: VerificationCandidate) -> None:
    must_alias_pairs = set()
    disjoint_pairs = set()
    for alias in candidate.memory.alias:
        pairs = {
            tuple(sorted((left, right)))
            for index, left in enumerate(alias.slots)
            for right in alias.slots[index + 1 :]
        }
        if alias.relation == "must_alias":
            must_alias_pairs.update(pairs)
        elif alias.relation == "disjoint":
            disjoint_pairs.update(pairs)
    if must_alias_pairs & disjoint_pairs:
        raise ValueError("invalid_alias_declaration")
```

Call `validate_alias_declarations(candidate)` at the start of `MemoryInitializer.initialize()`.

- [ ] **Step 6: Route alias/address errors to error/unsupported**

In `SemanticVerifier._verify()`, catch:

```python
except ValueError as exc:
    if str(exc).startswith("unsupported address expression"):
        return _unsupported(
            candidate.candidate_id,
            "memory",
            "unsupported_address_expression",
            "memory",
            "memory",
        )
    if str(exc) == "invalid_alias_declaration":
        return _error(candidate.candidate_id, "invalid_alias_declaration", str(exc))
    raise
```

- [ ] **Step 7: Migrate memory value checks to RelationChecker**

In `src/angr_rule_learning/verification/memory_checks.py`, change `check_memory_events()` signature to:

```python
def check_memory_events(context: CheckContext) -> list[CheckResult]:
```

Use:

```python
checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
```

For value comparison:

```python
checks.append(
    checker.check_equal(
        kind="memory",
        guest=expectation.slot,
        host=expectation.slot,
        guest_expr=guest_event.value,
        host_expr=host_event.value,
        mismatch_reason=(
            "memory_read_value_mismatch"
            if expectation.kind == "read"
            else "memory_write_value_mismatch"
        ),
        metadata={"event_index": index, "width": expectation.width},
    )
)
```

For address checks, compare `event.address` to `claripy.BVV(base, event.address.size())` through `checker.check_equal()` with reason `memory_address_mismatch`.

- [ ] **Step 8: Add disjoint layout test**

Append to `tests/test_memory_correctness.py`:

```python
def test_disjoint_slots_do_not_overlap_when_stride_is_large_enough() -> None:
    candidate = VerificationCandidate(
        candidate_id="disjoint",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
            alias=(AliasDeclaration(("mem0", "mem1"), "disjoint"),),
        ),
    )
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)

    layout = MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )

    assert layout.slot_base("mem1") - layout.slot_base("mem0") >= 4
```

- [ ] **Step 9: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_memory_correctness.py tests/test_verifier_memory.py tests/test_memory_events.py -v
git diff --check
git add src/angr_rule_learning/verification/addressing.py src/angr_rule_learning/verification/memory.py src/angr_rule_learning/verification/memory_checks.py src/angr_rule_learning/verification/verifier.py tests/test_memory_correctness.py tests/test_verifier_memory.py tests/test_memory_events.py
git commit -m "Strengthen memory relation checking"
```

Expected:

```text
All checks passed!
```

---

## Task 5: Explicit Flag Output Surface

**Files:**
- Create: `src/angr_rule_learning/arch/flags.py`
- Create: `src/angr_rule_learning/verification/flags.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Test: `tests/test_verifier_flags.py`

- [ ] **Step 1: Verify flag fixture disassembly**

Run:

```bash
uv run python - <<'PY'
import logging

logging.getLogger("angr.engines.unicorn").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

import angr

from angr_rule_learning.arch.registry import angr_arch_name

fixtures = [
    ("aarch64-cmp-x1-x2", "aarch64", "3f0002eb", 0x10000),
    ("x86-cmp-rcx-rdx", "x86-64", "4839d1", 0x8048000),
]
for name, arch, code_hex, addr in fixtures:
    project = angr.load_shellcode(
        bytes.fromhex(code_hex),
        arch=angr_arch_name(arch),
        load_address=addr,
    )
    print(name)
    for insn in project.factory.block(addr).capstone.insns:
        print(" ", insn.mnemonic, insn.op_str)
PY
```

Expected disassembly:

```text
aarch64-cmp-x1-x2
  cmp x1, x2
x86-cmp-rcx-rdx
  cmp rcx, rdx
```

If angr prints different operands, update the fixture bytes and comments before proceeding.

- [ ] **Step 2: Write failing flag verifier tests**

Create `tests/test_verifier_flags.py`:

```python
from angr_rule_learning.verification.candidate import CodeFragment, VerificationCandidate
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_CMP_X1_X2 = "3f 00 02 eb"
X86_64_CMP_RCX_RDX = "48 39 d1"


def _candidate(flags: tuple[tuple[str, str], ...]) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="cmp-flags",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_CMP_X1_X2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_CMP_RCX_RDX, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_flags=flags,
    )


def test_verifier_accepts_equivalent_zero_flag() -> None:
    report = SemanticVerifier().verify(_candidate((("nzcv.z", "zf"),)))

    assert report.status == "pass"
    assert report.checks[0].kind == "flag"
    assert report.checks[0].status == "pass"


def test_verifier_reports_unsupported_flag() -> None:
    report = SemanticVerifier().verify(_candidate((("nzcv.z", "pf"),)))

    assert report.status == "unsupported"
    assert report.checks[0].kind == "flag"
    assert report.checks[0].reason == "unsupported_flag"
```

- [ ] **Step 3: Run flag tests and confirm failure**

Run:

```bash
uv run pytest tests/test_verifier_flags.py -v
```

Expected:

```text
FAILED tests/test_verifier_flags.py::test_verifier_accepts_equivalent_zero_flag
```

- [ ] **Step 4: Implement architecture flag extractor**

Create `src/angr_rule_learning/arch/flags.py`:

```python
from __future__ import annotations

import claripy


X86_FLAG_BITS = {
    "cf": 0,
    "zf": 6,
    "sf": 7,
    "of": 11,
}

AARCH64_NZCV_BITS = {
    "n": 31,
    "z": 30,
    "c": 29,
    "v": 28,
}


def read_flag(state: object, flag: str) -> claripy.ast.BV:
    normalized = flag.strip().lower()
    if normalized.startswith("nzcv."):
        name = normalized.split(".", 1)[1]
        try:
            bit = AARCH64_NZCV_BITS[name]
        except KeyError as exc:
            raise ValueError(f"unsupported flag: {flag}") from exc
        nzcv = state.regs.nzcv
        return nzcv[bit:bit]
    try:
        bit = X86_FLAG_BITS[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported flag: {flag}") from exc
    eflags = state.regs.eflags
    return eflags[bit:bit]
```

- [ ] **Step 5: Implement flag checker**

Create `src/angr_rule_learning/verification/flags.py`:

```python
from __future__ import annotations

from angr_rule_learning.arch.flags import read_flag
from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


def check_flag_pair(
    context: CheckContext,
    guest_flag: str,
    host_flag: str,
) -> CheckResult:
    try:
        guest_expr = read_flag(context.guest_state, guest_flag)
        host_expr = read_flag(context.host_state, host_flag)
    except ValueError:
        return CheckResult(
            "flag",
            "unsupported",
            guest_flag,
            host_flag,
            reason="unsupported_flag",
        )
    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
    return checker.check_equal(
        kind="flag",
        guest=guest_flag,
        host=host_flag,
        guest_expr=guest_expr,
        host_expr=host_expr,
        mismatch_reason="flag_mismatch",
    )
```

- [ ] **Step 6: Wire flags into SemanticVerifier**

Remove the early `if candidate.output_flags: unsupported` block from `SemanticVerifier._verify()`.

After memory checks and before register checks:

```python
from angr_rule_learning.verification.flags import check_flag_pair

for guest_flag, host_flag in candidate.output_flags:
    check = check_flag_pair(context, guest_flag, host_flag)
    checks.append(check)
    if check.status != "pass" and self.config.fail_fast:
        return VerificationReport(candidate.candidate_id, check.status, checks=tuple(checks))
```

- [ ] **Step 7: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_verifier_flags.py tests/test_verifier_registers.py tests/test_schema.py -v
git diff --check
git add src/angr_rule_learning/arch/flags.py src/angr_rule_learning/verification/flags.py src/angr_rule_learning/verification/verifier.py tests/test_verifier_flags.py
git commit -m "Add explicit flag output checks"
```

Expected:

```text
All checks passed!
```

---

## Task 6: Terminal Branch Guard Surface

**Files:**
- Create: `src/angr_rule_learning/verification/branches.py`
- Modify: `src/angr_rule_learning/verification/execution.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Test: `tests/test_verifier_branches.py`

- [ ] **Step 1: Verify branch fixture disassembly**

Run:

```bash
uv run python - <<'PY'
import logging

logging.getLogger("angr.engines.unicorn").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

import angr

from angr_rule_learning.arch.registry import angr_arch_name

fixtures = [
    ("aarch64-cmp-beq", "aarch64", "1f0001eb40000054", 0x10000),
    ("x86-cmp-je", "x86-64", "4839c87402", 0x8048000),
    ("x86-cmp-jne", "x86-64", "4839c87502", 0x8048000),
]
for name, arch, code_hex, addr in fixtures:
    project = angr.load_shellcode(
        bytes.fromhex(code_hex),
        arch=angr_arch_name(arch),
        load_address=addr,
    )
    print(name)
    for insn in project.factory.block(addr).capstone.insns:
        print(" ", insn.mnemonic, insn.op_str)
PY
```

Expected disassembly includes:

```text
aarch64-cmp-beq
  cmp x0, x1
  b.eq ...
x86-cmp-je
  cmp rax, rcx
  je ...
x86-cmp-jne
  cmp rax, rcx
  jne ...
```

If angr prints different operands, update fixture bytes and comments before writing assertions.

- [ ] **Step 2: Write failing branch tests**

Create `tests/test_verifier_branches.py`:

```python
from angr_rule_learning.verification.candidate import CodeFragment, VerificationCandidate
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_CMP_X0_X1_B_EQ = "1f 00 01 eb 40 00 00 54"
X86_64_CMP_RAX_RCX_JE = "48 39 c8 74 02"
X86_64_CMP_RAX_RCX_JNE = "48 39 c8 75 02"
AARCH64_B_EQ_THEN_CMP = "40 00 00 54 1f 00 01 eb"


def _candidate(host_hex: str, *, guest_hex: str = AARCH64_CMP_X0_X1_B_EQ) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="branch-guard",
        guest=CodeFragment("aarch64", 0x10000, guest_hex, 2),
        host=CodeFragment("x86-64", 0x8048000, host_hex, 2),
        input_registers=(("x0", "rax"), ("x1", "rcx")),
    )


def test_verifier_accepts_equivalent_terminal_branch_guard() -> None:
    report = SemanticVerifier().verify(_candidate(X86_64_CMP_RAX_RCX_JE))

    assert report.status == "pass"
    assert any(check.kind == "branch" and check.status == "pass" for check in report.checks)


def test_verifier_rejects_mismatched_terminal_branch_guard() -> None:
    report = SemanticVerifier().verify(_candidate(X86_64_CMP_RAX_RCX_JNE))

    assert report.status == "fail"
    assert any(check.kind == "branch" and check.reason == "branch_guard_mismatch" for check in report.checks)


def test_verifier_reports_non_terminal_branch_as_unsupported() -> None:
    report = SemanticVerifier().verify(
        _candidate(X86_64_CMP_RAX_RCX_JE, guest_hex=AARCH64_B_EQ_THEN_CMP)
    )

    assert report.status == "unsupported"
    assert any(check.reason == "non_terminal_branch_unsupported" for check in report.checks)
```

- [ ] **Step 3: Run branch tests and confirm failure**

Run:

```bash
uv run pytest tests/test_verifier_branches.py -v
```

Expected:

```text
FAILED tests/test_verifier_branches.py::test_verifier_accepts_equivalent_terminal_branch_guard
```

- [ ] **Step 4: Capture successor guards in execution**

In `src/angr_rule_learning/verification/execution.py`, add:

```python
@dataclass(frozen=True)
class FragmentSuccessors:
    successors: tuple[angr.SimState, ...]

    @property
    def count(self) -> int:
        return len(self.successors)
```

Add a method:

```python
def successors(self, fragment: CodeFragment, state: angr.SimState) -> FragmentSuccessors:
    successors = state.project.factory.successors(
        state, num_inst=fragment.instruction_count
    ).successors
    return FragmentSuccessors(tuple(successors))
```

Keep `execute()` as a compatibility wrapper that calls `successors()` and still requires exactly one successor.

- [ ] **Step 5: Implement branch guard extractor**

Create `src/angr_rule_learning/verification/branches.py`.

Use raw fragment bytes for branch-position checks. Do not rely on
`project.factory.block(...).capstone.insns` for this check because angr may end
the basic block at the first control-flow instruction and hide trailing bytes.

```python
from __future__ import annotations

import claripy

from angr_rule_learning.verification.candidate import CodeFragment
from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


CONDITIONAL_BRANCH_MNEMONICS = {
    "aarch64": ("b.", "cbz", "cbnz", "tbz", "tbnz"),
    "x86-64": ("j",),
}


def has_non_terminal_branch(fragment: CodeFragment, state: object) -> bool:
    insns = _fragment_insns(fragment, state)
    if len(insns) < 2:
        return False
    return any(_is_conditional_branch(fragment.arch, insn.mnemonic) for insn in insns[:-1])


def _fragment_insns(fragment: CodeFragment, state: object) -> tuple[object, ...]:
    return tuple(state.project.arch.capstone.disasm(fragment.code_bytes, fragment.address))


def _is_conditional_branch(arch: str, mnemonic: str) -> bool:
    normalized_arch = arch.strip().lower()
    normalized_mnemonic = mnemonic.strip().lower()
    prefixes = CONDITIONAL_BRANCH_MNEMONICS.get(normalized_arch, ())
    if normalized_arch == "x86-64" and normalized_mnemonic == "jmp":
        return False
    return any(normalized_mnemonic.startswith(prefix) for prefix in prefixes)


def _guard_to_bitvector(guard: object) -> claripy.ast.BV:
    if isinstance(guard, claripy.ast.Bool):
        return claripy.If(guard, claripy.BVV(1, 1), claripy.BVV(0, 1))
    if not isinstance(guard, claripy.ast.BV):
        raise ValueError("branch_shape_unsupported")
    if guard.size() == 1:
        return guard
    return guard[0:0]


def terminal_taken_guard(
    fragment: CodeFragment,
    state: object,
    successors: tuple[object, ...],
) -> claripy.ast.BV:
    if len(successors) != 2:
        raise ValueError("branch_shape_unsupported")
    insns = _fragment_insns(fragment, state)
    if not insns or not _is_conditional_branch(fragment.arch, insns[-1].mnemonic):
        raise ValueError("branch_shape_unsupported")
    fallthrough = insns[-1].address + insns[-1].size
    taken = [state for state in successors if state.addr != fallthrough]
    if len(taken) != 1:
        raise ValueError("unmatched_successor_shape")
    guard = taken[0].history.jump_guard
    if guard is None:
        raise ValueError("branch_shape_unsupported")
    return _guard_to_bitvector(guard)


def check_terminal_branch_guard(
    context: CheckContext,
    guest_fragment: CodeFragment,
    host_fragment: CodeFragment,
    guest_successors: tuple[object, ...],
    host_successors: tuple[object, ...],
) -> CheckResult | None:
    if has_non_terminal_branch(guest_fragment, context.guest_state) or has_non_terminal_branch(
        host_fragment, context.host_state
    ):
        return CheckResult(
            "branch",
            "unsupported",
            "branch",
            "branch",
            reason="non_terminal_branch_unsupported",
        )
    if len(guest_successors) == 1 and len(host_successors) == 1:
        return None
    try:
        guest_guard = terminal_taken_guard(
            guest_fragment,
            context.guest_state,
            guest_successors,
        )
        host_guard = terminal_taken_guard(
            host_fragment,
            context.host_state,
            host_successors,
        )
    except ValueError as exc:
        return CheckResult(
            "branch",
            "unsupported",
            "branch",
            "branch",
            reason=str(exc),
        )
    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
    return checker.check_equal(
        kind="branch",
        guest="taken_guard",
        host="taken_guard",
        guest_expr=guest_guard,
        host_expr=host_guard,
        mismatch_reason="branch_guard_mismatch",
    )
```

- [ ] **Step 6: Wire branch execution into SemanticVerifier**

In `SemanticVerifier._verify()`:

1. Replace direct `execute()` calls with `successors()`.
2. Allow each side to have either one successor or two successors.
3. If a side has more than two successors, add `multi_branch_unsupported`.
4. Build final states from the single successor for straight-line code.
5. For two-successor branch code, create `CheckContext` from the pre-branch
   states and shared input constraints, then run `check_terminal_branch_guard()`.
   The branch checker must compare only the taken-guard expressions, not
   successor-specific path constraints.
6. Do not run register output checks for a candidate with terminal branch
   successors unless there is exactly one final state on both sides; return
   unsupported with reason `branch_register_outputs_unsupported` if explicit
   register outputs are requested with branch successors.

Use this status rule:

```python
if branch_check is not None:
    checks.append(branch_check)
    if branch_check.status != "pass" and self.config.fail_fast:
        return VerificationReport(candidate.candidate_id, branch_check.status, checks=tuple(checks))
```

- [ ] **Step 7: Verify and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_verifier_branches.py tests/test_verifier_flags.py tests/test_verifier_registers.py -v
git diff --check
git add src/angr_rule_learning/verification/branches.py src/angr_rule_learning/verification/execution.py src/angr_rule_learning/verification/verifier.py tests/test_verifier_branches.py
git commit -m "Add terminal branch guard checks"
```

Expected:

```text
All checks passed!
```

---

## Task 7: Documentation, Public Examples, and Final Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `examples/aarch64_x86_64_batch.jsonl` only if report smoke expectations require it
- Test: full suite and CLI smoke

- [ ] **Step 1: Update README current scope**

In `README.md`, update the implemented list to include:

```markdown
- four-state verifier reports: `pass`, `fail`, `unsupported`, `error`
- explicit flag output checks for the first stable flag subset
- terminal conditional branch guard checks
- stronger memory SMT checks and address binding expressions
```

Keep candidate extraction, rule generalization, rule store, and coverage evaluation in the not-implemented list.

- [ ] **Step 2: Update architecture documentation**

In `docs/architecture.md`, update the semantic verifier section so it says:

```markdown
The verifier checks semantic surfaces rather than instruction families:
register outputs, memory events, explicit flags, and terminal branch guards.
Instruction semantics come from angr; the verifier compares observed Claripy
expressions through shared SMT relation checks.
```

Update report taxonomy to mention `error`.

- [ ] **Step 3: Run full verification**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -q
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-report.jsonl --summary /tmp/angr-rule-learning-summary.json
git diff --check
git status -sb
```

Expected:

```text
All checks passed!
78+ tests passed
```

The exact test count will be higher than 78 after this plan. Third-party Python 3.14 deprecation warnings from angr dependencies are acceptable if no project tests fail.

- [ ] **Step 4: Inspect CLI output**

Run:

```bash
cat /tmp/angr-rule-learning-report.jsonl
cat /tmp/angr-rule-learning-summary.json
```

Expected:

```text
The report JSONL contains candidate_id, status, equivalent, checks, unsupported_features, events, and failure_reasons.
The summary JSON contains total, statuses, failure_reasons, by_kind, and top_reasons.
```

- [ ] **Step 5: Commit docs and final verification updates**

Run:

```bash
git add README.md docs/architecture.md examples/aarch64_x86_64_batch.jsonl
git commit -m "Document semantic verifier completeness"
```

Expected:

```text
[main <sha>] Document semantic verifier completeness
```

---

## Final Completion Checklist

Before declaring the implementation complete, run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-final-report.jsonl --summary /tmp/angr-rule-learning-final-summary.json
git log --oneline --decorate -8
git status -sb
```

Required outcomes:

- formatting check passes;
- lint passes;
- full pytest passes;
- CLI smoke exits 0 and does not emit project or angr environment noise to stderr;
- final report summary has `total >= 1`;
- working tree is clean;
- latest commits correspond to the tasks in this plan.

## Claude Code Handoff Prompt

Use this prompt when handing execution to Claude Code:

```text
Execute docs/superpowers/plans/2026-06-10-verifier-semantic-completeness-implementation.md task by task.

Follow the plan exactly:
- use TDD for each task;
- run the red test before implementation;
- run ruff format after Python edits;
- run ruff check and the task-specific pytest commands before each commit;
- commit after every task with the message specified in the plan;
- do not add legacy schema compatibility;
- do not treat concrete ISA instruction fixtures as verifier support boundaries;
- stop and report if an angr fixture disassembles differently than the plan expects.

After all tasks, run the Final Completion Checklist and report the exact command outputs.
```
