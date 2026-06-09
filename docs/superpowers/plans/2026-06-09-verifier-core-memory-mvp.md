# Verifier Core Memory MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first reusable verifier core with typed Python APIs, strict external JSON/JSONL I/O, batch-oriented CLI, existing register equivalence, and memory load/store event verification.

**Architecture:** The verifier is API-first: pipeline code calls `SemanticVerifier.verify(candidate)` or `BatchVerifier.verify_many(candidates)` directly. JSON/JSONL parsing lives only in `angr_rule_learning.io`, while angr execution, memory event recording, and Claripy checks live under `angr_rule_learning.verification`. The CLI is a thin wrapper around readers, `BatchVerifier`, and writers.

**Tech Stack:** Python dataclasses, angr, Claripy, pytest, ruff, uv.

---

## Scope

This plan implements the first verifier milestone from the approved design:

- New package layout.
- Typed candidate, report, and config models.
- Strict new schema with no legacy `init_map` support.
- Batch-oriented JSONL CLI.
- Existing register equivalence preserved through the new API.
- Memory slots, bindings, expected accesses, memory events, single-load checks, and store checks.
- `disjoint` and `must_alias` accepted in the model; `may_alias` returns an unsupported report.

Flag equivalence remains represented in the model and returns `unsupported` when requested. Detailed AArch64 `NZCV` to x86-64 flag extraction should be planned after the memory MVP is stable.

## File Structure

Create these packages and files:

- `src/angr_rule_learning/verification/__init__.py`: public verifier API exports.
- `src/angr_rule_learning/verification/candidate.py`: typed candidate model.
- `src/angr_rule_learning/verification/config.py`: verifier configuration.
- `src/angr_rule_learning/verification/report.py`: typed report, checks, statuses, reasons.
- `src/angr_rule_learning/verification/errors.py`: domain exceptions.
- `src/angr_rule_learning/verification/execution.py`: angr state construction and fragment execution.
- `src/angr_rule_learning/verification/memory.py`: memory slot allocation and event recorder.
- `src/angr_rule_learning/verification/checks.py`: Claripy relational checks.
- `src/angr_rule_learning/verification/batch.py`: batch verifier and summary aggregation.
- `src/angr_rule_learning/verification/verifier.py`: `SemanticVerifier`.
- `src/angr_rule_learning/io/__init__.py`: I/O exports.
- `src/angr_rule_learning/io/schema.py`: strict JSON to typed model conversion.
- `src/angr_rule_learning/io/readers.py`: JSON, JSONL, and directory candidate readers.
- `src/angr_rule_learning/io/writers.py`: JSONL report and summary writers.
- `src/angr_rule_learning/arch/__init__.py`: arch package marker.
- `src/angr_rule_learning/arch/registry.py`: angr architecture aliases.
- `src/angr_rule_learning/smt/__init__.py`: SMT helper package marker.
- `src/angr_rule_learning/smt/solver.py`: bit-vector width helpers and counterexample extraction.

Modify these files:

- `src/angr_rule_learning/cli.py`: replace single-file wrapper with batch-oriented wrapper.
- `src/angr_rule_learning/__init__.py`: export core API.
- `examples/aarch64_x86_64_add.json`: migrate to the new schema.
- `README.md`: update usage to JSONL batch command.

Tests:

- `tests/test_schema.py`: strict parsing, rejection of legacy fields, validation errors.
- `tests/test_batch_cli.py`: JSONL batch command and summary output.
- `tests/test_verifier_registers.py`: register equivalence through new API.
- `tests/test_verifier_memory.py`: memory load/store pass and fail cases.

## Task 1: Create Package Skeleton and Public API

**Files:**
- Create: `src/angr_rule_learning/verification/__init__.py`
- Create: `src/angr_rule_learning/verification/errors.py`
- Create: `src/angr_rule_learning/io/__init__.py`
- Create: `src/angr_rule_learning/arch/__init__.py`
- Create: `src/angr_rule_learning/smt/__init__.py`
- Modify: `src/angr_rule_learning/__init__.py`
- Test: `tests/test_public_api.py`

- [ ] **Step 1: Write the failing public API test**

Create `tests/test_public_api.py`:

```python
from angr_rule_learning.verification import (
    BatchVerifier,
    SemanticVerifier,
    VerificationCandidate,
    VerificationReport,
)


def test_verification_package_exports_core_api() -> None:
    assert VerificationCandidate.__name__ == "VerificationCandidate"
    assert VerificationReport.__name__ == "VerificationReport"
    assert SemanticVerifier.__name__ == "SemanticVerifier"
    assert BatchVerifier.__name__ == "BatchVerifier"
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
uv run pytest tests/test_public_api.py -v
```

Expected:

```text
FAILED tests/test_public_api.py::test_verification_package_exports_core_api
```

- [ ] **Step 3: Add minimal placeholder-free package exports**

Create `src/angr_rule_learning/verification/errors.py`:

```python
from __future__ import annotations


class VerificationError(Exception):
    """Raised when a candidate cannot be converted into a verifier run."""
```

Create `src/angr_rule_learning/verification/candidate.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class VerificationCandidate:
    candidate_id: str
```

Create `src/angr_rule_learning/verification/report.py`:

```python
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class VerificationReport:
    candidate_id: str
    status: str
    checks: tuple[object, ...] = field(default_factory=tuple)
```

Create `src/angr_rule_learning/verification/verifier.py`:

```python
from __future__ import annotations

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


class SemanticVerifier:
    def verify(self, candidate: VerificationCandidate) -> VerificationReport:
        return VerificationReport(candidate.candidate_id, "unsupported")
```

Create `src/angr_rule_learning/verification/batch.py`:

```python
from __future__ import annotations

from collections.abc import Iterable

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier


class BatchVerifier:
    def __init__(self, verifier: SemanticVerifier | None = None) -> None:
        self.verifier = verifier or SemanticVerifier()

    def verify_many(
        self, candidates: Iterable[VerificationCandidate]
    ) -> list[VerificationReport]:
        return [self.verifier.verify(candidate) for candidate in candidates]
```

Create `src/angr_rule_learning/verification/__init__.py`:

```python
from angr_rule_learning.verification.batch import BatchVerifier
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier

__all__ = [
    "BatchVerifier",
    "SemanticVerifier",
    "VerificationCandidate",
    "VerificationReport",
]
```

Create `src/angr_rule_learning/io/__init__.py`:

```python
__all__: list[str] = []
```

Create `src/angr_rule_learning/arch/__init__.py`:

```python
__all__: list[str] = []
```

Create `src/angr_rule_learning/smt/__init__.py`:

```python
__all__: list[str] = []
```

Modify `src/angr_rule_learning/__init__.py`:

```python
from angr_rule_learning.verification import (
    BatchVerifier,
    SemanticVerifier,
    VerificationCandidate,
    VerificationReport,
)

__all__ = [
    "BatchVerifier",
    "SemanticVerifier",
    "VerificationCandidate",
    "VerificationReport",
]
```

- [ ] **Step 4: Run the public API test**

Run:

```bash
uv run pytest tests/test_public_api.py -v
```

Expected:

```text
1 passed
```

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_public_api.py -v
git add src/angr_rule_learning tests/test_public_api.py
git commit -m "Create verifier package skeleton"
```

Expected:

```text
All checks passed!
1 passed
```

## Task 2: Define Candidate, Report, and Config Models

**Files:**
- Modify: `src/angr_rule_learning/verification/candidate.py`
- Modify: `src/angr_rule_learning/verification/report.py`
- Create: `src/angr_rule_learning/verification/config.py`
- Test: `tests/test_candidate_models.py`

- [ ] **Step 1: Write model validation tests**

Create `tests/test_candidate_models.py`:

```python
import pytest

from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def test_candidate_normalizes_hex_and_register_names() -> None:
    candidate = VerificationCandidate(
        candidate_id="add",
        guest=CodeFragment("AARCH64", 0x10000, "20 00 02 8b", 1),
        host=CodeFragment("x86-64", 0x8048000, "48_8d_04_11", 1),
        input_registers=(("X1", "RCX"),),
        output_registers=(("X0", "RAX"),),
    )

    assert candidate.guest.arch == "aarch64"
    assert candidate.guest.code_hex == "2000028b"
    assert candidate.host.code_bytes == bytes.fromhex("488d0411")
    assert candidate.input_registers == (("x1", "rcx"),)
    assert candidate.output_registers == (("x0", "rax"),)


def test_memory_model_rejects_invalid_slot_size() -> None:
    with pytest.raises(ValueError, match="memory slot size must be positive"):
        MemorySlot(name="mem0", size=0)


def test_memory_model_rejects_invalid_alias_relation() -> None:
    with pytest.raises(ValueError, match="unsupported alias relation"):
        AliasDeclaration(slots=("mem0", "mem1"), relation="unknown")


def test_memory_access_expectation_rejects_invalid_kind() -> None:
    with pytest.raises(ValueError, match="unsupported memory access kind"):
        MemoryAccessExpectation(slot="mem0", kind="execute", width=4)


def test_report_equivalent_only_when_status_passes() -> None:
    report = VerificationReport(
        candidate_id="add",
        status="pass",
        checks=(CheckResult("register", "pass", "x0", "rax"),),
    )

    assert report.equivalent
    assert report.failure_reasons == {}


def test_config_defaults_are_small_fragment_focused() -> None:
    config = VerificationConfig()

    assert config.max_successors == 1
    assert config.emit_events is False
```

- [ ] **Step 2: Run the failing tests**

Run:

```bash
uv run pytest tests/test_candidate_models.py -v
```

Expected:

```text
FAILED tests/test_candidate_models.py::test_candidate_normalizes_hex_and_register_names
```

- [ ] **Step 3: Implement typed models**

Replace `src/angr_rule_learning/verification/candidate.py` with:

```python
from __future__ import annotations

from dataclasses import dataclass, field


def normalize_register(reg: str) -> str:
    return reg.strip().lower()


def normalize_hex(code_hex: str) -> str:
    parts = code_hex.replace(",", " ").replace("_", " ").split()
    normalized = []
    for part in parts:
        if part.startswith(("0x", "0X")):
            part = part[2:]
        normalized.append(part)
    return "".join(normalized).lower()


@dataclass(frozen=True)
class CodeFragment:
    arch: str
    address: int
    code_hex: str
    instruction_count: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "arch", self.arch.strip().lower())
        object.__setattr__(self, "code_hex", normalize_hex(self.code_hex))
        if self.instruction_count < 1:
            raise ValueError("instruction_count must be positive")

    @property
    def code_bytes(self) -> bytes:
        return bytes.fromhex(self.code_hex)


@dataclass(frozen=True)
class MemorySlot:
    name: str
    size: int
    initial: str = "symbolic"

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "initial", self.initial.strip().lower())
        if not self.name:
            raise ValueError("memory slot name must not be empty")
        if self.size < 1:
            raise ValueError("memory slot size must be positive")
        if self.initial != "symbolic":
            raise ValueError("only symbolic memory slots are supported")


@dataclass(frozen=True)
class MemoryBinding:
    slot: str
    guest_addr: str
    host_addr: str
    access: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot", self.slot.strip())
        object.__setattr__(self, "guest_addr", self.guest_addr.strip().lower())
        object.__setattr__(self, "host_addr", self.host_addr.strip().lower())
        object.__setattr__(self, "access", self.access.strip().lower())
        if self.access not in {"read", "write", "read_write"}:
            raise ValueError("unsupported memory binding access")


@dataclass(frozen=True)
class MemoryAccessExpectation:
    slot: str
    kind: str
    width: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot", self.slot.strip())
        object.__setattr__(self, "kind", self.kind.strip().lower())
        if self.kind not in {"read", "write"}:
            raise ValueError("unsupported memory access kind")
        if self.width < 1:
            raise ValueError("memory access width must be positive")


@dataclass(frozen=True)
class AliasDeclaration:
    slots: tuple[str, ...]
    relation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "slots", tuple(slot.strip() for slot in self.slots))
        object.__setattr__(self, "relation", self.relation.strip().lower())
        if len(self.slots) < 2:
            raise ValueError("alias declaration must include at least two slots")
        if self.relation not in {"disjoint", "must_alias", "may_alias"}:
            raise ValueError("unsupported alias relation")


@dataclass(frozen=True)
class MemorySpec:
    slots: tuple[MemorySlot, ...] = field(default_factory=tuple)
    bindings: tuple[MemoryBinding, ...] = field(default_factory=tuple)
    accesses: tuple[MemoryAccessExpectation, ...] = field(default_factory=tuple)
    alias: tuple[AliasDeclaration, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Clobbers:
    guest: tuple[str, ...] = field(default_factory=tuple)
    host: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "guest", tuple(normalize_register(reg) for reg in self.guest)
        )
        object.__setattr__(
            self, "host", tuple(normalize_register(reg) for reg in self.host)
        )


@dataclass(frozen=True)
class VerificationCandidate:
    candidate_id: str
    guest: CodeFragment
    host: CodeFragment
    input_registers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    output_registers: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    output_flags: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    memory: MemorySpec = field(default_factory=MemorySpec)
    preconditions: tuple[str, ...] = field(default_factory=tuple)
    clobbers: Clobbers = field(default_factory=Clobbers)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", self.candidate_id.strip())
        if not self.candidate_id:
            raise ValueError("candidate_id must not be empty")
        object.__setattr__(
            self,
            "input_registers",
            tuple(
                (normalize_register(guest), normalize_register(host))
                for guest, host in self.input_registers
            ),
        )
        object.__setattr__(
            self,
            "output_registers",
            tuple(
                (normalize_register(guest), normalize_register(host))
                for guest, host in self.output_registers
            ),
        )
        object.__setattr__(
            self,
            "output_flags",
            tuple(
                (normalize_register(guest), normalize_register(host))
                for guest, host in self.output_flags
            ),
        )
```

Replace `src/angr_rule_learning/verification/config.py` with:

```python
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationConfig:
    max_successors: int = 1
    emit_events: bool = False
    memory_base: int = 0x70000000
    memory_stride: int = 0x1000
```

Replace `src/angr_rule_learning/verification/report.py` with:

```python
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    kind: str
    status: str
    guest: str
    host: str
    reason: str = ""
    counterexample: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationReport:
    candidate_id: str
    status: str
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    unsupported_features: tuple[str, ...] = field(default_factory=tuple)
    events: tuple[dict[str, Any], ...] = field(default_factory=tuple)

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

- [ ] **Step 4: Run model tests**

Run:

```bash
uv run pytest tests/test_candidate_models.py -v
```

Expected:

```text
6 passed
```

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_candidate_models.py tests/test_public_api.py -v
git add src/angr_rule_learning/verification tests/test_candidate_models.py
git commit -m "Define verifier candidate and report models"
```

Expected:

```text
All checks passed!
7 passed
```

## Task 3: Add Strict JSON Schema Conversion

**Files:**
- Create: `src/angr_rule_learning/io/schema.py`
- Modify: `src/angr_rule_learning/io/__init__.py`
- Test: `tests/test_schema.py`

- [ ] **Step 1: Write schema tests**

Create `tests/test_schema.py`:

```python
import pytest

from angr_rule_learning.io.schema import candidate_from_json, report_to_json
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _payload() -> dict[str, object]:
    return {
        "candidate_id": "load32",
        "guest": {
            "arch": "aarch64",
            "address": 0x10000,
            "code_hex": "20 00 40 b9",
            "instruction_count": 1,
        },
        "host": {
            "arch": "x86-64",
            "address": 0x8048000,
            "code_hex": "8b 01",
            "instruction_count": 1,
        },
        "inputs": {"registers": [["x1", "rcx"]]},
        "outputs": {"registers": [["w0", "eax"]], "flags": []},
        "memory": {
            "slots": [{"name": "mem0", "size": 4, "initial": "symbolic"}],
            "bindings": [
                {
                    "slot": "mem0",
                    "guest_addr": "x1",
                    "host_addr": "rcx",
                    "access": "read",
                }
            ],
            "accesses": [{"slot": "mem0", "kind": "read", "width": 4}],
            "alias": [],
        },
        "preconditions": [],
        "clobbers": {"guest": [], "host": []},
    }


def test_candidate_from_json_parses_new_schema() -> None:
    candidate = candidate_from_json(_payload())

    assert candidate.candidate_id == "load32"
    assert candidate.guest.arch == "aarch64"
    assert candidate.memory.slots[0].name == "mem0"
    assert candidate.output_registers == (("w0", "eax"),)


def test_candidate_from_json_rejects_legacy_init_map() -> None:
    payload = _payload()
    payload["init_map"] = [["x1", "rcx"]]

    with pytest.raises(ValueError, match="unknown top-level field: init_map"):
        candidate_from_json(payload)


def test_candidate_from_json_rejects_missing_required_field() -> None:
    payload = _payload()
    del payload["guest"]

    with pytest.raises(ValueError, match="missing top-level field: guest"):
        candidate_from_json(payload)


def test_report_to_json_is_stable() -> None:
    report = VerificationReport(
        candidate_id="load32",
        status="fail",
        checks=(
            CheckResult(
                kind="memory",
                status="fail",
                guest="mem0",
                host="mem0",
                reason="memory_read_value_mismatch",
                counterexample={"x1": 1},
            ),
        ),
    )

    assert report_to_json(report) == {
        "candidate_id": "load32",
        "equivalent": False,
        "status": "fail",
        "checks": [
            {
                "kind": "memory",
                "status": "fail",
                "guest": "mem0",
                "host": "mem0",
                "reason": "memory_read_value_mismatch",
                "counterexample": {"x1": 1},
            }
        ],
        "unsupported_features": [],
        "events": [],
        "failure_reasons": {"memory_read_value_mismatch": 1},
    }
```

- [ ] **Step 2: Run failing schema tests**

Run:

```bash
uv run pytest tests/test_schema.py -v
```

Expected:

```text
FAILED tests/test_schema.py::test_candidate_from_json_parses_new_schema
```

- [ ] **Step 3: Implement strict schema conversion**

Create `src/angr_rule_learning/io/schema.py`:

```python
from __future__ import annotations

from typing import Any

from angr_rule_learning.verification.candidate import (
    AliasDeclaration,
    Clobbers,
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.report import VerificationReport


TOP_LEVEL_FIELDS = {
    "candidate_id",
    "guest",
    "host",
    "inputs",
    "outputs",
    "memory",
    "preconditions",
    "clobbers",
}


def candidate_from_json(payload: dict[str, Any]) -> VerificationCandidate:
    _reject_unknown_fields(payload, TOP_LEVEL_FIELDS, "top-level")
    for field in ("candidate_id", "guest", "host"):
        if field not in payload:
            raise ValueError(f"missing top-level field: {field}")

    inputs = _dict(payload.get("inputs", {}), "inputs")
    outputs = _dict(payload.get("outputs", {}), "outputs")
    memory = _dict(payload.get("memory", {}), "memory")
    clobbers = _dict(payload.get("clobbers", {}), "clobbers")

    return VerificationCandidate(
        candidate_id=str(payload["candidate_id"]),
        guest=_fragment_from_json(_dict(payload["guest"], "guest")),
        host=_fragment_from_json(_dict(payload["host"], "host")),
        input_registers=_pairs(inputs.get("registers", []), "inputs.registers"),
        output_registers=_pairs(outputs.get("registers", []), "outputs.registers"),
        output_flags=_pairs(outputs.get("flags", []), "outputs.flags"),
        memory=_memory_from_json(memory),
        preconditions=tuple(str(item) for item in payload.get("preconditions", [])),
        clobbers=Clobbers(
            guest=tuple(str(reg) for reg in clobbers.get("guest", [])),
            host=tuple(str(reg) for reg in clobbers.get("host", [])),
        ),
    )


def report_to_json(report: VerificationReport) -> dict[str, Any]:
    return {
        "candidate_id": report.candidate_id,
        "equivalent": report.equivalent,
        "status": report.status,
        "checks": [
            {
                "kind": check.kind,
                "status": check.status,
                "guest": check.guest,
                "host": check.host,
                "reason": check.reason,
                "counterexample": check.counterexample,
            }
            for check in report.checks
        ],
        "unsupported_features": list(report.unsupported_features),
        "events": list(report.events),
        "failure_reasons": report.failure_reasons,
    }


def _fragment_from_json(payload: dict[str, Any]) -> CodeFragment:
    return CodeFragment(
        arch=str(payload["arch"]),
        address=int(payload["address"]),
        code_hex=str(payload["code_hex"]),
        instruction_count=int(payload["instruction_count"]),
    )


def _memory_from_json(payload: dict[str, Any]) -> MemorySpec:
    return MemorySpec(
        slots=tuple(
            MemorySlot(
                name=str(slot["name"]),
                size=int(slot["size"]),
                initial=str(slot.get("initial", "symbolic")),
            )
            for slot in payload.get("slots", [])
        ),
        bindings=tuple(
            MemoryBinding(
                slot=str(binding["slot"]),
                guest_addr=str(binding["guest_addr"]),
                host_addr=str(binding["host_addr"]),
                access=str(binding["access"]),
            )
            for binding in payload.get("bindings", [])
        ),
        accesses=tuple(
            MemoryAccessExpectation(
                slot=str(access["slot"]),
                kind=str(access["kind"]),
                width=int(access["width"]),
            )
            for access in payload.get("accesses", [])
        ),
        alias=tuple(
            AliasDeclaration(
                slots=tuple(str(slot) for slot in alias["slots"]),
                relation=str(alias["relation"]),
            )
            for alias in payload.get("alias", [])
        ),
    )


def _pairs(value: object, path: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    pairs = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{path} entries must be two-item lists")
        pairs.append((str(item[0]), str(item[1])))
    return tuple(pairs)


def _dict(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _reject_unknown_fields(
    payload: dict[str, Any], allowed: set[str], location: str
) -> None:
    for field in payload:
        if field not in allowed:
            raise ValueError(f"unknown {location} field: {field}")
```

Modify `src/angr_rule_learning/io/__init__.py`:

```python
from angr_rule_learning.io.schema import candidate_from_json, report_to_json

__all__ = ["candidate_from_json", "report_to_json"]
```

- [ ] **Step 4: Run schema tests**

Run:

```bash
uv run pytest tests/test_schema.py -v
```

Expected:

```text
4 passed
```

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_candidate_models.py tests/test_schema.py -v
git add src/angr_rule_learning/io tests/test_schema.py
git commit -m "Add strict verifier JSON schema"
```

Expected:

```text
All checks passed!
10 passed
```

## Task 4: Add Batch Readers, Writers, and CLI Wrapper

**Files:**
- Create: `src/angr_rule_learning/io/readers.py`
- Create: `src/angr_rule_learning/io/writers.py`
- Modify: `src/angr_rule_learning/verification/batch.py`
- Modify: `src/angr_rule_learning/cli.py`
- Test: `tests/test_batch_cli.py`

- [ ] **Step 1: Write batch CLI tests**

Create `tests/test_batch_cli.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from angr_rule_learning.cli import main
from angr_rule_learning.io.readers import read_candidates


def _candidate_payload(candidate_id: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "guest": {
            "arch": "aarch64",
            "address": 0x10000,
            "code_hex": "20 00 02 8b",
            "instruction_count": 1,
        },
        "host": {
            "arch": "x86-64",
            "address": 0x8048000,
            "code_hex": "48 8d 04 11",
            "instruction_count": 1,
        },
        "inputs": {"registers": [["x1", "rcx"], ["x2", "rdx"]]},
        "outputs": {"registers": [["x0", "rax"]], "flags": []},
        "memory": {"slots": [], "bindings": [], "accesses": [], "alias": []},
        "preconditions": [],
        "clobbers": {"guest": [], "host": []},
    }


def test_read_candidates_supports_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "candidates.jsonl"
    path.write_text(
        json.dumps(_candidate_payload("one")) + "\n"
        + json.dumps(_candidate_payload("two")) + "\n",
        encoding="utf-8",
    )

    candidates = list(read_candidates(path))

    assert [candidate.candidate_id for candidate in candidates] == ["one", "two"]


def test_cli_writes_report_jsonl_and_summary(tmp_path: Path) -> None:
    input_path = tmp_path / "candidates.jsonl"
    report_path = tmp_path / "report.jsonl"
    summary_path = tmp_path / "summary.json"
    input_path.write_text(json.dumps(_candidate_payload("one")) + "\n", encoding="utf-8")

    main(
        [
            "verify",
            str(input_path),
            "--output",
            str(report_path),
            "--summary",
            str(summary_path),
        ]
    )

    reports = [
        json.loads(line)
        for line in report_path.read_text(encoding="utf-8").splitlines()
    ]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    assert reports[0]["candidate_id"] == "one"
    assert summary["total"] == 1
    assert "unsupported" in summary["statuses"]
```

- [ ] **Step 2: Run failing batch tests**

Run:

```bash
uv run pytest tests/test_batch_cli.py -v
```

Expected:

```text
FAILED tests/test_batch_cli.py::test_read_candidates_supports_jsonl
```

- [ ] **Step 3: Implement readers, writers, summary, and CLI**

Create `src/angr_rule_learning/io/readers.py`:

```python
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from angr_rule_learning.io.schema import candidate_from_json
from angr_rule_learning.verification.candidate import VerificationCandidate


def read_candidates(path: Path) -> Iterator[VerificationCandidate]:
    if path.is_dir():
        for child in sorted(path.glob("*.json")):
            yield candidate_from_json(json.loads(child.read_text(encoding="utf-8")))
        return
    if path.suffix == ".jsonl":
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                try:
                    yield candidate_from_json(json.loads(line))
                except ValueError as exc:
                    raise ValueError(f"{path}:{line_number}: {exc}") from exc
        return
    yield candidate_from_json(json.loads(path.read_text(encoding="utf-8")))
```

Create `src/angr_rule_learning/io/writers.py`:

```python
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from angr_rule_learning.io.schema import report_to_json
from angr_rule_learning.verification.batch import BatchSummary
from angr_rule_learning.verification.report import VerificationReport


def write_reports_jsonl(path: Path, reports: Iterable[VerificationReport]) -> None:
    with path.open("w", encoding="utf-8") as output:
        for report in reports:
            output.write(json.dumps(report_to_json(report), sort_keys=True))
            output.write("\n")


def write_summary_json(path: Path, summary: BatchSummary) -> None:
    path.write_text(
        json.dumps(summary.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
```

Replace `src/angr_rule_learning/verification/batch.py` with:

```python
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier


@dataclass(frozen=True)
class BatchSummary:
    total: int
    statuses: dict[str, int]
    failure_reasons: dict[str, int]

    def to_json(self) -> dict[str, object]:
        return {
            "total": self.total,
            "statuses": self.statuses,
            "failure_reasons": self.failure_reasons,
        }


class BatchVerifier:
    def __init__(self, verifier: SemanticVerifier | None = None) -> None:
        self.verifier = verifier or SemanticVerifier()

    def verify_many(
        self, candidates: Iterable[VerificationCandidate]
    ) -> list[VerificationReport]:
        return [self.verifier.verify(candidate) for candidate in candidates]

    def summarize(self, reports: Iterable[VerificationReport]) -> BatchSummary:
        report_list = list(reports)
        statuses = Counter(report.status for report in report_list)
        reasons: Counter[str] = Counter()
        for report in report_list:
            reasons.update(report.failure_reasons)
        return BatchSummary(
            total=len(report_list),
            statuses=dict(statuses),
            failure_reasons=dict(reasons),
        )
```

Replace `src/angr_rule_learning/cli.py` with:

```python
from __future__ import annotations

import argparse
from pathlib import Path

from angr_rule_learning.io.readers import read_candidates
from angr_rule_learning.io.writers import write_reports_jsonl, write_summary_json
from angr_rule_learning.verification.batch import BatchVerifier


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="angr-rule-learning")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="verify candidate batches")
    verify_parser.add_argument("input", type=Path)
    verify_parser.add_argument("--output", type=Path, required=True)
    verify_parser.add_argument("--summary", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "verify":
        candidates = list(read_candidates(args.input))
        batch = BatchVerifier()
        reports = batch.verify_many(candidates)
        write_reports_jsonl(args.output, reports)
        write_summary_json(args.summary, batch.summarize(reports))
```

- [ ] **Step 4: Run batch tests**

Run:

```bash
uv run pytest tests/test_batch_cli.py -v
```

Expected:

```text
2 passed
```

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_batch_cli.py tests/test_schema.py tests/test_public_api.py -v
git add src/angr_rule_learning/io src/angr_rule_learning/verification/batch.py src/angr_rule_learning/cli.py tests/test_batch_cli.py
git commit -m "Add batch verifier CLI boundary"
```

Expected:

```text
All checks passed!
7 passed
```

## Task 5: Port Register Verification to the New API

**Files:**
- Create: `src/angr_rule_learning/arch/registry.py`
- Create: `src/angr_rule_learning/smt/solver.py`
- Create: `src/angr_rule_learning/verification/execution.py`
- Create: `src/angr_rule_learning/verification/checks.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Modify: `tests/test_verifier_registers.py`

- [ ] **Step 1: Rewrite register tests against `VerificationCandidate`**

Replace `tests/test_verifier_registers.py` with:

```python
from angr_rule_learning.verification.candidate import CodeFragment, VerificationCandidate
from angr_rule_learning.verification.verifier import SemanticVerifier


AARCH64_ADD_X0_X1_X2 = "20 00 02 8b"
X86_64_LEA_RAX_RCX_RDX = "48 8d 04 11"
X86_64_MOV_RAX_RCX = "48 89 c8"


def _candidate(host_hex: str) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="add",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_ADD_X0_X1_X2, 1),
        host=CodeFragment("x86-64", 0x8048000, host_hex, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("x0", "rax"),),
    )


def test_verifier_accepts_equivalent_register_outputs() -> None:
    result = SemanticVerifier().verify(_candidate(X86_64_LEA_RAX_RCX_RDX))

    assert result.equivalent
    assert result.status == "pass"
    assert result.checks[0].status == "pass"


def test_verifier_rejects_register_counterexample() -> None:
    result = SemanticVerifier().verify(_candidate(X86_64_MOV_RAX_RCX))

    assert not result.equivalent
    assert result.status == "fail"
    assert result.checks[0].reason == "register_mismatch"
    assert "x2" in result.checks[0].counterexample
```

- [ ] **Step 2: Run failing register tests**

Run:

```bash
uv run pytest tests/test_verifier_registers.py -v
```

Expected:

```text
FAILED tests/test_verifier_registers.py::test_verifier_accepts_equivalent_register_outputs
```

- [ ] **Step 3: Add arch and SMT helpers**

Create `src/angr_rule_learning/arch/registry.py`:

```python
from __future__ import annotations


ARCH_ALIASES = {
    "arm": "ARMEL",
    "armel": "ARMEL",
    "x86": "X86",
    "i386": "X86",
    "amd64": "AMD64",
    "x86_64": "AMD64",
    "x86-64": "AMD64",
    "aarch64": "AARCH64",
    "arm64": "AARCH64",
}


def angr_arch_name(arch: str) -> str:
    normalized = arch.strip().lower()
    try:
        return ARCH_ALIASES[normalized]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {arch}") from exc
```

Create `src/angr_rule_learning/smt/solver.py`:

```python
from __future__ import annotations

import claripy


def fit_width(value: claripy.ast.BV, width: int) -> claripy.ast.BV:
    if value.size() == width:
        return value
    if value.size() < width:
        return value.zero_extend(width - value.size())
    return value[width - 1 : 0]


def align_widths(
    left: claripy.ast.BV, right: claripy.ast.BV
) -> tuple[claripy.ast.BV, claripy.ast.BV]:
    width = max(left.size(), right.size())
    return fit_width(left, width), fit_width(right, width)


def merged_solver(*states: object) -> claripy.Solver:
    solver = claripy.Solver()
    for state in states:
        state_solver = state.solver
        if state_solver.constraints:
            solver.add(*state_solver.constraints)
    return solver
```

- [ ] **Step 4: Add execution wrapper**

Create `src/angr_rule_learning/verification/execution.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
import logging

logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

import angr
import claripy

from angr_rule_learning.arch.registry import angr_arch_name
from angr_rule_learning.smt.solver import fit_width
from angr_rule_learning.verification.candidate import CodeFragment


@dataclass(frozen=True)
class ExecutedFragment:
    state: angr.SimState


class FragmentExecutor:
    def make_state(self, fragment: CodeFragment) -> angr.SimState:
        project = angr.load_shellcode(
            fragment.code_bytes,
            arch=angr_arch_name(fragment.arch),
            load_address=fragment.address,
        )
        return project.factory.blank_state(addr=fragment.address)

    def execute(self, fragment: CodeFragment, state: angr.SimState) -> ExecutedFragment:
        project = angr.load_shellcode(
            fragment.code_bytes,
            arch=angr_arch_name(fragment.arch),
            load_address=fragment.address,
        )
        successors = project.factory.successors(
            state, num_inst=fragment.instruction_count
        ).successors
        if len(successors) != 1:
            raise ValueError(f"expected exactly one successor, got {len(successors)}")
        return ExecutedFragment(successors[0])


def read_reg(state: angr.SimState, reg: str) -> claripy.ast.BV:
    return getattr(state.regs, reg)


def write_reg(state: angr.SimState, reg: str, value: claripy.ast.BV) -> None:
    setattr(state.regs, reg, fit_width(value, reg_width(state, reg)))


def reg_width(state: angr.SimState, reg: str) -> int:
    try:
        _, size = state.arch.registers[reg]
    except KeyError as exc:
        raise ValueError(f"unknown register for {state.arch.name}: {reg}") from exc
    return size * state.arch.byte_width
```

- [ ] **Step 5: Add register checker and verifier**

Create `src/angr_rule_learning/verification/checks.py`:

```python
from __future__ import annotations

import claripy

from angr_rule_learning.smt.solver import align_widths, merged_solver
from angr_rule_learning.verification.execution import read_reg
from angr_rule_learning.verification.report import CheckResult


def check_register_pair(
    guest_state: object,
    host_state: object,
    guest_reg: str,
    host_reg: str,
    symbols: dict[str, claripy.ast.BV],
) -> CheckResult:
    guest_value = read_reg(guest_state, guest_reg)
    host_value = read_reg(host_state, host_reg)
    guest_value, host_value = align_widths(guest_value, host_value)
    diff = guest_value != host_value
    solver = merged_solver(guest_state, host_state)
    if solver.satisfiable(extra_constraints=[diff]):
        solver.add(diff)
        return CheckResult(
            kind="register",
            status="fail",
            guest=guest_reg,
            host=host_reg,
            reason="register_mismatch",
            counterexample={
                reg: solver.eval(symbol, 1)[0] for reg, symbol in symbols.items()
            },
        )
    return CheckResult("register", "pass", guest_reg, host_reg)
```

Replace `src/angr_rule_learning/verification/verifier.py` with:

```python
from __future__ import annotations

import claripy

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.execution import (
    FragmentExecutor,
    reg_width,
    write_reg,
)
from angr_rule_learning.verification.checks import check_register_pair
from angr_rule_learning.verification.report import CheckResult, VerificationReport


class SemanticVerifier:
    def __init__(self, executor: FragmentExecutor | None = None) -> None:
        self.executor = executor or FragmentExecutor()

    def verify(self, candidate: VerificationCandidate) -> VerificationReport:
        if candidate.output_flags:
            return VerificationReport(
                candidate_id=candidate.candidate_id,
                status="unsupported",
                unsupported_features=("flag_outputs",),
            )

        guest_state = self.executor.make_state(candidate.guest)
        host_state = self.executor.make_state(candidate.host)

        symbols: dict[str, claripy.ast.BV] = {}
        for guest_reg, host_reg in candidate.input_registers:
            width = max(reg_width(guest_state, guest_reg), reg_width(host_state, host_reg))
            symbol = claripy.BVS(f"init_{guest_reg}_{host_reg}", width)
            symbols[guest_reg] = symbol
            symbols[host_reg] = symbol
            write_reg(guest_state, guest_reg, symbol)
            write_reg(host_state, host_reg, symbol)

        try:
            guest_final = self.executor.execute(candidate.guest, guest_state)
            host_final = self.executor.execute(candidate.host, host_state)
        except ValueError:
            return VerificationReport(
                candidate_id=candidate.candidate_id,
                status="unsupported",
                unsupported_features=("multi_successor_unsupported",),
            )

        checks: list[CheckResult] = []
        for guest_reg, host_reg in candidate.output_registers:
            check = check_register_pair(
                guest_final.state, host_final.state, guest_reg, host_reg, symbols
            )
            checks.append(check)
            if check.status == "fail":
                return VerificationReport(candidate.candidate_id, "fail", tuple(checks))

        return VerificationReport(candidate.candidate_id, "pass", tuple(checks))
```

- [ ] **Step 6: Run register tests**

Run:

```bash
uv run pytest tests/test_verifier_registers.py -v
```

Expected:

```text
2 passed
```

- [ ] **Step 7: Run broader tests and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_public_api.py tests/test_candidate_models.py tests/test_schema.py tests/test_batch_cli.py tests/test_verifier_registers.py -v
git add src/angr_rule_learning tests/test_verifier_registers.py
git commit -m "Port register verifier to typed API"
```

Expected:

```text
All checks passed!
15 passed
```

## Task 6: Add Memory Slot Initialization and Event Recording

**Files:**
- Create: `src/angr_rule_learning/verification/memory.py`
- Modify: `src/angr_rule_learning/verification/execution.py`
- Test: `tests/test_memory_events.py`

- [ ] **Step 1: Write memory event tests**

Create `tests/test_memory_events.py`:

```python
from angr_rule_learning.verification.candidate import (
    CodeFragment,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import FragmentExecutor
from angr_rule_learning.verification.memory import MemoryInitializer, MemoryEventRecorder


def test_memory_initializer_binds_guest_and_host_address_registers() -> None:
    candidate = VerificationCandidate(
        candidate_id="load",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
        ),
    )
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)

    layout = MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )

    assert layout.slot_base("mem0") == 0x70000000
    assert guest_state.solver.eval(guest_state.regs.x1) == 0x70000000
    assert host_state.solver.eval(host_state.regs.rcx) == 0x70000000


def test_memory_event_recorder_captures_read_event() -> None:
    candidate = VerificationCandidate(
        candidate_id="load",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
        ),
    )
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)
    initializer = MemoryInitializer(VerificationConfig())
    initializer.initialize(candidate, guest_state, host_state)
    recorder = MemoryEventRecorder()
    recorder.install(guest_state, "guest")
    recorder.install(host_state, "host")

    executor.execute(candidate.guest, guest_state)
    executor.execute(candidate.host, host_state)

    assert recorder.events[0].side == "guest"
    assert recorder.events[0].kind == "read"
    assert recorder.events[1].side == "host"
    assert recorder.events[1].kind == "read"
```

- [ ] **Step 2: Run failing memory event tests**

Run:

```bash
uv run pytest tests/test_memory_events.py -v
```

Expected:

```text
FAILED tests/test_memory_events.py::test_memory_initializer_binds_guest_and_host_address_registers
```

- [ ] **Step 3: Implement memory layout and recorder**

Create `src/angr_rule_learning/verification/memory.py`:

```python
from __future__ import annotations

from dataclasses import dataclass

import angr
import claripy

from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import write_reg


@dataclass(frozen=True)
class MemoryLayout:
    bases: dict[str, int]

    def slot_base(self, slot: str) -> int:
        return self.bases[slot]


@dataclass(frozen=True)
class MemoryEvent:
    side: str
    kind: str
    address: claripy.ast.BV
    value: claripy.ast.BV
    width: int
    endness: str


class MemoryInitializer:
    def __init__(self, config: VerificationConfig) -> None:
        self.config = config

    def initialize(
        self,
        candidate: VerificationCandidate,
        guest_state: object,
        host_state: object,
    ) -> MemoryLayout:
        bases = {
            slot.name: self.config.memory_base + index * self.config.memory_stride
            for index, slot in enumerate(candidate.memory.slots)
        }
        for slot in candidate.memory.slots:
            content = claripy.BVS(f"{candidate.candidate_id}_{slot.name}_init", slot.size * 8)
            base = bases[slot.name]
            guest_state.memory.store(base, content, endness=guest_state.arch.memory_endness)
            host_state.memory.store(base, content, endness=host_state.arch.memory_endness)

        for binding in candidate.memory.bindings:
            base_value = claripy.BVV(bases[binding.slot], guest_state.arch.bits)
            write_reg(guest_state, binding.guest_addr, base_value)
            host_base_value = claripy.BVV(bases[binding.slot], host_state.arch.bits)
            write_reg(host_state, binding.host_addr, host_base_value)

        return MemoryLayout(bases)


class MemoryEventRecorder:
    def __init__(self) -> None:
        self.events: list[MemoryEvent] = []

    def install(self, state: object, side: str) -> None:
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=self._read(side))
        state.inspect.b("mem_write", when=angr.BP_AFTER, action=self._write(side))

    def _read(self, side: str) -> object:
        def record(state: object) -> None:
            length = state.inspect.mem_read_length
            self.events.append(
                MemoryEvent(
                    side=side,
                    kind="read",
                    address=state.inspect.mem_read_address,
                    value=state.inspect.mem_read_expr,
                    width=int(length) if isinstance(length, int) else state.solver.eval(length),
                    endness=state.arch.memory_endness,
                )
            )

        return record

    def _write(self, side: str) -> object:
        def record(state: object) -> None:
            length = state.inspect.mem_write_length
            self.events.append(
                MemoryEvent(
                    side=side,
                    kind="write",
                    address=state.inspect.mem_write_address,
                    value=state.inspect.mem_write_expr,
                    width=int(length) if isinstance(length, int) else state.solver.eval(length),
                    endness=state.arch.memory_endness,
                )
            )

        return record
```

- [ ] **Step 4: Run memory event tests**

Run:

```bash
uv run pytest tests/test_memory_events.py -v
```

Expected:

```text
2 passed
```

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest tests/test_memory_events.py tests/test_verifier_registers.py -v
git add src/angr_rule_learning/verification/memory.py tests/test_memory_events.py
git commit -m "Add memory slot initialization and events"
```

Expected:

```text
All checks passed!
4 passed
```

## Task 7: Verify Memory Load and Store Equivalence

**Files:**
- Modify: `src/angr_rule_learning/verification/checks.py`
- Modify: `src/angr_rule_learning/verification/verifier.py`
- Test: `tests/test_verifier_memory.py`

- [ ] **Step 1: Write memory verifier tests**

Create `tests/test_verifier_memory.py`:

```python
from angr_rule_learning.verification.candidate import (
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.verifier import SemanticVerifier


def test_verifier_accepts_equivalent_load() -> None:
    candidate = VerificationCandidate(
        candidate_id="load32",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "8b 01", 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.equivalent
    assert report.status == "pass"


def test_verifier_rejects_load_width_mismatch() -> None:
    candidate = VerificationCandidate(
        candidate_id="load-width",
        guest=CodeFragment("aarch64", 0x10000, "20 00 40 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "48 8b 01", 1),
        output_registers=(("w0", "rax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 8),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert report.checks[0].reason == "memory_access_width_mismatch"


def test_verifier_accepts_equivalent_store() -> None:
    candidate = VerificationCandidate(
        candidate_id="store32",
        guest=CodeFragment("aarch64", 0x10000, "20 00 00 b9", 1),
        host=CodeFragment("x86-64", 0x8048000, "89 01", 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.equivalent
    assert report.status == "pass"
```

- [ ] **Step 2: Run failing memory verifier tests**

Run:

```bash
uv run pytest tests/test_verifier_memory.py -v
```

Expected:

```text
FAILED tests/test_verifier_memory.py::test_verifier_accepts_equivalent_load
```

- [ ] **Step 3: Add memory relational checks**

Append to `src/angr_rule_learning/verification/checks.py`:

```python
from angr_rule_learning.verification.candidate import MemoryAccessExpectation
from angr_rule_learning.verification.memory import MemoryEvent, MemoryLayout


def check_memory_events(
    expectations: tuple[MemoryAccessExpectation, ...],
    layout: MemoryLayout,
    events: list[MemoryEvent],
) -> list[CheckResult]:
    guest_events = [event for event in events if event.side == "guest"]
    host_events = [event for event in events if event.side == "host"]
    if len(guest_events) != len(expectations) or len(host_events) != len(expectations):
        return [
            CheckResult(
                kind="memory",
                status="fail",
                guest="events",
                host="events",
                reason="memory_access_count_mismatch",
            )
        ]

    checks: list[CheckResult] = []
    for expectation, guest_event, host_event in zip(
        expectations, guest_events, host_events, strict=True
    ):
        if guest_event.kind != expectation.kind or host_event.kind != expectation.kind:
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=guest_event.kind,
                    host=host_event.kind,
                    reason="memory_access_kind_mismatch",
                )
            )
            continue
        if guest_event.width != expectation.width or host_event.width != expectation.width:
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=str(guest_event.width),
                    host=str(host_event.width),
                    reason="memory_access_width_mismatch",
                )
            )
            continue

        base = layout.slot_base(expectation.slot)
        guest_addr_solver = claripy.Solver()
        host_addr_solver = claripy.Solver()
        if guest_addr_solver.satisfiable(extra_constraints=[guest_event.address != base]):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=expectation.slot,
                    host=expectation.slot,
                    reason="memory_address_mismatch",
                )
            )
            continue
        if host_addr_solver.satisfiable(extra_constraints=[host_event.address != base]):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=expectation.slot,
                    host=expectation.slot,
                    reason="memory_address_mismatch",
                )
            )
            continue

        guest_value, host_value = align_widths(guest_event.value, host_event.value)
        solver = claripy.Solver()
        diff = guest_value != host_value
        if solver.satisfiable(extra_constraints=[diff]):
            checks.append(
                CheckResult(
                    kind="memory",
                    status="fail",
                    guest=expectation.slot,
                    host=expectation.slot,
                    reason=(
                        "memory_read_value_mismatch"
                        if expectation.kind == "read"
                        else "memory_write_value_mismatch"
                    ),
                )
            )
            continue

        checks.append(
            CheckResult("memory", "pass", expectation.slot, expectation.slot)
        )
    return checks
```

- [ ] **Step 4: Wire memory initialization and checks into verifier**

Modify `src/angr_rule_learning/verification/verifier.py` so `verify()` initializes memory before execution and checks memory before register outputs:

```python
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.memory import MemoryEventRecorder, MemoryInitializer
```

Use this constructor:

```python
    def __init__(
        self,
        executor: FragmentExecutor | None = None,
        config: VerificationConfig | None = None,
    ) -> None:
        self.executor = executor or FragmentExecutor()
        self.config = config or VerificationConfig()
```

Add this block after input register initialization:

```python
        unsupported_alias = tuple(
            "unsupported_may_alias"
            for alias in candidate.memory.alias
            if alias.relation == "may_alias"
        )
        if unsupported_alias:
            return VerificationReport(
                candidate_id=candidate.candidate_id,
                status="unsupported",
                unsupported_features=unsupported_alias,
            )

        layout = MemoryInitializer(self.config).initialize(
            candidate, guest_state, host_state
        )
        recorder = MemoryEventRecorder()
        recorder.install(guest_state, "guest")
        recorder.install(host_state, "host")
```

Add this block after both fragments execute and before register checks:

```python
        from angr_rule_learning.verification.checks import check_memory_events

        memory_checks = check_memory_events(
            candidate.memory.accesses, layout, recorder.events
        )
        checks.extend(memory_checks)
        failed_memory = next(
            (check for check in memory_checks if check.status == "fail"), None
        )
        if failed_memory is not None:
            return VerificationReport(candidate.candidate_id, "fail", tuple(checks))
```

- [ ] **Step 5: Run memory verifier tests**

Run:

```bash
uv run pytest tests/test_verifier_memory.py -v
```

Expected:

```text
3 passed
```

- [ ] **Step 6: Run full tests and commit**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -v
git add src/angr_rule_learning tests/test_verifier_memory.py
git commit -m "Verify memory load and store events"
```

Expected:

```text
All checks passed!
```

`pytest` should report all collected tests passing. Dependency deprecation warnings from angr libraries on Python 3.14 are acceptable if no project test fails.

## Task 8: Update Example, README, and Verify CLI Batch

**Files:**
- Modify: `examples/aarch64_x86_64_add.json`
- Create: `examples/aarch64_x86_64_batch.jsonl`
- Modify: `README.md`
- Test: existing full suite plus CLI command

- [ ] **Step 1: Replace the example JSON with the new schema**

Modify `examples/aarch64_x86_64_add.json`:

```json
{
  "candidate_id": "aarch64-add-x86-64-lea",
  "guest": {
    "arch": "aarch64",
    "address": 65536,
    "code_hex": "20 00 02 8b",
    "instruction_count": 1
  },
  "host": {
    "arch": "x86-64",
    "address": 134512640,
    "code_hex": "48 8d 04 11",
    "instruction_count": 1
  },
  "inputs": {
    "registers": [["x1", "rcx"], ["x2", "rdx"]]
  },
  "outputs": {
    "registers": [["x0", "rax"]],
    "flags": []
  },
  "memory": {
    "slots": [],
    "bindings": [],
    "accesses": [],
    "alias": []
  },
  "preconditions": [],
  "clobbers": {
    "guest": [],
    "host": []
  }
}
```

Create `examples/aarch64_x86_64_batch.jsonl` with one line:

```json
{"candidate_id":"aarch64-add-x86-64-lea","guest":{"arch":"aarch64","address":65536,"code_hex":"20 00 02 8b","instruction_count":1},"host":{"arch":"x86-64","address":134512640,"code_hex":"48 8d 04 11","instruction_count":1},"inputs":{"registers":[["x1","rcx"],["x2","rdx"]]},"outputs":{"registers":[["x0","rax"]],"flags":[]},"memory":{"slots":[],"bindings":[],"accesses":[],"alias":[]},"preconditions":[],"clobbers":{"guest":[],"host":[]}}
```

- [ ] **Step 2: Update README usage**

Modify the usage section in `README.md` so it includes:

```markdown
Run tests:

```bash
uv run pytest
```

Verify a JSONL batch:

```bash
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output report.jsonl --summary summary.json
```

The CLI is an external wrapper around the Python verifier API. Full pipeline
code should call `SemanticVerifier` or `BatchVerifier` directly instead of
shelling out to the CLI.
```

- [ ] **Step 3: Run format, lint, tests, and CLI smoke test**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -v
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-report.jsonl --summary /tmp/angr-rule-learning-summary.json
```

Expected:

```text
All checks passed!
```

`pytest` should pass all collected tests. The CLI command should exit with code
0 and create both `/tmp/angr-rule-learning-report.jsonl` and
`/tmp/angr-rule-learning-summary.json`.

- [ ] **Step 4: Inspect CLI output**

Run:

```bash
cat /tmp/angr-rule-learning-report.jsonl
cat /tmp/angr-rule-learning-summary.json
```

Expected report fields:

```json
{"candidate_id":"aarch64-add-x86-64-lea","equivalent":true,"status":"pass"}
```

The exact JSON key order may differ because writer output is sorted. The report
must include `candidate_id`, `equivalent`, `status`, `checks`,
`unsupported_features`, `events`, and `failure_reasons`.

- [ ] **Step 5: Commit docs and examples**

Run:

```bash
git add README.md examples/aarch64_x86_64_add.json examples/aarch64_x86_64_batch.jsonl
git commit -m "Update examples for batch verifier API"
```

Expected:

```text
[main
```

## Task 9: Final Verification Pass

**Files:**
- No code changes expected.

- [ ] **Step 1: Run the full verification suite**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -v
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-report.jsonl --summary /tmp/angr-rule-learning-summary.json
git status -sb
```

Expected:

```text
All checks passed!
```

`pytest` should pass all collected tests. `git status -sb` should show no
uncommitted source changes after `ruff format`.

- [ ] **Step 2: Review the commit stack**

Run:

```bash
git log --oneline --decorate -8
```

Expected:

```text
The latest commits correspond to the task commits in this plan.
```

- [ ] **Step 3: Report implementation result**

Final implementation summary should include:

```text
- New verifier package layout is in place.
- JSON/JSONL is isolated in io/.
- CLI is batch-oriented and wraps BatchVerifier.
- Register equivalence still passes.
- Memory load/store event checks pass.
- may_alias reports unsupported.
- ruff format, ruff check, pytest, and CLI smoke test results.
```

## Self-Review

Spec coverage:

- Verifier-first architecture: covered by Tasks 1, 4, 5, 7.
- API-first boundary: covered by Tasks 1, 2, 4, 5.
- Strict external JSON schema: covered by Task 3.
- No legacy `init_map` acceptance: covered by Task 3.
- Batch-oriented CLI: covered by Task 4.
- Early package split: covered by Task 1 and the file structure section.
- Memory model and event recording: covered by Tasks 6 and 7.
- SMT contradiction checks: covered by Tasks 5 and 7.
- Failure taxonomy: covered by Tasks 2, 5, and 7.
- Report summary: covered by Task 4.

Known scope split:

- Detailed flag equivalence is modeled as unsupported in this plan. It needs a focused plan after memory verification is stable.
- Coverage comparison against the complete rule table is not implemented here. It should consume the batch report and summary format created by this plan.

Placeholder scan:

- No placeholder tokens or old-schema acceptance steps are present.

Type consistency:

- The plan consistently uses `VerificationCandidate`, `VerificationReport`,
  `SemanticVerifier`, `BatchVerifier`, `MemorySpec`, `MemorySlot`,
  `MemoryBinding`, `MemoryAccessExpectation`, and `AliasDeclaration`.
