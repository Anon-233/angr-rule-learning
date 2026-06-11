# Rule Generalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate plain text AArch64-to-x86-64 rules from verifier-passing extraction windows, using typed register placeholders such as `i32_reg1` and `i64_reg2`.

**Architecture:** Add a focused `angr_rule_learning.rules` package that owns register classification, rule generalization, text formatting, and rule diagnostics. Integrate it into `ExtractionPipeline.run()` only after semantic verification succeeds, so rule output is derived from `WindowPair + VerificationCandidate + VerificationReport` while assembly text is still available.

**Tech Stack:** Python dataclasses, archinfo register metadata through angr dependencies, pytest, ruff, existing extraction pipeline, existing verifier reports, uv.

---

## Design Inputs

Read before implementation:

- `docs/superpowers/specs/2026-06-11-rule-generalization-design.md`
- `src/angr_rule_learning/extraction/models.py`
- `src/angr_rule_learning/extraction/pipeline.py`
- `src/angr_rule_learning/verification/candidate.py`
- `src/angr_rule_learning/verification/report.py`
- `tests/test_extraction_pipeline.py`

Important constraints:

- Do not generate rules from candidate JSONL alone; candidate JSONL lacks assembly text.
- Generate rules only from reports where `report.status == "pass"` and `report.equivalent is True`.
- Keep candidate JSONL, extraction diagnostics, and verifier behavior unchanged when `--rules-output` is not supplied.
- `--rules-output` requires `--verify`.
- First implementation generalizes registers only.
- Immediates, offsets, scale values, labels, and mnemonics remain literal.
- Replace only registers present in candidate input/output pairs.
- Skip a rule if ordinary concrete registers remain after replacement.
- Allow AArch64 `xzr` and `wzr` as literal architectural zero registers.
- Support current integer register rules first; represent float/vector classes in the API but skip ambiguous float/vector rules.
- Run `uv run ruff format` after editing Python files.

## Target File Structure

Create:

- `src/angr_rule_learning/rules/__init__.py`: public rule generation exports.
- `src/angr_rule_learning/rules/registers.py`: register normalization, classification, known-register scanning, and literal-register policy.
- `src/angr_rule_learning/rules/generalize.py`: typed rule records, rule diagnostics, placeholder assignment, instruction text rewriting, and skip decisions.
- `src/angr_rule_learning/rules/writer.py`: text rule formatting and JSON diagnostics writing.
- `tests/test_rules_registers.py`: register classification coverage.
- `tests/test_rules_generalize.py`: placeholder mapping and safe rewrite coverage.
- `tests/test_rules_writer.py`: plain text rule and diagnostics output coverage.
- `docs/rule-generalization.md`: repository-level user/developer documentation for rule output.

Modify:

- `src/angr_rule_learning/extraction/pipeline.py`: keep verified window/candidate/report associations and optionally emit rules.
- `src/angr_rule_learning/cli.py`: add `--rules-output` and `--rules-diagnostics`.
- `tests/test_extraction_pipeline.py`: pipeline-level rule output tests.
- `tests/test_batch_cli.py` or `tests/test_extraction_pipeline.py`: CLI validation for `--rules-output` requiring `--verify`.
- `README.md`: show verified extraction with rule output.
- `docs/architecture.md`: add the `rules/` package and current extraction-to-rule data flow.

---

## Task 1: Register Classification

**Files:**
- Create: `src/angr_rule_learning/rules/__init__.py`
- Create: `src/angr_rule_learning/rules/registers.py`
- Test: `tests/test_rules_registers.py`

- [ ] **Step 1: Write failing register classification tests**

Create `tests/test_rules_registers.py`:

```python
import pytest

from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
    is_allowed_literal_register,
    known_register_tokens,
    normalize_register_name,
)


def test_classifies_aarch64_integer_register_widths() -> None:
    assert classify_register("aarch64", "w0") == RegisterClass("i", 32)
    assert classify_register("aarch64", "x0") == RegisterClass("i", 64)
    assert classify_register("aarch64", "sp") == RegisterClass("i", 64)
    assert classify_register("aarch64", "fp") == RegisterClass("i", 64)
    assert classify_register("aarch64", "lr") == RegisterClass("i", 64)


def test_classifies_x86_64_integer_subregister_widths() -> None:
    assert classify_register("x86-64", "al") == RegisterClass("i", 8)
    assert classify_register("x86-64", "ax") == RegisterClass("i", 16)
    assert classify_register("x86-64", "eax") == RegisterClass("i", 32)
    assert classify_register("x86-64", "rax") == RegisterClass("i", 64)
    assert classify_register("x86-64", "r8d") == RegisterClass("i", 32)
    assert classify_register("x86-64", "r15") == RegisterClass("i", 64)


def test_normalizes_project_arch_names_for_archinfo() -> None:
    assert classify_register("amd64", "edi") == classify_register("x86-64", "edi")
    assert classify_register("aarch64", "X8") == RegisterClass("i", 64)


def test_zero_registers_are_literals_not_classified_operands() -> None:
    assert is_allowed_literal_register("aarch64", "xzr")
    assert is_allowed_literal_register("aarch64", "wzr")
    with pytest.raises(RegisterClassError, match="unknown register"):
        classify_register("aarch64", "xzr")


def test_unknown_registers_raise_unknown_class_error() -> None:
    with pytest.raises(RegisterClassError, match="unknown register"):
        classify_register("aarch64", "notareg")


def test_float_and_vector_registers_are_explicitly_unsupported() -> None:
    with pytest.raises(UnsupportedRegisterClass, match="unsupported register class"):
        classify_register("aarch64", "v0")
    with pytest.raises(UnsupportedRegisterClass, match="unsupported register class"):
        classify_register("x86-64", "xmm0")


def test_known_register_tokens_include_subregisters_and_literals() -> None:
    aarch64 = known_register_tokens("aarch64")
    x86_64 = known_register_tokens("x86-64")

    assert {"w0", "x0", "xzr", "wzr", "sp", "lr"}.issubset(aarch64)
    assert {"al", "eax", "rax", "r8d", "r15"}.issubset(x86_64)


def test_register_class_placeholder_prefix() -> None:
    assert RegisterClass("i", 32).placeholder_prefix == "i32"
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_rules_registers.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'angr_rule_learning.rules'`.

- [ ] **Step 3: Implement register classification**

Create `src/angr_rule_learning/rules/__init__.py`:

```python
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
)

__all__ = [
    "RegisterClass",
    "RegisterClassError",
    "UnsupportedRegisterClass",
    "classify_register",
]
```

Create `src/angr_rule_learning/rules/registers.py`:

```python
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from archinfo import ArchNotFound, arch_from_id


RegisterKind = Literal["i", "f", "v"]


class RegisterClassError(ValueError):
    """Raised when a register cannot be used for rule generalization."""


class UnsupportedRegisterClass(RegisterClassError):
    """Raised when a known register belongs to a class this stage skips."""


@dataclass(frozen=True)
class RegisterClass:
    kind: RegisterKind
    bits: int

    @property
    def placeholder_prefix(self) -> str:
        return f"{self.kind}{self.bits}"


_ARCHINFO_IDS = {
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "amd64",
    "x86_64": "amd64",
    "x86-64": "amd64",
}

_ALLOWED_LITERAL_REGISTERS = {
    "aarch64": frozenset({"xzr", "wzr"}),
}

_UNSUPPORTED_PREFIXES = {
    "aarch64": ("s", "d", "q", "v"),
    "x86-64": ("xmm", "ymm", "zmm", "st", "mm"),
}

_X86_64_INTEGER_FALLBACKS = {
    "al": 8,
    "ah": 8,
    "bl": 8,
    "bh": 8,
    "cl": 8,
    "ch": 8,
    "dl": 8,
    "dh": 8,
    "spl": 8,
    "bpl": 8,
    "sil": 8,
    "dil": 8,
    "ax": 16,
    "bx": 16,
    "cx": 16,
    "dx": 16,
    "sp": 16,
    "bp": 16,
    "si": 16,
    "di": 16,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "esp": 32,
    "ebp": 32,
    "esi": 32,
    "edi": 32,
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "rsp": 64,
    "rbp": 64,
    "rsi": 64,
    "rdi": 64,
}

for index in range(8, 16):
    _X86_64_INTEGER_FALLBACKS[f"r{index}b"] = 8
    _X86_64_INTEGER_FALLBACKS[f"r{index}w"] = 16
    _X86_64_INTEGER_FALLBACKS[f"r{index}d"] = 32
    _X86_64_INTEGER_FALLBACKS[f"r{index}"] = 64

_AARCH64_INTEGER_PATTERN = re.compile(r"^(?:w|x)(?:[0-9]|[12][0-9]|30)$")


def normalize_register_name(register: str) -> str:
    return register.strip().lower()


def canonical_arch_name(arch: str) -> str:
    normalized = arch.strip().lower()
    if normalized in {"amd64", "x86_64", "x86-64"}:
        return "x86-64"
    if normalized in {"aarch64", "arm64"}:
        return "aarch64"
    return normalized


def _archinfo_id(arch: str) -> str:
    return _ARCHINFO_IDS.get(canonical_arch_name(arch), arch.strip().lower())


def is_allowed_literal_register(arch: str, register: str) -> bool:
    canonical = canonical_arch_name(arch)
    return normalize_register_name(register) in _ALLOWED_LITERAL_REGISTERS.get(
        canonical, frozenset()
    )


def classify_register(arch: str, register: str) -> RegisterClass:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    if is_allowed_literal_register(canonical, reg):
        raise RegisterClassError(f"unknown register class for literal register: {reg}")
    if _is_unsupported_register(canonical, reg):
        raise UnsupportedRegisterClass(f"unsupported register class: {canonical}:{reg}")
    if canonical == "aarch64":
        fallback = _classify_aarch64_integer(reg)
        if fallback is not None:
            return fallback
    if canonical == "x86-64" and reg in _X86_64_INTEGER_FALLBACKS:
        return RegisterClass("i", _X86_64_INTEGER_FALLBACKS[reg])

    width_bytes = _archinfo_register_size(canonical, reg)
    if width_bytes is not None:
        return RegisterClass("i", width_bytes * 8)
    raise RegisterClassError(f"unknown register class: {canonical}:{reg}")


def known_register_tokens(arch: str) -> frozenset[str]:
    canonical = canonical_arch_name(arch)
    tokens: set[str] = set(_ALLOWED_LITERAL_REGISTERS.get(canonical, frozenset()))
    tokens.update(_archinfo_register_names(canonical))
    if canonical == "aarch64":
        tokens.update({"sp", "fp", "lr"})
        tokens.update(f"w{index}" for index in range(31))
        tokens.update(f"x{index}" for index in range(31))
    if canonical == "x86-64":
        tokens.update(_X86_64_INTEGER_FALLBACKS)
    return frozenset(tokens)


def _classify_aarch64_integer(reg: str) -> RegisterClass | None:
    if reg in {"sp", "fp", "lr"}:
        return RegisterClass("i", 64)
    if _AARCH64_INTEGER_PATTERN.match(reg):
        return RegisterClass("i", 32 if reg.startswith("w") else 64)
    return None


def _is_unsupported_register(arch: str, reg: str) -> bool:
    prefixes = _UNSUPPORTED_PREFIXES.get(arch, ())
    if not prefixes:
        return False
    return reg.startswith(prefixes) and any(char.isdigit() for char in reg)


@lru_cache(maxsize=None)
def _archinfo_register_names(arch: str) -> frozenset[str]:
    try:
        return frozenset(arch_from_id(_archinfo_id(arch)).registers)
    except ArchNotFound:
        return frozenset()


@lru_cache(maxsize=None)
def _archinfo_register_size(arch: str, reg: str) -> int | None:
    try:
        register = arch_from_id(_archinfo_id(arch)).registers.get(reg)
    except ArchNotFound:
        return None
    if register is None:
        return None
    return int(register[1])
```

- [ ] **Step 4: Run register tests**

Run:

```bash
uv run pytest tests/test_rules_registers.py -v
```

Expected: PASS.

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules tests/test_rules_registers.py
uv run ruff check src/angr_rule_learning/rules tests/test_rules_registers.py
uv run pytest tests/test_rules_registers.py -v
git add src/angr_rule_learning/rules tests/test_rules_registers.py
git commit -m "Add rule register classification" -m "Co-authored-by: Codex <codex@openai.com>" -m "Co-authored-by: Claude Code <noreply@anthropic.com>"
```

Expected: formatting succeeds, lint succeeds, tests pass, commit created.

---

## Task 2: Rule Generalizer Core

**Files:**
- Modify: `src/angr_rule_learning/rules/__init__.py`
- Create: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Write failing generalizer tests**

Create `tests/test_rules_generalize.py`:

```python
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    SourceLocation,
    WindowPair,
)
from angr_rule_learning.rules.generalize import RuleDiagnostics, RuleGeneralizer
from angr_rule_learning.verification.candidate import CodeFragment, VerificationCandidate
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _inst(
    arch: str,
    address: int,
    mnemonic: str,
    op_str: str,
    code_hex: str = "01020304",
) -> ExtractedInstruction:
    code = bytes.fromhex(code_hex)
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=len(code),
        code_bytes=code,
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 1),
    )


def _window_pair(
    guest_instructions: tuple[ExtractedInstruction, ...],
    host_instructions: tuple[ExtractedInstruction, ...],
) -> WindowPair:
    return WindowPair(
        region_id="sample:sample.c:1:0",
        stage=(len(guest_instructions), len(host_instructions)),
        guest=InstructionWindow("sample:sample.c:1:0", "guest", guest_instructions),
        host=InstructionWindow("sample:sample.c:1:0", "host", host_instructions),
    )


def _candidate(
    *,
    inputs: tuple[tuple[str, str], ...] = (),
    outputs: tuple[tuple[str, str], ...] = (),
) -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="sample:sample.c:1:0:g0:h0",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "010203", 1),
        input_registers=inputs,
        output_registers=outputs,
    )


def _passing_report(candidate_id: str = "sample:sample.c:1:0:g0:h0") -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "pass",
        checks=(CheckResult("register", "pass", "w8", "eax"),),
    )


def test_generalizes_output_register_before_input_registers() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w1"),),
        (_inst("x86-64", 0x2000, "lea", "eax, [edi + esi]"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"), ("w1", "esi")), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.rule_id == 1
    assert rule.candidate_id == candidate.candidate_id
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg3",)
    assert rule.host_lines == ("lea i32_reg1, [i32_reg2 + i32_reg3]",)
    assert diagnostics.to_json()["rules_emitted"] == 1


def test_generalizes_multi_instruction_windows() -> None:
    pair = _window_pair(
        (
            _inst("aarch64", 0x1000, "mov", "w8, w0"),
            _inst("aarch64", 0x1004, "add", "w8, w8, #1"),
        ),
        (
            _inst("x86-64", 0x2000, "mov", "eax, edi"),
            _inst("x86-64", 0x2003, "add", "eax, 1"),
        ),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("mov i32_reg1, i32_reg2", "add i32_reg1, i32_reg1, #1")
    assert rule.host_lines == ("mov i32_reg1, i32_reg2", "add i32_reg1, 1")


def test_replacement_is_token_aware() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "x10, x1, x10"),),
        (_inst("x86-64", 0x2000, "add", "r10, rcx"),),
    )
    candidate = _candidate(inputs=(("x1", "rcx"),), outputs=(("x10", "r10"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("add i64_reg1, i64_reg2, i64_reg1",)
    assert rule.host_lines == ("add i64_reg1, i64_reg2",)


def test_allowed_zero_register_literals_may_remain() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "orr", "w8, wzr, w0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("orr i32_reg1, wzr, i32_reg2",)


def test_skips_mismatched_register_classes() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "x8, x0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("x0", "edi"),), outputs=(("x8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    assert diagnostics.to_json()["skip_reasons"] == {"register_class_mismatch": 1}


def test_skips_unknown_register_classes() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "badreg, w0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("badreg", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    assert diagnostics.to_json()["skip_reasons"] == {"unknown_register_class": 1}


def test_skips_unmapped_physical_registers_left_in_assembly() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w2"),),
        (_inst("x86-64", 0x2000, "add", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    assert diagnostics.to_json()["skip_reasons"] == {"unmapped_register_surface": 1}


def test_nonpassing_reports_are_not_considered_for_rule_output() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "w8, w0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("w0", "edi"),), outputs=(("w8", "eax"),))
    diagnostics = RuleDiagnostics()
    report = VerificationReport(
        candidate.candidate_id,
        "fail",
        checks=(CheckResult("register", "fail", "w8", "eax", reason="register_mismatch"),),
    )

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, report)

    assert rule is None
    assert diagnostics.to_json() == {
        "rules_considered": 0,
        "rules_emitted": 0,
        "rules_skipped": 0,
        "skip_reasons": {},
    }
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -v
```

Expected: FAIL because `angr_rule_learning.rules.generalize` is not implemented.

- [ ] **Step 3: Implement generalization**

Create `src/angr_rule_learning/rules/generalize.py`:

```python
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from angr_rule_learning.extraction.models import ExtractedInstruction, WindowPair
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
    is_allowed_literal_register,
    known_register_tokens,
    normalize_register_name,
)
from angr_rule_learning.verification.candidate import VerificationCandidate
from angr_rule_learning.verification.report import VerificationReport


_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*)(?![A-Za-z0-9_])")


@dataclass(frozen=True)
class GeneratedRule:
    rule_id: int
    candidate_id: str
    guest_lines: tuple[str, ...]
    host_lines: tuple[str, ...]


@dataclass
class RuleDiagnostics:
    rules_considered: int = 0
    rules_emitted: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)

    @property
    def rules_skipped(self) -> int:
        return sum(self.skip_reasons.values())

    def record_considered(self) -> None:
        self.rules_considered += 1

    def record_emitted(self) -> None:
        self.rules_emitted += 1

    def record_skipped(self, reason: str) -> None:
        self.skip_reasons.update((reason,))

    def to_json(self) -> dict[str, object]:
        return {
            "rules_considered": self.rules_considered,
            "rules_emitted": self.rules_emitted,
            "rules_skipped": self.rules_skipped,
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
        }


class _RuleSkip(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RuleGeneralizer:
    def __init__(self, diagnostics: RuleDiagnostics | None = None) -> None:
        self.diagnostics = diagnostics or RuleDiagnostics()

    def generate(
        self,
        rule_id: int,
        window: WindowPair,
        candidate: VerificationCandidate,
        report: VerificationReport,
    ) -> GeneratedRule | None:
        if report.status != "pass" or not report.equivalent:
            return None

        self.diagnostics.record_considered()
        try:
            mapping = _build_placeholder_map(candidate)
            guest_lines = _generalize_instructions(
                window.guest.instructions, mapping, "aarch64"
            )
            host_lines = _generalize_instructions(
                window.host.instructions, mapping, "x86-64"
            )
        except _RuleSkip as exc:
            self.diagnostics.record_skipped(exc.reason)
            return None

        rule = GeneratedRule(
            rule_id=rule_id,
            candidate_id=candidate.candidate_id,
            guest_lines=guest_lines,
            host_lines=host_lines,
        )
        self.diagnostics.record_emitted()
        return rule


def _build_placeholder_map(candidate: VerificationCandidate) -> dict[str, str]:
    mapping: dict[str, str] = {}
    next_id = 1
    for guest_reg, host_reg in candidate.output_registers + candidate.input_registers:
        guest_reg = normalize_register_name(guest_reg)
        host_reg = normalize_register_name(host_reg)
        guest_class = _classify_for_rule("aarch64", guest_reg)
        host_class = _classify_for_rule("x86-64", host_reg)
        if guest_class != host_class:
            raise _RuleSkip("register_class_mismatch")
        existing = mapping.get(guest_reg) or mapping.get(host_reg)
        if existing is None:
            existing = f"{guest_class.placeholder_prefix}_reg{next_id}"
            next_id += 1
        for register in (guest_reg, host_reg):
            previous = mapping.get(register)
            if previous is not None and previous != existing:
                raise _RuleSkip("unsupported_rule_shape")
            mapping[register] = existing
    if not mapping:
        raise _RuleSkip("unsupported_rule_shape")
    return mapping


def _classify_for_rule(arch: str, register: str) -> RegisterClass:
    try:
        return classify_register(arch, register)
    except UnsupportedRegisterClass as exc:
        raise _RuleSkip("unsupported_register_class") from exc
    except RegisterClassError as exc:
        raise _RuleSkip("unknown_register_class") from exc


def _generalize_instructions(
    instructions: tuple[ExtractedInstruction, ...],
    mapping: dict[str, str],
    arch: str,
) -> tuple[str, ...]:
    lines = tuple(_generalize_line(_instruction_text(inst), mapping, arch) for inst in instructions)
    if not lines:
        raise _RuleSkip("unsupported_rule_shape")
    return lines


def _instruction_text(instruction: ExtractedInstruction) -> str:
    op_str = instruction.op_str.strip()
    mnemonic = instruction.mnemonic.strip()
    if op_str:
        return f"{mnemonic} {op_str}"
    return mnemonic


def _generalize_line(text: str, mapping: dict[str, str], arch: str) -> str:
    rewritten = text
    for register, replacement in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        rewritten = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(register)}(?![A-Za-z0-9_])",
            replacement,
            rewritten,
            flags=re.IGNORECASE,
        )
    if _remaining_registers(rewritten, arch):
        raise _RuleSkip("unmapped_register_surface")
    return rewritten


def _remaining_registers(text: str, arch: str) -> tuple[str, ...]:
    known = known_register_tokens(arch)
    remaining = []
    for token in _TOKEN_RE.findall(text.lower()):
        if is_allowed_literal_register(arch, token):
            continue
        if token in known:
            remaining.append(token)
    return tuple(remaining)
```

After adding this file, update `src/angr_rule_learning/rules/__init__.py` to export `GeneratedRule`, `RuleDiagnostics`, and `RuleGeneralizer` from `generalize.py`. Do not import writer functions until Task 3 creates `writer.py`.

```python
from angr_rule_learning.rules.generalize import (
    GeneratedRule,
    RuleDiagnostics,
    RuleGeneralizer,
)
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
)

__all__ = [
    "GeneratedRule",
    "RegisterClass",
    "RegisterClassError",
    "RuleDiagnostics",
    "RuleGeneralizer",
    "UnsupportedRegisterClass",
    "classify_register",
]
```

- [ ] **Step 4: Run generalizer tests**

Run:

```bash
uv run pytest tests/test_rules_registers.py tests/test_rules_generalize.py -v
```

Expected: PASS.

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules tests/test_rules_generalize.py
uv run ruff check src/angr_rule_learning/rules tests/test_rules_generalize.py
uv run pytest tests/test_rules_registers.py tests/test_rules_generalize.py -v
git add src/angr_rule_learning/rules tests/test_rules_generalize.py
git commit -m "Generalize verified rule windows" -m "Co-authored-by: Codex <codex@openai.com>" -m "Co-authored-by: Claude Code <noreply@anthropic.com>"
```

Expected: formatting succeeds, lint succeeds, tests pass, commit created.

---

## Task 3: Rule Text Writer And Diagnostics Output

**Files:**
- Modify: `src/angr_rule_learning/rules/__init__.py`
- Create: `src/angr_rule_learning/rules/writer.py`
- Test: `tests/test_rules_writer.py`

- [ ] **Step 1: Write failing writer tests**

Create `tests/test_rules_writer.py`:

```python
import json
from pathlib import Path

from angr_rule_learning.rules.generalize import GeneratedRule, RuleDiagnostics
from angr_rule_learning.rules.writer import (
    format_rule,
    write_rule_diagnostics_json,
    write_rules_text,
)


def test_format_rule_uses_requested_plain_text_shape() -> None:
    rule = GeneratedRule(
        rule_id=1,
        candidate_id="candidate0",
        guest_lines=("add i32_reg1, i32_reg2, i32_reg3",),
        host_lines=("lea i32_reg1, [i32_reg2 + i32_reg3]",),
    )

    assert format_rule(rule) == (
        "1.Guest:\n"
        "\tadd i32_reg1, i32_reg2, i32_reg3\n"
        ".Host:\n"
        "\tlea i32_reg1, [i32_reg2 + i32_reg3]\n"
        "\n"
    )


def test_format_rule_preserves_multi_instruction_lines() -> None:
    rule = GeneratedRule(
        rule_id=7,
        candidate_id="candidate7",
        guest_lines=("mov i32_reg1, i32_reg2", "add i32_reg1, i32_reg1, #1"),
        host_lines=("mov i32_reg1, i32_reg2", "add i32_reg1, 1"),
    )

    assert format_rule(rule) == (
        "7.Guest:\n"
        "\tmov i32_reg1, i32_reg2\n"
        "\tadd i32_reg1, i32_reg1, #1\n"
        ".Host:\n"
        "\tmov i32_reg1, i32_reg2\n"
        "\tadd i32_reg1, 1\n"
        "\n"
    )


def test_write_rules_text_creates_parent_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "rules.txt"
    rule = GeneratedRule(
        rule_id=1,
        candidate_id="candidate0",
        guest_lines=("mov i32_reg1, i32_reg2",),
        host_lines=("mov i32_reg1, i32_reg2",),
    )

    write_rules_text(path, (rule,))

    assert path.read_text(encoding="utf-8") == (
        "1.Guest:\n"
        "\tmov i32_reg1, i32_reg2\n"
        ".Host:\n"
        "\tmov i32_reg1, i32_reg2\n"
        "\n"
    )


def test_write_rule_diagnostics_json(tmp_path: Path) -> None:
    diagnostics = RuleDiagnostics()
    diagnostics.record_considered()
    diagnostics.record_skipped("unmapped_register_surface")
    path = tmp_path / "nested" / "rules_diagnostics.json"

    write_rule_diagnostics_json(path, diagnostics)

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "rules_considered": 1,
        "rules_emitted": 0,
        "rules_skipped": 1,
        "skip_reasons": {"unmapped_register_surface": 1},
    }
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_rules_writer.py -v
```

Expected: FAIL because `angr_rule_learning.rules.writer` is not implemented.

- [ ] **Step 3: Implement writer**

Create `src/angr_rule_learning/rules/writer.py`:

```python
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from angr_rule_learning.rules.generalize import GeneratedRule, RuleDiagnostics


def format_rule(rule: GeneratedRule) -> str:
    lines = [f"{rule.rule_id}.Guest:"]
    lines.extend(f"\t{line}" for line in rule.guest_lines)
    lines.append(".Host:")
    lines.extend(f"\t{line}" for line in rule.host_lines)
    lines.append("")
    return "\n".join(lines) + "\n"


def write_rules_text(path: Path, rules: Iterable[GeneratedRule]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(format_rule(rule) for rule in rules), encoding="utf-8")


def write_rule_diagnostics_json(path: Path, diagnostics: RuleDiagnostics) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(diagnostics.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
```

Update `src/angr_rule_learning/rules/__init__.py`:

```python
from angr_rule_learning.rules.generalize import (
    GeneratedRule,
    RuleDiagnostics,
    RuleGeneralizer,
)
from angr_rule_learning.rules.registers import (
    RegisterClass,
    RegisterClassError,
    UnsupportedRegisterClass,
    classify_register,
)
from angr_rule_learning.rules.writer import (
    format_rule,
    write_rule_diagnostics_json,
    write_rules_text,
)

__all__ = [
    "GeneratedRule",
    "RegisterClass",
    "RegisterClassError",
    "RuleDiagnostics",
    "RuleGeneralizer",
    "UnsupportedRegisterClass",
    "classify_register",
    "format_rule",
    "write_rule_diagnostics_json",
    "write_rules_text",
]
```

- [ ] **Step 4: Run writer tests**

Run:

```bash
uv run pytest tests/test_rules_writer.py tests/test_rules_generalize.py tests/test_rules_registers.py -v
```

Expected: PASS.

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules tests/test_rules_writer.py
uv run ruff check src/angr_rule_learning/rules tests/test_rules_writer.py
uv run pytest tests/test_rules_writer.py tests/test_rules_generalize.py tests/test_rules_registers.py -v
git add src/angr_rule_learning/rules tests/test_rules_writer.py
git commit -m "Write generalized rule text" -m "Co-authored-by: Codex <codex@openai.com>" -m "Co-authored-by: Claude Code <noreply@anthropic.com>"
```

Expected: formatting succeeds, lint succeeds, tests pass, commit created.

---

## Task 4: Pipeline Rule Output Integration

**Files:**
- Modify: `src/angr_rule_learning/extraction/pipeline.py`
- Modify: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Write failing pipeline tests**

Append to `tests/test_extraction_pipeline.py`:

```python
from angr_rule_learning.verification.report import CheckResult, VerificationReport


class _FakePassingVerifier:
    def verify_many(self, candidates):
        return [
            VerificationReport(
                candidate.candidate_id,
                "pass",
                checks=(
                    CheckResult(
                        kind="register",
                        status="pass",
                        guest=candidate.output_registers[0][0],
                        host=candidate.output_registers[0][1],
                    ),
                ),
            )
            for candidate in candidates
        ]


class _FakeFailingVerifier:
    def verify_many(self, candidates):
        return [
            VerificationReport(
                candidate.candidate_id,
                "fail",
                checks=(
                    CheckResult(
                        kind="register",
                        status="fail",
                        guest=candidate.output_registers[0][0],
                        host=candidate.output_registers[0][1],
                        reason="register_mismatch",
                    ),
                ),
            )
            for candidate in candidates
        ]


def _asm_inst(
    arch: str,
    address: int,
    code: bytes,
    mnemonic: str,
    op_str: str,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=len(code),
        code_bytes=code,
        mnemonic=mnemonic,
        op_str=op_str,
        function="add",
        source=SourceLocation("sample.c", 1),
        read_registers=reads,
        write_registers=writes,
    )


def test_pipeline_writes_rules_for_verified_passing_windows(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    candidates_output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules" / "rules.txt"
    rules_diagnostics = tmp_path / "rules" / "rules_diagnostics.json"
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(
            _asm_inst(
                "aarch64",
                0x1000,
                bytes.fromhex("2000020b"),
                "add",
                "w0, w0, w1",
                ("w0", "w1"),
                ("w0",),
            ),
        ),
        host_instructions=(
            _asm_inst(
                "x86-64",
                0x2000,
                bytes.fromhex("01f0"),
                "add",
                "eax, esi",
                ("eax", "esi"),
                ("eax",),
            ),
        ),
    )
    pipeline = ExtractionPipeline(
        build_driver=None,
        object_extractor=None,
        region_provider=lambda config, diagnostics: (region,),
        verifier=_FakePassingVerifier(),
    )

    result = pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=candidates_output,
        diagnostics_output=diagnostics_path,
        verify=True,
        rules_output=rules_output,
        rules_diagnostics_output=rules_diagnostics,
    )

    assert len(result.candidates) == 1
    assert len(result.reports) == 1
    assert len(result.rules) == 1
    assert rules_output.read_text(encoding="utf-8") == (
        "1.Guest:\n"
        "\tadd i32_reg1, i32_reg1, i32_reg2\n"
        ".Host:\n"
        "\tadd i32_reg1, i32_reg2\n"
        "\n"
    )
    assert json.loads(rules_diagnostics.read_text(encoding="utf-8")) == {
        "rules_considered": 1,
        "rules_emitted": 1,
        "rules_skipped": 0,
        "skip_reasons": {},
    }


def test_pipeline_does_not_write_rules_for_failing_reports(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    candidates_output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules.txt"
    region = AlignmentRegion(
        region_id="add:sample.c:1:0",
        function="add",
        source_file="sample.c",
        source_lines=(1,),
        guest_instructions=(
            _asm_inst("aarch64", 0x1000, b"\x01\x02\x03\x04", "add", "w0, w0, w1", ("w0", "w1"), ("w0",)),
        ),
        host_instructions=(
            _asm_inst("x86-64", 0x2000, b"\x01\xf0", "add", "eax, esi", ("eax", "esi"), ("eax",)),
        ),
    )
    pipeline = ExtractionPipeline(
        build_driver=None,
        object_extractor=None,
        region_provider=lambda config, diagnostics: (region,),
        verifier=_FakeFailingVerifier(),
    )

    result = pipeline.run(
        ExtractionConfig(source=source, work_dir=tmp_path / "work"),
        candidates_output=candidates_output,
        diagnostics_output=diagnostics_path,
        verify=True,
        rules_output=rules_output,
    )

    assert result.rules == ()
    assert rules_output.read_text(encoding="utf-8") == ""


def test_pipeline_rejects_rules_output_without_verification(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    pipeline = ExtractionPipeline(region_provider=lambda config, diagnostics: ())

    with pytest.raises(ValueError, match="rule output requires verify=True"):
        pipeline.run(
            ExtractionConfig(source=source, work_dir=tmp_path / "work"),
            candidates_output=tmp_path / "candidates.jsonl",
            diagnostics_output=tmp_path / "diagnostics.json",
            verify=False,
            rules_output=tmp_path / "rules.txt",
        )


def test_pipeline_rejects_rules_diagnostics_without_verification(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    pipeline = ExtractionPipeline(region_provider=lambda config, diagnostics: ())

    with pytest.raises(ValueError, match="rule output requires verify=True"):
        pipeline.run(
            ExtractionConfig(source=source, work_dir=tmp_path / "work"),
            candidates_output=tmp_path / "candidates.jsonl",
            diagnostics_output=tmp_path / "diagnostics.json",
            verify=False,
            rules_diagnostics_output=tmp_path / "rules_diagnostics.json",
        )
```

Also add `import pytest` near the top of `tests/test_extraction_pipeline.py` if absent.

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_pipeline.py -v
```

Expected: FAIL because `ExtractionPipeline.run()` has no `rules_output`, no `rules_diagnostics_output`, and `ExtractionResult` has no `rules`.

- [ ] **Step 3: Integrate rule generation into pipeline**

Modify imports in `src/angr_rule_learning/extraction/pipeline.py`:

```python
from angr_rule_learning.rules.generalize import GeneratedRule, RuleDiagnostics, RuleGeneralizer
from angr_rule_learning.rules.writer import write_rule_diagnostics_json, write_rules_text
```

Modify `ExtractionResult`:

```python
@dataclass(frozen=True)
class ExtractionResult:
    candidates: tuple[VerificationCandidate, ...]
    reports: tuple[VerificationReport, ...]
    diagnostics: MiningDiagnostics
    rules: tuple[GeneratedRule, ...] = ()
    rule_diagnostics: RuleDiagnostics | None = None
```

Modify `ExtractionPipeline.run()` signature:

```python
def run(
    self,
    config: ExtractionConfig,
    *,
    candidates_output: Path,
    diagnostics_output: Path,
    verify: bool = False,
    rules_output: Path | None = None,
    rules_diagnostics_output: Path | None = None,
) -> ExtractionResult:
```

Add the validation at the start of `run()`:

```python
rule_generation_requested = (
    rules_output is not None or rules_diagnostics_output is not None
)
if rule_generation_requested and not verify:
    raise ValueError("rule output requires verify=True")
```

Initialize rule state after diagnostics:

```python
rule_diagnostics = RuleDiagnostics()
rule_generalizer = RuleGeneralizer(rule_diagnostics)
rules: list[GeneratedRule] = []
```

Inside the existing `if verify and staged_candidates:` block, after `diagnostics.record_window_verified(report.status)`, add:

```python
rule = None
if rule_generation_requested:
    rule = rule_generalizer.generate(len(rules) + 1, window, candidate, report)
if rule is not None:
    rules.append(rule)
```

Keep the existing verified-window pruning behavior:

```python
if report.status == "pass":
    verified.add(window)
```

Use `candidate` from the zipped tuple:

```python
for (window, candidate), report in zip(emitted, staged_reports, strict=True):
```

After writing candidate and extraction diagnostics, write optional rule outputs:

```python
rule_tuple = tuple(rules)
if rules_output is not None:
    write_rules_text(rules_output, rule_tuple)
if rules_diagnostics_output is not None:
    write_rule_diagnostics_json(rules_diagnostics_output, rule_diagnostics)
return ExtractionResult(
    candidate_tuple,
    tuple(reports),
    diagnostics,
    rule_tuple,
    rule_diagnostics if rule_generation_requested else None,
)
```

- [ ] **Step 4: Run pipeline tests**

Run:

```bash
uv run pytest tests/test_extraction_pipeline.py tests/test_rules_generalize.py tests/test_rules_writer.py -v
```

Expected: PASS.

- [ ] **Step 5: Format, lint, and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/pipeline.py tests/test_extraction_pipeline.py
uv run ruff check src/angr_rule_learning/extraction/pipeline.py tests/test_extraction_pipeline.py
uv run pytest tests/test_extraction_pipeline.py tests/test_rules_generalize.py tests/test_rules_writer.py -v
git add src/angr_rule_learning/extraction/pipeline.py tests/test_extraction_pipeline.py
git commit -m "Emit rules from verified extraction windows" -m "Co-authored-by: Codex <codex@openai.com>" -m "Co-authored-by: Claude Code <noreply@anthropic.com>"
```

Expected: formatting succeeds, lint succeeds, tests pass, commit created.

---

## Task 5: CLI, Docs, And End-To-End Smoke

**Files:**
- Modify: `src/angr_rule_learning/cli.py`
- Modify: `tests/test_batch_cli.py`
- Modify: `tests/test_extraction_pipeline.py`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Create: `docs/rule-generalization.md`

- [ ] **Step 1: Write failing CLI validation test**

Append to `tests/test_batch_cli.py`:

```python
def test_extract_cli_rejects_rules_output_without_verify(tmp_path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(tmp_path / "candidates.jsonl"),
                "--diagnostics",
                str(tmp_path / "diagnostics.json"),
                "--rules-output",
                str(tmp_path / "rules.txt"),
            ]
        )

    assert excinfo.value.code == 2


def test_extract_cli_rejects_rules_diagnostics_without_verify(tmp_path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "extract",
                str(source),
                "--work-dir",
                str(tmp_path / "work"),
                "--output",
                str(tmp_path / "candidates.jsonl"),
                "--diagnostics",
                str(tmp_path / "diagnostics.json"),
                "--rules-diagnostics",
                str(tmp_path / "rules_diagnostics.json"),
            ]
        )

    assert excinfo.value.code == 2
```

Extend `test_extract_cli_smoke()` in `tests/test_extraction_pipeline.py` so it runs verified extraction with rule output when clang and verifier support are available:

```python
    rules_output = tmp_path / "rules.txt"
    rules_diagnostics = tmp_path / "rules_diagnostics.json"
    main(
        [
            "extract",
            str(source),
            "--work-dir",
            str(tmp_path / "work-verified"),
            "--output",
            str(tmp_path / "verified_candidates.jsonl"),
            "--diagnostics",
            str(tmp_path / "verified_diagnostics.json"),
            "--optimization",
            "0",
            "--verify",
            "--rules-output",
            str(rules_output),
            "--rules-diagnostics",
            str(rules_diagnostics),
        ]
    )
    assert rules_output.exists()
    assert rules_diagnostics.exists()
    rule_text = rules_output.read_text(encoding="utf-8")
    assert "1.Guest:" in rule_text or rule_text == ""
    if rule_text:
        assert "i32_reg" in rule_text or "i64_reg" in rule_text
        assert "\tw0" not in rule_text
        assert "\tx0" not in rule_text
        assert "\teax" not in rule_text
        assert "\trdi" not in rule_text
```

Keep the existing `RuntimeError` escape paths in `test_extract_cli_smoke()` for missing target support. If the verified run raises the same target-support errors, return from the smoke test as the current test already does.

- [ ] **Step 2: Run CLI tests and confirm failure**

Run:

```bash
uv run pytest tests/test_batch_cli.py::test_extract_cli_rejects_rules_output_without_verify tests/test_batch_cli.py::test_extract_cli_rejects_rules_diagnostics_without_verify tests/test_extraction_pipeline.py::test_extract_cli_smoke -v
```

Expected: FAIL because CLI arguments are not wired.

- [ ] **Step 3: Wire CLI arguments**

Modify `src/angr_rule_learning/cli.py` by adding arguments to the extract parser:

```python
extract_parser.add_argument("--rules-output", type=Path)
extract_parser.add_argument("--rules-diagnostics", type=Path)
```

After `args = parser.parse_args(argv)`, add this validation inside the extract branch before constructing `ExtractionConfig`:

```python
if (args.rules_output is not None or args.rules_diagnostics is not None) and not args.verify:
    extract_parser.error("--rules-output and --rules-diagnostics require --verify")
```

Pass paths into the pipeline:

```python
ExtractionPipeline().run(
    config,
    candidates_output=args.output,
    diagnostics_output=args.diagnostics,
    verify=args.verify,
    rules_output=args.rules_output,
    rules_diagnostics_output=args.rules_diagnostics,
)
```

- [ ] **Step 4: Add repository docs**

Create `docs/rule-generalization.md`:

```markdown
# Rule Generalization

Rule generalization turns verifier-passing extraction windows into plain text
translation rules. It runs inside `extract --verify` because the pipeline still
has both the verified candidate model and the original disassembled instruction
text.

## Command

```bash
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir runs/samples/smoke_int_o0/work \
  --output runs/samples/smoke_int_o0/candidates.jsonl \
  --diagnostics runs/samples/smoke_int_o0/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output runs/samples/smoke_int_o0/rules.txt \
  --rules-diagnostics runs/samples/smoke_int_o0/rules_diagnostics.json
```

`--rules-output` requires `--verify`. The rule generator emits only windows
whose verifier report has status `pass` and equivalent checks.

## Text Format

```text
1.Guest:
	<guest asm>
.Host:
	<host asm>

```

Multi-instruction rules use one tab-indented assembly line per instruction.
The text file contains only rules. Diagnostics and candidate ids are kept out
of the rule text.

## Register Generalization

Registers are replaced with typed placeholders:

- `i8_regN`, `i16_regN`, `i32_regN`, `i64_regN` for integer registers;
- `f32_regN` and `f64_regN` are reserved for scalar floating-point rules;
- `v128_regN` and wider vector placeholders are reserved for vector rules.

The first implementation emits integer register rules only. It keeps
immediates, offsets, scales, labels, and mnemonics literal.

## Conservative Skips

The generator skips verified windows when it cannot produce a safe generalized
rule:

- `register_class_mismatch`: guest and host mapped registers differ in kind or width;
- `unknown_register_class`: a mapped register cannot be classified;
- `unsupported_register_class`: the register class is known but not enabled;
- `unmapped_register_surface`: a concrete register remains after replacement;
- `unsupported_rule_shape`: the candidate mapping is inconsistent or empty.

AArch64 `xzr` and `wzr` may remain literal because they represent architectural
zero registers.
```

Modify `README.md`:

- Add rule generation to the implemented feature list.
- Replace the "Not implemented yet" item for rule generalization with rule store and coverage evaluation.
- Add this quick-start command after the extraction command:

```markdown
Extract, verify, and write generalized text rules:

```bash
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir /tmp/angr-rule-learning-extract \
  --output /tmp/angr-rule-learning-candidates.jsonl \
  --diagnostics /tmp/angr-rule-learning-diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output /tmp/angr-rule-learning-rules.txt \
  --rules-diagnostics /tmp/angr-rule-learning-rules-diagnostics.json
```
```

- Add `[Rule Generalization](docs/rule-generalization.md)` to the documentation list.
- Add `rules/` to the repository layout.

Modify `docs/architecture.md`:

- Change the current status text so extraction and rule generation are no longer described as only planned.
- Add `rules/` to the package structure:

```text
  rules/
    registers.py
    generalize.py
    writer.py
```

- Add a data-flow note:

```text
single C source
  -> extraction.ExtractionPipeline
  -> verification.BatchVerifier
  -> rules.RuleGeneralizer
  -> plain text rules
```

- State that rule generation consumes `WindowPair + VerificationCandidate + VerificationReport` and does not reconstruct assembly from JSONL.

- [ ] **Step 5: Run focused tests**

Run:

```bash
uv run pytest tests/test_batch_cli.py::test_extract_cli_rejects_rules_output_without_verify tests/test_batch_cli.py::test_extract_cli_rejects_rules_diagnostics_without_verify tests/test_extraction_pipeline.py tests/test_rules_registers.py tests/test_rules_generalize.py tests/test_rules_writer.py -v
```

Expected: PASS.

- [ ] **Step 6: Run full verification and smoke command**

Run:

```bash
uv run ruff format src tests
uv run ruff check
uv run pytest -q
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir runs/samples/rule_generalization_smoke/work \
  --output runs/samples/rule_generalization_smoke/candidates.jsonl \
  --diagnostics runs/samples/rule_generalization_smoke/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output runs/samples/rule_generalization_smoke/rules.txt \
  --rules-diagnostics runs/samples/rule_generalization_smoke/rules_diagnostics.json
```

Expected:

- `ruff format` completes without remaining formatting changes on rerun.
- `ruff check` reports all checks passed.
- `pytest -q` passes.
- Smoke extraction exits with code 0.
- `runs/samples/rule_generalization_smoke/rules.txt` exists.
- `runs/samples/rule_generalization_smoke/rules_diagnostics.json` exists.
- `runs/` remains ignored by git.

- [ ] **Step 7: Commit**

Run:

```bash
git status -sb
git add src/angr_rule_learning/cli.py tests/test_batch_cli.py tests/test_extraction_pipeline.py README.md docs/architecture.md docs/rule-generalization.md
git commit -m "Expose rule generation through extract CLI" -m "Co-authored-by: Codex <codex@openai.com>" -m "Co-authored-by: Claude Code <noreply@anthropic.com>"
```

Expected: commit created. `runs/` must not be staged.

---

## Final Review Checklist

Run after Task 5:

```bash
uv run ruff format --check src tests
uv run ruff check
uv run pytest -q
git status -sb
```

Expected:

- Format check passes.
- Lint passes.
- Full test suite passes.
- Worktree is clean except ignored `runs/` artifacts.

Manual inspection:

- Open `runs/samples/rule_generalization_smoke/rules.txt`.
- Confirm the format is exactly:

```text
<id>.Guest:
	<guest asm>
.Host:
	<host asm>

```

- Confirm emitted rules contain typed placeholders such as `i32_reg1` or `i64_reg1`.
- Confirm emitted rules do not leak concrete mapped registers such as `w0`, `x0`, `eax`, or `rdi`.
- Confirm `xzr` and `wzr` are the only ordinary AArch64 register names allowed to remain literal.

## Implementation Notes

- Keep all rule-generalization JSON diagnostics separate from extraction diagnostics.
- Use `ValueError("rule output requires verify=True")` in the Python API and `extract_parser.error("--rules-output and --rules-diagnostics require --verify")` in the CLI.
- Do not change candidate JSON schema in this feature.
- Do not change verifier semantics in this feature.
- Do not add coverage scoring in this feature.
