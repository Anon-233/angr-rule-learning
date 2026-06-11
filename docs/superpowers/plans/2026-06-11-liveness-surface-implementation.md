# Liveness-Based Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace raw read/write extraction surfaces with function-level liveness-based surfaces so verified rule generation can learn arithmetic and bitwise register rules instead of mostly `mov` rules.

**Architecture:** Add a focused liveness module under `angr_rule_learning.extraction` that owns register alias families, ABI exit live-out seeds, function CFG construction, fixed-point liveness, and per-window surface slicing. `SurfaceInferer` consumes this liveness index to build verifier candidates, while `RuleGeneralizer` rejects conflicting physical-register-to-placeholder mappings.

**Tech Stack:** Python dataclasses, pyelftools/Capstone-derived instruction metadata already present in extraction models, pytest, ruff, uv, existing angr-backed verifier.

---

## Design Inputs

Read these files before implementation:

- `docs/superpowers/specs/2026-06-11-liveness-surface-design.md`
- `src/angr_rule_learning/extraction/models.py`
- `src/angr_rule_learning/extraction/blocks.py`
- `src/angr_rule_learning/extraction/surfaces.py`
- `src/angr_rule_learning/extraction/pipeline.py`
- `src/angr_rule_learning/rules/generalize.py`
- `samples/sources/smoke_int.c`

Current problem to fix:

- The extractor currently compares raw `read_registers` and `write_registers`.
- `SurfaceInferer` skips any window that mentions `nzcv` or `rflags`.
- Arithmetic windows are therefore skipped or mis-surfaced, and generated rules are mostly `mov`.

Required behavior:

- Compute register liveness at function scope.
- Use canonical alias families for liveness, not concrete subregister names.
- Preserve concrete register names for verifier candidates and rule text.
- Ignore dead condition-code writes.
- Skip windows that depend on condition codes defined before the window.
- Keep local compare-and-branch windows eligible when the branch guard is defined inside the same candidate window.
- Seed function exits with return and callee-saved families.
- Reject rule generalization when one concrete register would map to two semantic placeholders.
- Run `uv run ruff format` after editing Python files.

## Target File Structure

Create:

- `src/angr_rule_learning/extraction/liveness.py`: register alias families, ABI seeds, CFG successor extraction, fixed-point liveness, and window surface slicing.
- `tests/test_extraction_liveness.py`: unit tests for alias families, ABI seeds, CFG liveness, and window slicing.

Modify:

- `src/angr_rule_learning/extraction/surfaces.py`: consume liveness-based window surfaces and remove the broad flag-surface skip.
- `src/angr_rule_learning/extraction/pipeline.py`: compute a liveness index from extracted functions and pass it into `SurfaceInferer`.
- `src/angr_rule_learning/rules/generalize.py`: reject conflicting placeholder mappings instead of merging through either side of a register pair.
- `tests/test_extraction_surfaces.py`: update surface tests to assert liveness-based behavior.
- `tests/test_extraction_pipeline.py`: update smoke assertions so arithmetic candidates are emitted and verifier noise stays bounded.
- `tests/test_rules_generalize.py`: add conflict and valid two-address mapping tests.
- `docs/architecture.md`: document liveness-based surface inference.
- `docs/rule-generalization.md`: document that rule output depends on liveness-derived verifier surfaces.

Do not modify:

- `src/angr_rule_learning/verification/candidate.py`: keep the candidate JSON schema stable.
- `src/angr_rule_learning/verification/verifier.py`: keep SMT semantics unchanged in this stage.
- Memory rule handling: keep memory windows skipped by `SurfaceInferer`.

---

## Task 1: Register Alias Families and ABI Exit Seeds

**Files:**
- Create: `src/angr_rule_learning/extraction/liveness.py`
- Test: `tests/test_extraction_liveness.py`

- [ ] **Step 1: Write failing alias and ABI seed tests**

Create `tests/test_extraction_liveness.py` with these initial tests:

```python
from angr_rule_learning.extraction.liveness import (
    abi_exit_live_out,
    family_for_register,
    families_for_registers,
    is_condition_family,
)


def test_aarch64_integer_aliases_share_family() -> None:
    assert family_for_register("aarch64", "w0") == "x0"
    assert family_for_register("aarch64", "x0") == "x0"
    assert family_for_register("aarch64", "fp") == "x29"
    assert family_for_register("aarch64", "lr") == "x30"
    assert family_for_register("aarch64", "sp") == "sp"


def test_x86_64_subregister_aliases_share_family() -> None:
    expected = "rax"
    for register in ("al", "ah", "ax", "eax", "rax"):
        assert family_for_register("x86-64", register) == expected
    assert family_for_register("x86-64", "r8b") == "r8"
    assert family_for_register("x86-64", "r8w") == "r8"
    assert family_for_register("x86-64", "r8d") == "r8"
    assert family_for_register("x86-64", "r8") == "r8"


def test_condition_code_families_are_normalized() -> None:
    assert family_for_register("aarch64", "nzcv") == "nzcv"
    assert family_for_register("x86-64", "rflags") == "rflags"
    assert family_for_register("x86-64", "zf") == "rflags"
    assert family_for_register("x86-64", "cf") == "rflags"
    assert is_condition_family("aarch64", "nzcv")
    assert is_condition_family("x86-64", "rflags")
    assert not is_condition_family("x86-64", "rax")


def test_families_for_registers_preserves_first_use_order() -> None:
    assert families_for_registers("x86-64", ("eax", "al", "ecx", "rflags")) == (
        "rax",
        "rcx",
        "rflags",
    )


def test_abi_exit_live_out_includes_return_and_callee_saved() -> None:
    assert abi_exit_live_out("aarch64") == frozenset(
        {
            "x0",
            "x19",
            "x20",
            "x21",
            "x22",
            "x23",
            "x24",
            "x25",
            "x26",
            "x27",
            "x28",
            "x29",
            "x30",
            "sp",
        }
    )
    assert abi_exit_live_out("x86-64") == frozenset(
        {"rax", "rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"}
    )
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_liveness.py -v
```

Expected: FAIL with `ModuleNotFoundError` or missing liveness functions.

- [ ] **Step 3: Implement alias helpers and ABI seeds**

Create `src/angr_rule_learning/extraction/liveness.py` with these public functions and constants:

```python
from __future__ import annotations

import re


_X86_64_ALIASES: dict[str, str] = {
    "al": "rax",
    "ah": "rax",
    "ax": "rax",
    "eax": "rax",
    "rax": "rax",
    "bl": "rbx",
    "bh": "rbx",
    "bx": "rbx",
    "ebx": "rbx",
    "rbx": "rbx",
    "cl": "rcx",
    "ch": "rcx",
    "cx": "rcx",
    "ecx": "rcx",
    "rcx": "rcx",
    "dl": "rdx",
    "dh": "rdx",
    "dx": "rdx",
    "edx": "rdx",
    "rdx": "rdx",
    "sil": "rsi",
    "si": "rsi",
    "esi": "rsi",
    "rsi": "rsi",
    "dil": "rdi",
    "di": "rdi",
    "edi": "rdi",
    "rdi": "rdi",
    "bpl": "rbp",
    "bp": "rbp",
    "ebp": "rbp",
    "rbp": "rbp",
    "spl": "rsp",
    "sp": "rsp",
    "esp": "rsp",
    "rsp": "rsp",
    "rip": "rip",
    "eip": "rip",
    "ip": "rip",
}

_X86_FLAG_ALIASES = frozenset(
    {"rflags", "eflags", "flags", "cf", "pf", "af", "zf", "sf", "of", "df", "if"}
)


def family_for_register(arch: str, register: str) -> str:
    normalized_arch = _normalize_arch(arch)
    reg = register.strip().lower()
    if normalized_arch == "aarch64":
        return _aarch64_family(reg)
    if normalized_arch == "x86-64":
        return _x86_64_family(reg)
    return reg


def families_for_registers(arch: str, registers: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for register in registers:
        family = family_for_register(arch, register)
        if family and family not in seen:
            seen.add(family)
            result.append(family)
    return tuple(result)


def is_condition_family(arch: str, family: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    normalized_family = family.strip().lower()
    if normalized_arch == "aarch64":
        return normalized_family == "nzcv"
    if normalized_arch == "x86-64":
        return normalized_family == "rflags"
    return False


def abi_exit_live_out(arch: str) -> frozenset[str]:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return frozenset(
            {
                "x0",
                "x19",
                "x20",
                "x21",
                "x22",
                "x23",
                "x24",
                "x25",
                "x26",
                "x27",
                "x28",
                "x29",
                "x30",
                "sp",
            }
        )
    if normalized_arch == "x86-64":
        return frozenset({"rax", "rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"})
    return frozenset()


def _normalize_arch(arch: str) -> str:
    normalized = arch.strip().lower()
    if normalized in {"amd64", "x86_64"}:
        return "x86-64"
    if normalized == "arm64":
        return "aarch64"
    return normalized


def _aarch64_family(register: str) -> str:
    if register == "nzcv":
        return "nzcv"
    if register == "fp":
        return "x29"
    if register == "lr":
        return "x30"
    if register in {"sp", "wsp"}:
        return "sp"
    match = re.fullmatch(r"[wx](\d+)", register)
    if match:
        return f"x{match.group(1)}"
    return register


def _x86_64_family(register: str) -> str:
    if register in _X86_FLAG_ALIASES:
        return "rflags"
    if register in _X86_64_ALIASES:
        return _X86_64_ALIASES[register]
    match = re.fullmatch(r"r(8|9|10|11|12|13|14|15)(b|w|d)?", register)
    if match:
        return f"r{match.group(1)}"
    return register
```

- [ ] **Step 4: Run tests and format**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/liveness.py tests/test_extraction_liveness.py
uv run pytest tests/test_extraction_liveness.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/liveness.py tests/test_extraction_liveness.py
git commit -m "Add register liveness alias families"
```

---

## Task 2: Function CFG and Fixed-Point Liveness

**Files:**
- Modify: `src/angr_rule_learning/extraction/liveness.py`
- Test: `tests/test_extraction_liveness.py`

- [ ] **Step 1: Add failing CFG and liveness tests**

Append these tests to `tests/test_extraction_liveness.py`:

```python
from angr_rule_learning.extraction.liveness import LivenessAnalyzer
from angr_rule_learning.extraction.models import ExtractedFunction, ExtractedInstruction


def _inst(
    address: int,
    mnemonic: str,
    op_str: str = "",
    *,
    arch: str = "x86-64",
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x90\x90\x90\x90",
        mnemonic=mnemonic,
        op_str=op_str,
        function="f",
        source=None,
        read_registers=reads,
        write_registers=writes,
    )


def _function(
    instructions: tuple[ExtractedInstruction, ...],
    *,
    arch: str = "x86-64",
) -> ExtractedFunction:
    return ExtractedFunction(
        arch=arch,
        name="f",
        address=instructions[0].address,
        size=sum(inst.size for inst in instructions),
        instructions=instructions,
    )


def test_linear_liveness_keeps_return_value_live_at_exit() -> None:
    function = _function(
        (
            _inst(0x1000, "add", "eax, ecx", reads=("eax", "ecx"), writes=("eax", "rflags")),
            _inst(0x1004, "ret"),
        )
    )

    index = LivenessAnalyzer().analyze((function,))
    add = index.for_instruction(function.instructions[0])
    ret = index.for_instruction(function.instructions[1])

    assert add.reads == ("rax", "rcx")
    assert add.writes == ("rax", "rflags")
    assert "rax" in add.live_out
    assert "rflags" not in add.live_out
    assert "rax" in ret.live_out
    assert {"rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"}.issubset(ret.live_out)


def test_conditional_branch_merges_target_and_fallthrough_liveness() -> None:
    function = _function(
        (
            _inst(0x1000, "cmp", "eax, ecx", reads=("eax", "ecx"), writes=("rflags",)),
            _inst(0x1004, "jl", "0x1010", reads=("rflags",)),
            _inst(0x1008, "mov", "eax, 1", writes=("eax",)),
            _inst(0x100C, "ret"),
            _inst(0x1010, "mov", "eax, 2", writes=("eax",)),
            _inst(0x1014, "ret"),
        )
    )

    index = LivenessAnalyzer().analyze((function,))
    cmp_inst = index.for_instruction(function.instructions[0])
    branch = index.for_instruction(function.instructions[1])

    assert branch.successor_addresses == (0x1010, 0x1008)
    assert "rflags" in cmp_inst.live_out
    assert "rflags" in branch.live_in
    assert "rax" not in branch.live_out


def test_aarch64_return_liveness_uses_return_and_callee_saved_seed() -> None:
    function = _function(
        (
            _inst(
                0x4000,
                "add",
                "w0, w0, w1",
                arch="aarch64",
                reads=("w0", "w1"),
                writes=("w0", "nzcv"),
            ),
            _inst(0x4004, "ret", arch="aarch64"),
        ),
        arch="aarch64",
    )

    index = LivenessAnalyzer().analyze((function,))
    add = index.for_instruction(function.instructions[0])

    assert "x0" in add.live_out
    assert "nzcv" not in add.live_out
    assert {"x19", "x28", "x29", "x30", "sp"}.issubset(
        index.for_instruction(function.instructions[1]).live_out
    )
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_liveness.py -v
```

Expected: FAIL because `LivenessAnalyzer` is missing.

- [ ] **Step 3: Add liveness data structures and analyzer**

Extend `src/angr_rule_learning/extraction/liveness.py` with:

```python
from dataclasses import dataclass
from collections.abc import Iterable

from angr_rule_learning.extraction.models import ExtractedFunction, ExtractedInstruction


@dataclass(frozen=True)
class InstructionLiveness:
    live_in: frozenset[str]
    live_out: frozenset[str]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    successor_addresses: tuple[int, ...]
    unsupported: bool = False


class LivenessIndex:
    def __init__(self, entries: dict[tuple[str, str, int], InstructionLiveness]) -> None:
        self._entries = dict(entries)

    @classmethod
    def empty(cls) -> "LivenessIndex":
        return cls({})

    def for_instruction(self, instruction: ExtractedInstruction) -> InstructionLiveness | None:
        return self._entries.get(
            (instruction.arch, instruction.function, instruction.address)
        )

    def require_instruction(self, instruction: ExtractedInstruction) -> InstructionLiveness:
        liveness = self.for_instruction(instruction)
        if liveness is None:
            raise KeyError(
                f"missing liveness for {instruction.arch}:{instruction.function}:"
                f"{instruction.address:x}"
            )
        return liveness

    def has_instruction(self, instruction: ExtractedInstruction) -> bool:
        return self.for_instruction(instruction) is not None


class LivenessAnalyzer:
    def analyze(self, functions: Iterable[ExtractedFunction]) -> LivenessIndex:
        entries: dict[tuple[str, str, int], InstructionLiveness] = {}
        for function in functions:
            entries.update(_analyze_function(function))
        return LivenessIndex(entries)
```

Add private helpers in the same file:

```python
def _analyze_function(
    function: ExtractedFunction,
) -> dict[tuple[str, str, int], InstructionLiveness]:
    instructions = function.instructions
    if not instructions:
        return {}

    successors = _successor_map(function)
    reads = {
        inst.address: families_for_registers(function.arch, inst.read_registers)
        for inst in instructions
    }
    writes = {
        inst.address: families_for_registers(function.arch, inst.write_registers)
        for inst in instructions
    }
    live_in: dict[int, frozenset[str]] = {
        inst.address: frozenset() for inst in instructions
    }
    live_out: dict[int, frozenset[str]] = {
        inst.address: _exit_seed(function, inst, successors[inst.address])
        for inst in instructions
    }
    by_address = {inst.address: inst for inst in instructions}

    changed = True
    while changed:
        changed = False
        for inst in reversed(instructions):
            succ_live = set(_exit_seed(function, inst, successors[inst.address]))
            for succ in successors[inst.address]:
                if succ in by_address:
                    succ_live.update(live_in[succ])
            next_live_out = frozenset(succ_live)
            next_live_in = frozenset(
                set(reads[inst.address]) | (set(next_live_out) - set(writes[inst.address]))
            )
            if next_live_out != live_out[inst.address] or next_live_in != live_in[inst.address]:
                live_out[inst.address] = next_live_out
                live_in[inst.address] = next_live_in
                changed = True

    return {
        (function.arch, function.name, inst.address): InstructionLiveness(
            live_in=live_in[inst.address],
            live_out=live_out[inst.address],
            reads=reads[inst.address],
            writes=writes[inst.address],
            successor_addresses=successors[inst.address],
            unsupported=_is_unresolved_indirect_control_flow(function.arch, inst),
        )
        for inst in instructions
    }
```

Add CFG helpers:

```python
def _successor_map(function: ExtractedFunction) -> dict[int, tuple[int, ...]]:
    instructions = function.instructions
    addresses = {inst.address for inst in instructions}
    result: dict[int, tuple[int, ...]] = {}
    for index, inst in enumerate(instructions):
        fallthrough = instructions[index + 1].address if index + 1 < len(instructions) else None
        mnemonic = inst.mnemonic.strip().lower()
        target = _parse_direct_target(inst.op_str, addresses)
        successors: list[int] = []

        if _is_return(function.arch, mnemonic):
            result[inst.address] = ()
            continue
        if _is_conditional_branch(function.arch, mnemonic):
            if target is not None:
                successors.append(target)
            if fallthrough is not None:
                successors.append(fallthrough)
            result[inst.address] = tuple(successors)
            continue
        if _is_direct_unconditional_branch(function.arch, mnemonic):
            result[inst.address] = (target,) if target is not None else ()
            continue
        if fallthrough is not None:
            successors.append(fallthrough)
        result[inst.address] = tuple(successors)
    return result


def _parse_direct_target(op_str: str, valid_addresses: set[int]) -> int | None:
    match = re.search(r"#?(-?0x[0-9a-fA-F]+|-?\d+)", op_str)
    if match is None:
        return None
    value = int(match.group(1), 0)
    return value if value in valid_addresses else None


def _exit_seed(
    function: ExtractedFunction,
    instruction: ExtractedInstruction,
    successors: tuple[int, ...],
) -> frozenset[str]:
    if successors:
        return frozenset()
    if _is_return(function.arch, instruction.mnemonic.strip().lower()):
        return abi_exit_live_out(function.arch)
    return frozenset()
```

Add branch predicate helpers. Keep them private because `surfaces.py` already has its own public behavior:

```python
def _is_conditional_branch(arch: str, mnemonic: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return mnemonic.startswith(("b.", "cbz", "cbnz", "tbz", "tbnz"))
    if normalized_arch == "x86-64":
        return mnemonic.startswith("j") and mnemonic != "jmp"
    return False


def _is_direct_unconditional_branch(arch: str, mnemonic: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return mnemonic == "b"
    if normalized_arch == "x86-64":
        return mnemonic == "jmp"
    return False


def _is_return(arch: str, mnemonic: str) -> bool:
    normalized_arch = _normalize_arch(arch)
    if normalized_arch == "aarch64":
        return mnemonic == "ret"
    if normalized_arch == "x86-64":
        return mnemonic == "ret"
    return False


def _is_unresolved_indirect_control_flow(arch: str, instruction: ExtractedInstruction) -> bool:
    normalized_arch = _normalize_arch(arch)
    mnemonic = instruction.mnemonic.strip().lower()
    if normalized_arch == "aarch64":
        return mnemonic in {"br", "blr", "eret"}
    if normalized_arch == "x86-64":
        return mnemonic == "jmp" and _parse_direct_target(instruction.op_str, set()) is None
    return False
```

- [ ] **Step 4: Run tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/liveness.py tests/test_extraction_liveness.py
uv run pytest tests/test_extraction_liveness.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/liveness.py tests/test_extraction_liveness.py
git commit -m "Add function liveness analysis"
```

---

## Task 3: Window Surface Slicing

**Files:**
- Modify: `src/angr_rule_learning/extraction/liveness.py`
- Test: `tests/test_extraction_liveness.py`

- [ ] **Step 1: Add failing window surface tests**

Append these tests to `tests/test_extraction_liveness.py`:

```python
from angr_rule_learning.extraction.liveness import WindowSurfaceInferer
from angr_rule_learning.extraction.models import InstructionWindow


def _window(instructions: tuple[ExtractedInstruction, ...], side: str = "host") -> InstructionWindow:
    return InstructionWindow("r1", side, instructions)


def test_window_surface_ignores_dead_flag_write() -> None:
    function = _function(
        (
            _inst(0x1000, "add", "eax, ecx", reads=("eax", "ecx"), writes=("eax", "rflags")),
            _inst(0x1004, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(_window((function.instructions[0],)))

    assert surface.skip_reason is None
    assert surface.outputs == ("eax",)
    assert surface.output_families == ("rax",)
    assert surface.inputs == ("eax", "ecx")
    assert surface.input_families == ("rax", "rcx")
    assert surface.kind == "register"


def test_window_surface_rejects_external_live_condition_code_dependency() -> None:
    function = _function(
        (
            _inst(0x1000, "jl", "0x1008", reads=("rflags",)),
            _inst(0x1004, "mov", "eax, 1", writes=("eax",)),
            _inst(0x1008, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(_window((function.instructions[0],)))

    assert surface.skip_reason == "external_live_condition_code_dependency"


def test_window_surface_keeps_local_compare_and_branch() -> None:
    function = _function(
        (
            _inst(0x1000, "cmp", "eax, ecx", reads=("eax", "ecx"), writes=("rflags",)),
            _inst(0x1004, "jl", "0x100C", reads=("rflags",)),
            _inst(0x1008, "mov", "eax, 1", writes=("eax",)),
            _inst(0x100C, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(
        _window((function.instructions[0], function.instructions[1]))
    )

    assert surface.skip_reason is None
    assert surface.kind == "branch"
    assert surface.outputs == ()
    assert surface.inputs == ("eax", "ecx")
    assert surface.input_families == ("rax", "rcx")


def test_window_surface_reports_no_verifiable_surface_for_dead_write() -> None:
    function = _function(
        (
            _inst(0x1000, "mov", "ecx, 1", writes=("ecx",)),
            _inst(0x1004, "ret"),
        )
    )
    index = LivenessAnalyzer().analyze((function,))

    surface = WindowSurfaceInferer(index).infer(_window((function.instructions[0],)))

    assert surface.skip_reason == "no_verifiable_surface"
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_liveness.py -v
```

Expected: FAIL because `WindowSurfaceInferer` is missing.

- [ ] **Step 3: Add window surface records and slicing**

Extend `src/angr_rule_learning/extraction/liveness.py`:

```python
from typing import Literal

from angr_rule_learning.extraction.models import InstructionWindow


SurfaceKind = Literal["register", "branch"]


@dataclass(frozen=True)
class WindowSurface:
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    input_families: tuple[str, ...] = ()
    output_families: tuple[str, ...] = ()
    kind: SurfaceKind = "register"
    skip_reason: str | None = None

    @property
    def emitted(self) -> bool:
        return self.skip_reason is None


class WindowSurfaceInferer:
    def __init__(self, liveness: LivenessIndex) -> None:
        self._liveness = liveness

    def infer(self, window: InstructionWindow) -> WindowSurface:
        if not window.instructions:
            return WindowSurface(skip_reason="no_verifiable_surface")
        if any(
            (entry := self._liveness.for_instruction(inst)) is None or entry.unsupported
            for inst in window.instructions
        ):
            return WindowSurface(skip_reason="missing_liveness_surface")

        arch = window.instructions[0].arch
        last = window.instructions[-1]
        last_liveness = self._liveness.require_instruction(last)
        defs = _ordered_family_registers(
            arch,
            tuple(reg for inst in window.instructions for reg in inst.write_registers),
        )
        semantic_output_families = tuple(
            family for family, _register in defs if family in last_liveness.live_out
        )
        terminal_branch = _is_conditional_branch(arch, last.mnemonic.strip().lower())

        needed = set(semantic_output_families)
        if terminal_branch:
            needed.update(
                family
                for family in families_for_registers(arch, last.read_registers)
                if is_condition_family(arch, family)
            )

        for inst in reversed(window.instructions):
            inst_entry = self._liveness.require_instruction(inst)
            written = set(inst_entry.writes)
            if written & needed:
                needed.difference_update(written)
                needed.update(inst_entry.reads)
            elif terminal_branch and inst is last:
                needed.update(inst_entry.reads)

        if any(is_condition_family(arch, family) for family in needed):
            return WindowSurface(skip_reason="external_live_condition_code_dependency")

        input_pairs = _ordered_input_registers(arch, window.instructions, needed)
        output_pairs = tuple(
            (family, register)
            for family, register in defs
            if family in semantic_output_families
        )
        if not output_pairs and not terminal_branch:
            return WindowSurface(skip_reason="no_verifiable_surface")

        return WindowSurface(
            inputs=tuple(register for _family, register in input_pairs),
            outputs=tuple(register for _family, register in output_pairs),
            input_families=tuple(family for family, _register in input_pairs),
            output_families=tuple(family for family, _register in output_pairs),
            kind="branch" if terminal_branch and not output_pairs else "register",
        )
```

Add order helpers:

```python
def _ordered_family_registers(
    arch: str,
    registers: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for register in registers:
        family = family_for_register(arch, register)
        if family and family not in seen:
            seen.add(family)
            result.append((family, register))
    return tuple(result)


def _ordered_input_registers(
    arch: str,
    instructions: tuple[ExtractedInstruction, ...],
    needed: set[str],
) -> tuple[tuple[str, str], ...]:
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    all_reads = tuple(reg for inst in instructions for reg in inst.read_registers)
    all_writes = tuple(reg for inst in instructions for reg in inst.write_registers)
    write_families = {
        family_for_register(arch, reg)
        for reg in all_writes
    }

    # Two-address operations should pair the read/write family first.
    for family, register in _ordered_family_registers(arch, all_reads):
        if family in needed and family in write_families and family not in seen:
            seen.add(family)
            result.append((family, register))

    for family, register in _ordered_family_registers(arch, all_reads):
        if family in needed and family not in seen:
            seen.add(family)
            result.append((family, register))

    return tuple(result)
```

If the exact branch slicing logic differs while implementing, preserve these externally visible outcomes:

- Dead flag writes are not outputs.
- A standalone conditional branch with live-in flags is skipped as `external_live_condition_code_dependency`.
- `cmp` plus terminal conditional branch emits a branch surface with non-flag operands as inputs.
- A dead write with no terminal branch is skipped as `no_verifiable_surface`.

- [ ] **Step 4: Run tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/liveness.py tests/test_extraction_liveness.py
uv run pytest tests/test_extraction_liveness.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/liveness.py tests/test_extraction_liveness.py
git commit -m "Infer liveness based window surfaces"
```

---

## Task 4: Integrate Liveness Surfaces into SurfaceInferer and Pipeline

**Files:**
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Modify: `src/angr_rule_learning/extraction/pipeline.py`
- Modify: `tests/test_extraction_surfaces.py`
- Modify: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Add failing surface tests for arithmetic and external flags**

Update `tests/test_extraction_surfaces.py` so it constructs a `LivenessIndex` with `LivenessAnalyzer` for direct `SurfaceInferer` tests. Add these tests:

```python
from angr_rule_learning.extraction.liveness import LivenessAnalyzer
from angr_rule_learning.extraction.surfaces import SurfaceInferer


def test_surface_inferer_emits_arithmetic_without_dead_flags(diagnostics) -> None:
    guest_function = _function(
        (
            _inst(
                0x1000,
                "add",
                "w0, w0, w1",
                arch="aarch64",
                reads=("w0", "w1"),
                writes=("w0", "nzcv"),
            ),
            _inst(0x1004, "ret", arch="aarch64"),
        ),
        arch="aarch64",
    )
    host_function = _function(
        (
            _inst(
                0x2000,
                "add",
                "eax, ecx",
                reads=("eax", "ecx"),
                writes=("eax", "rflags"),
            ),
            _inst(0x2004, "ret"),
        )
    )
    liveness = LivenessAnalyzer().analyze((guest_function, host_function))
    pair = _pair(
        guest_function.instructions[:1],
        host_function.instructions[:1],
    )

    candidate = SurfaceInferer(diagnostics, liveness).infer(pair)

    assert candidate is not None
    assert candidate.input_registers == (("w0", "eax"), ("w1", "ecx"))
    assert candidate.output_registers == (("w0", "eax"),)
    assert candidate.output_flags == ()


def test_surface_inferer_skips_standalone_external_flag_branch(diagnostics) -> None:
    guest_function = _function(
        (
            _inst(0x1000, "b.lt", "0x1008", arch="aarch64", reads=("nzcv",)),
            _inst(0x1004, "mov", "w0, #1", arch="aarch64", writes=("w0",)),
            _inst(0x1008, "ret", arch="aarch64"),
        ),
        arch="aarch64",
    )
    host_function = _function(
        (
            _inst(0x2000, "jl", "0x2008", reads=("rflags",)),
            _inst(0x2004, "mov", "eax, 1", writes=("eax",)),
            _inst(0x2008, "ret"),
        )
    )
    liveness = LivenessAnalyzer().analyze((guest_function, host_function))
    pair = _pair(
        guest_function.instructions[:1],
        host_function.instructions[:1],
    )

    assert SurfaceInferer(diagnostics, liveness).infer(pair) is None
    assert diagnostics.skip_reasons["external_live_condition_code_dependency"] == 1
```

Use the existing local helper style in the file. If `_inst`, `_function`, `_pair`, or `diagnostics` fixture do not exist, add them locally in the test file with the same shapes as `tests/test_extraction_liveness.py`.

- [ ] **Step 2: Run surface tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_surfaces.py -v
```

Expected: FAIL because `SurfaceInferer` does not accept `liveness` and still skips flag surfaces.

- [ ] **Step 3: Change SurfaceInferer to use WindowSurfaceInferer**

Modify `src/angr_rule_learning/extraction/surfaces.py`:

- Constructor signature becomes:

```python
def __init__(self, diagnostics: MiningDiagnostics, liveness: LivenessIndex) -> None:
    self._diagnostics = diagnostics
    self._surface_inferer = WindowSurfaceInferer(liveness)
```

- Keep unsupported control flow and memory checks before liveness inference.
- Remove `_has_flag_surface()` from the rejection path.
- Infer guest and host surfaces separately:

```python
guest_surface = self._surface_inferer.infer(pair.guest)
host_surface = self._surface_inferer.infer(pair.host)
for surface in (guest_surface, host_surface):
    if surface.skip_reason is not None:
        self._diagnostics.record_window_skipped(surface.skip_reason)
        return None
```

- Pair surfaces with this policy:

```python
if (
    len(guest_surface.inputs) != len(host_surface.inputs)
    or len(guest_surface.outputs) != len(host_surface.outputs)
):
    self._diagnostics.record_window_skipped("ambiguous_register_surface")
    return None
if guest_surface.kind != host_surface.kind:
    self._diagnostics.record_window_skipped("ambiguous_register_surface")
    return None
```

- Build the candidate from liveness-derived concrete registers:

```python
candidate = VerificationCandidate(
    candidate_id=_candidate_id(pair),
    guest=CodeFragment(...),
    host=CodeFragment(...),
    input_registers=tuple(zip(guest_surface.inputs, host_surface.inputs, strict=True)),
    output_registers=tuple(zip(guest_surface.outputs, host_surface.outputs, strict=True)),
    output_flags=(),
    memory=MemorySpec(),
    preconditions=(),
    clobbers=Clobbers(),
)
```

- Record `("branch",)` when both surfaces are branch surfaces and there are no outputs; otherwise record `("register",)`.

Do not keep the old raw `guest_reads`, `host_reads`, `guest_writes`, `host_writes` pairing as a fallback. Missing liveness should skip with `missing_liveness_surface` so production bugs are visible.

- [ ] **Step 4: Update pipeline to compute and pass liveness**

Modify `src/angr_rule_learning/extraction/pipeline.py`:

- Add imports:

```python
from angr_rule_learning.extraction.liveness import LivenessAnalyzer, LivenessIndex
from angr_rule_learning.extraction.models import ExtractedFunction
```

- Add a small data carrier near `ExtractionResult`:

```python
@dataclass(frozen=True)
class ExtractionData:
    regions: tuple[AlignmentRegion, ...]
    liveness: LivenessIndex
```

- Change `_regions()` to return `ExtractionData`.
- If `region_provider` is used, return `ExtractionData(regions, LivenessIndex.empty())`. Existing tests that use `region_provider` must either inject real liveness through extracted functions or be updated to assert `missing_liveness_surface`.
- Change `_extract_regions()` to return `ExtractionData`:

```python
guest_functions = self._object_extractor.extract(...)
host_functions = self._object_extractor.extract(...)
liveness = LivenessAnalyzer().analyze(guest_functions + host_functions)
...
regions = AlignmentRegionBuilder(diagnostics).build(guest_blocks, host_blocks)
return ExtractionData(regions, liveness)
```

- In `run()`:

```python
data = self._regions(config, diagnostics)
regions = data.regions
inferer = SurfaceInferer(diagnostics, data.liveness)
```

- Update test-only pipeline setup so tests that expect candidates are backed by real `ExtractedFunction` objects or use the object extractor/build driver path.

- [ ] **Step 5: Update pipeline smoke assertions**

In `tests/test_extraction_pipeline.py`, add or update a smoke test that runs the sample extraction path and asserts diagnostics show arithmetic candidates:

```python
assert result.diagnostics.windows_emitted > 0
assert result.diagnostics.surface_kinds["register"] > 0
assert result.diagnostics.skip_reasons.get("unsupported_flag_surface", 0) == 0
```

If the test already verifies generated rule output, add an assertion that at least one emitted or verified candidate has a non-`mov` mnemonic in the original `WindowPair` path or that generated rules include one of these instruction names:

```python
assert any(
    any(line.lstrip().startswith(("add ", "sub ", "and ", "orr ", "eor ", "xor "))
        for line in rule.guest_lines + rule.host_lines)
    for rule in result.rules
)
```

- [ ] **Step 6: Run focused tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/surfaces.py src/angr_rule_learning/extraction/pipeline.py tests/test_extraction_surfaces.py tests/test_extraction_pipeline.py
uv run pytest tests/test_extraction_liveness.py tests/test_extraction_surfaces.py tests/test_extraction_pipeline.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/surfaces.py src/angr_rule_learning/extraction/pipeline.py tests/test_extraction_surfaces.py tests/test_extraction_pipeline.py
git commit -m "Use liveness surfaces for extraction candidates"
```

---

## Task 5: Rule Generalizer Conflict Rejection

**Files:**
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Modify: `tests/test_rules_generalize.py`

- [ ] **Step 1: Add failing tests for valid two-address and invalid conflict mappings**

Append these tests to `tests/test_rules_generalize.py`:

```python
def test_generalizer_allows_two_address_input_output_pair() -> None:
    diagnostics = RuleDiagnostics()
    generalizer = RuleGeneralizer(diagnostics)
    window = _window_pair(
        guest=("add w8, w0, w8",),
        host=("add eax, ecx",),
    )
    candidate = _candidate(
        input_registers=(("w8", "eax"), ("w0", "ecx")),
        output_registers=(("w8", "eax"),),
    )
    report = _pass_report(candidate.candidate_id)

    rule = generalizer.generate(1, window, candidate, report)

    assert rule is not None
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg1",)
    assert rule.host_lines == ("add i32_reg1, i32_reg2",)
    assert diagnostics.rules_emitted == 1


def test_generalizer_rejects_conflicting_physical_register_mapping() -> None:
    diagnostics = RuleDiagnostics()
    generalizer = RuleGeneralizer(diagnostics)
    window = _window_pair(
        guest=("add w8, w0, w8",),
        host=("add eax, ecx",),
    )
    candidate = _candidate(
        input_registers=(("w0", "eax"), ("w8", "ecx")),
        output_registers=(("w8", "eax"),),
    )
    report = _pass_report(candidate.candidate_id)

    assert generalizer.generate(1, window, candidate, report) is None
    assert diagnostics.skip_reasons["unsupported_rule_shape"] == 1
```

Use the existing helper names in `tests/test_rules_generalize.py`. If helper signatures differ, preserve the candidate pairs and expected rule text exactly.

- [ ] **Step 2: Run tests and confirm the conflict test fails**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -v
```

Expected: the conflict test FAILS because `_build_placeholder_map()` currently merges through `mapping.get(guest_reg) or mapping.get(host_reg)`.

- [ ] **Step 3: Fix placeholder assignment**

Modify `_build_placeholder_map()` in `src/angr_rule_learning/rules/generalize.py` so each register pair is treated as one semantic slot only if neither side conflicts:

```python
def _build_placeholder_map(
    candidate: VerificationCandidate,
    guest_arch: str,
    host_arch: str,
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    next_id = 1
    for guest_reg, host_reg in candidate.output_registers + candidate.input_registers:
        guest_reg = normalize_register_name(guest_reg)
        host_reg = normalize_register_name(host_reg)
        guest_class = _classify_for_rule(guest_arch, guest_reg)
        host_class = _classify_for_rule(host_arch, host_reg)
        if guest_class != host_class:
            raise _RuleSkip("register_class_mismatch")

        guest_existing = mapping.get(guest_reg)
        host_existing = mapping.get(host_reg)
        if (
            guest_existing is not None
            and host_existing is not None
            and guest_existing != host_existing
        ):
            raise _RuleSkip("unsupported_rule_shape")

        existing = guest_existing or host_existing
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
```

- [ ] **Step 4: Run tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
uv run pytest tests/test_rules_generalize.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "Reject conflicting rule register mappings"
```

---

## Task 6: End-to-End Smoke, Diagnostics, and Documentation

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/rule-generalization.md`
- Modify: `README.md` only if the command examples or status wording became stale.

- [ ] **Step 1: Run full verification before docs**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -q
```

Expected:

- `ruff format` reports files formatted or unchanged.
- `ruff check` reports `All checks passed!`.
- `pytest -q` passes.

- [ ] **Step 2: Run extraction and rule generation smoke**

Run:

```bash
uv run angr-rule-learning extract \
  --source samples/sources/smoke_int.c \
  --output-dir runs/samples/liveness_surface_smoke \
  --candidates-output runs/samples/liveness_surface_smoke/candidates.jsonl \
  --diagnostics-output runs/samples/liveness_surface_smoke/diagnostics.json \
  --verify \
  --rules-output runs/samples/liveness_surface_smoke/rules.txt \
  --rules-diagnostics-output runs/samples/liveness_surface_smoke/rule_diagnostics.json
```

Expected:

- Command exits with status 0.
- `runs/` remains ignored by git.
- `diagnostics.json` has `windows_emitted > 0`.
- `diagnostics.json` has no `unsupported_flag_surface` skip reason.
- `rules.txt` contains at least one non-`mov` arithmetic or bitwise rule if the verifier accepts such windows. If none pass, inspect `candidates.jsonl` and `diagnostics.json`; do not mark this task complete until the reason is documented in `docs/rule-generalization.md`.

- [ ] **Step 3: Inspect smoke output**

Run:

```bash
python - <<'PY'
from pathlib import Path
import json

root = Path("runs/samples/liveness_surface_smoke")
diagnostics = json.loads((root / "diagnostics.json").read_text())
rule_diagnostics = json.loads((root / "rule_diagnostics.json").read_text())
rules = (root / "rules.txt").read_text().splitlines()

print(json.dumps({
    "windows_emitted": diagnostics.get("windows_emitted"),
    "skip_reasons": diagnostics.get("skip_reasons", {}),
    "surface_kinds": diagnostics.get("surface_kinds", {}),
    "rule_diagnostics": rule_diagnostics,
}, indent=2, sort_keys=True))
print("first_rules:")
for line in rules[:40]:
    print(line)
PY
```

Expected: output includes diagnostics and first generated rules for review.

- [ ] **Step 4: Update architecture docs**

In `docs/architecture.md`, update the extraction section to state:

```markdown
Candidate register surfaces are liveness-derived. The extractor computes function-level liveness over canonical register alias families, seeds function exits with ABI-visible return and callee-saved families, and slices each candidate window backward from live outputs or a terminal branch guard. Dead flag writes are ignored; windows that require condition-code values defined before the window are skipped as `external_live_condition_code_dependency`.
```

Also add `src/angr_rule_learning/extraction/liveness.py` to the package structure description.

- [ ] **Step 5: Update rule generalization docs**

In `docs/rule-generalization.md`, add a section:

```markdown
## Surface Source

Rules are generated only from verifier-passing candidates. Candidate input and output registers are not raw Capstone read/write lists. They come from function-level liveness:

- outputs are writes inside the window whose alias families are live after the window;
- inputs are live-in values needed to compute those outputs or a terminal branch guard;
- dead condition-code writes are ignored;
- externally live condition-code dependencies are skipped;
- memory windows are still skipped until memory rule learning is implemented.

This is why arithmetic rules can omit `nzcv` or `rflags` when those flags are dead.
```

- [ ] **Step 6: Run final verification**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -q
git status -sb
```

Expected:

- ruff passes.
- pytest passes.
- `git status -sb` shows only intentional tracked doc/source/test changes. Ignored files under `runs/` must not appear.

- [ ] **Step 7: Commit**

Run:

```bash
git add docs/architecture.md docs/rule-generalization.md README.md
git commit -m "Document liveness based rule surfaces"
```

If `README.md` was not changed, omit it from `git add`.

---

## Final Acceptance Criteria

The implementation is complete when all of these are true:

- `uv run ruff check` passes.
- `uv run pytest -q` passes.
- `SurfaceInferer` no longer has a broad `unsupported_flag_surface` rejection path.
- `ExtractionPipeline` production extraction computes `LivenessIndex` from extracted functions.
- `smoke_int.c` extraction emits register candidates from arithmetic or bitwise windows, not only `mov`.
- Generated rules do not silently merge conflicting concrete register mappings.
- `runs/` output remains untracked.
- Documentation explains liveness-based surfaces and the current memory limitation.

## Handoff Notes for Claude Code

Use `superpowers:subagent-driven-development` and execute one task per subagent. After each task, review the diff before continuing. Stop after Task 4 if the extractor smoke still produces only `mov`-style candidates; that means the issue is in liveness surface inference or candidate pairing, not documentation.

When reporting completion, include:

- commit list;
- `ruff format`, `ruff check`, and `pytest -q` output;
- extraction smoke diagnostics summary;
- first 5 generated rules from `runs/samples/liveness_surface_smoke/rules.txt`;
- any remaining semantic boundary that prevented arithmetic or bitwise rule emission.
