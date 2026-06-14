# Memory Rule Learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Learn verifier-backed integer scalar memory-operation rules from extracted AArch64 and x86-64 windows, starting with single memory operands and base-plus-constant addressing.

**Architecture:** Add structured memory operand extraction under `angr_rule_learning.extraction`, use it to infer `MemorySpec` values for candidate verification, and add memory-address placeholders in rule generation. Keep the existing angr memory verifier as the semantic backend, but stop relying on stack-only regex inference in `surfaces.py`.

**Tech Stack:** Python dataclasses, Capstone-derived instruction text already present in `ExtractedInstruction`, angr memory event recording, Claripy SMT checks, pytest, ruff, uv.

---

## Design Inputs

Read these files before implementation:

- `src/angr_rule_learning/extraction/surfaces.py`
- `src/angr_rule_learning/extraction/liveness.py`
- `src/angr_rule_learning/verification/addressing.py`
- `src/angr_rule_learning/verification/candidate.py`
- `src/angr_rule_learning/verification/memory.py`
- `src/angr_rule_learning/verification/memory_checks.py`
- `src/angr_rule_learning/rules/generalize.py`
- `src/angr_rule_learning/rules/registers.py`
- `tests/test_verifier_memory.py`
- `tests/test_extraction_surfaces.py`
- `tests/test_rules_generalize.py`

Current behavior to replace:

- `SurfaceInferer` only has a stack-oriented memory heuristic.
- Memory access detection is broader than memory surface inference, so many windows become `unsupported_memory_surface`.
- Address binding only accepts `register +/- constant`.
- Rule output does not replace memory operands with address placeholders before concrete base registers are rejected.

First implementation scope:

- AArch64 integer scalar `ldr`, `ldur`, `str`, `stur` with `[xN]`, `[xN, #imm]`, `[sp, #imm]`, `[fp, #imm]`, `[x29, #imm]`.
- x86-64 integer scalar `mov reg, [base +/- disp]` and `mov [base +/- disp], reg`, with optional `byte/word/dword/qword ptr`.
- Single memory operand per instruction.
- Base-plus-constant addressing only.
- Memory read and memory write events, with exact guest/host count, kind, and width matching.
- Memory address placeholders in text rules, such as `[addr64_1]`.

Out of scope for this implementation:

- AArch64 `ldp/stp`, pre-index, post-index, register-offset addressing, and SIMD/vector memory.
- x86-64 index-scale addressing, RIP-relative addressing, `push/pop`, `xchg`, `cmpxchg`, and read-modify-write memory instructions.
- `may_alias` verification.
- Partial-overlap alias reasoning.

Run `uv run ruff format` after editing Python files.

## Target File Structure

Create:

- `src/angr_rule_learning/extraction/memory_operands.py`: structured parsing of supported memory operands from `ExtractedInstruction`.
- `src/angr_rule_learning/extraction/memory_surfaces.py`: guest/host memory access pairing and `MemorySpec` construction.
- `src/angr_rule_learning/rules/memory.py`: memory operand placeholder rewriting for rule text.
- `tests/test_extraction_memory_operands.py`: memory operand parser coverage.
- `tests/test_extraction_memory_surfaces.py`: `MemorySpec` inference coverage.
- `tests/test_rules_memory_generalize.py`: rule output coverage for memory placeholders.
- `samples/sources/memory_int.c`: smoke input for memory rule learning.

Modify:

- `src/angr_rule_learning/extraction/surfaces.py`: delegate memory inference to `memory_surfaces.py` and allow memory-only candidates.
- `src/angr_rule_learning/verification/addressing.py`: keep current public API while making parsing explicit and tested for base-plus-constant syntax.
- `src/angr_rule_learning/rules/generalize.py`: rewrite memory operands before concrete register leak checks.
- `docs/rule-generalization.md`: document memory address placeholders and current memory limitations.
- `docs/architecture.md`: mention structured memory surface inference.

---

## Task 1: Structured Memory Operand Parser

**Files:**
- Create: `src/angr_rule_learning/extraction/memory_operands.py`
- Test: `tests/test_extraction_memory_operands.py`

- [ ] **Step 1: Write failing parser tests**

Create `tests/test_extraction_memory_operands.py`:

```python
from angr_rule_learning.extraction.memory_operands import (
    MemoryAddress,
    MemoryOperand,
    extract_memory_operands,
)
from angr_rule_learning.extraction.models import ExtractedInstruction


def _inst(arch: str, mnemonic: str, op_str: str) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=0x1000,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="f",
        source=None,
    )


def test_parses_aarch64_ldr_base_address() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1]"))

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=MemoryAddress(base="x1", displacement=0),
            text="[x1]",
            value_register="w0",
        ),
    )


def test_parses_aarch64_str_base_plus_offset() -> None:
    operands = extract_memory_operands(_inst("aarch64", "str", "x2, [sp, #16]"))

    assert operands == (
        MemoryOperand(
            kind="write",
            width=8,
            address=MemoryAddress(base="sp", displacement=16),
            text="[sp, #16]",
            value_register="x2",
        ),
    )


def test_parses_aarch64_negative_offset() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldur", "w8, [x29, #-4]"))

    assert operands[0].address == MemoryAddress(base="x29", displacement=-4)
    assert operands[0].width == 4


def test_parses_x86_64_mov_load_with_ptr_prefix() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "eax, dword ptr [rcx + 4]")
    )

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=MemoryAddress(base="rcx", displacement=4),
            text="[rcx + 4]",
            value_register="eax",
        ),
    )


def test_parses_x86_64_mov_store_with_negative_offset() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "qword ptr [rbp - 8], rax")
    )

    assert operands == (
        MemoryOperand(
            kind="write",
            width=8,
            address=MemoryAddress(base="rbp", displacement=-8),
            text="[rbp - 8]",
            value_register="rax",
        ),
    )


def test_unsupported_memory_forms_return_empty_tuple() -> None:
    assert extract_memory_operands(_inst("x86-64", "push", "rax")) == ()
    assert extract_memory_operands(_inst("aarch64", "ldp", "x0, x1, [sp]")) == ()
    assert (
        extract_memory_operands(_inst("x86-64", "mov", "eax, [rax + rcx * 4]"))
        == ()
    )
```

- [ ] **Step 2: Run parser tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py -v
```

Expected: FAIL because `angr_rule_learning.extraction.memory_operands` does not exist.

- [ ] **Step 3: Implement parser models and supported forms**

Create `src/angr_rule_learning/extraction/memory_operands.py`:

```python
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from angr_rule_learning.extraction.models import ExtractedInstruction


MemoryKind = Literal["read", "write"]


@dataclass(frozen=True)
class MemoryAddress:
    base: str
    displacement: int = 0

    def binding_text(self) -> str:
        if self.displacement == 0:
            return self.base
        op = "+" if self.displacement > 0 else "-"
        return f"{self.base} {op} {abs(self.displacement)}"


@dataclass(frozen=True)
class MemoryOperand:
    kind: MemoryKind
    width: int
    address: MemoryAddress
    text: str
    value_register: str


_AARCH64_MEM_RE = re.compile(
    r"(?P<value>[wx]\d+|sp|wsp|fp|x29|x30|lr)\s*,\s*"
    r"(?P<mem>\[(?P<base>[a-z0-9]+)"
    r"(?:\s*,\s*#(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+)))?\])",
    re.IGNORECASE,
)

_X86_MEM_RE = re.compile(
    r"(?P<mem>\[(?P<base>[a-z][a-z0-9]*)"
    r"(?:\s*(?P<sign>[+-])\s*(?P<disp>0x[0-9a-fA-F]+|\d+))?\])",
    re.IGNORECASE,
)


def extract_memory_operands(instruction: ExtractedInstruction) -> tuple[MemoryOperand, ...]:
    arch = instruction.arch.strip().lower()
    mnemonic = instruction.mnemonic.strip().lower()
    op_str = instruction.op_str.strip()
    if arch == "aarch64":
        return _extract_aarch64(mnemonic, op_str)
    if arch == "x86-64":
        return _extract_x86_64(mnemonic, op_str)
    return ()


def _extract_aarch64(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic not in {"ldr", "ldur", "str", "stur"}:
        return ()
    match = _AARCH64_MEM_RE.search(op_str)
    if match is None:
        return ()
    value = match.group("value").lower()
    width = _aarch64_register_width(value)
    if width is None:
        return ()
    return (
        MemoryOperand(
            kind="read" if mnemonic in {"ldr", "ldur"} else "write",
            width=width,
            address=MemoryAddress(
                base=match.group("base").lower(),
                displacement=_parse_displacement(match.group("disp"), "+"),
            ),
            text=match.group("mem"),
            value_register=value,
        ),
    )


def _extract_x86_64(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic != "mov":
        return ()
    parts = [part.strip() for part in op_str.split(",", maxsplit=1)]
    if len(parts) != 2:
        return ()
    left, right = parts
    left_mem = _X86_MEM_RE.search(left)
    right_mem = _X86_MEM_RE.search(right)
    if left_mem is not None and right_mem is not None:
        return ()
    if left_mem is None and right_mem is None:
        return ()
    if left_mem is not None:
        value_register = right.strip().lower()
        width = _x86_width(left, value_register)
        if width is None:
            return ()
        return (_x86_operand("write", width, left_mem, value_register),)
    value_register = left.strip().lower()
    width = _x86_width(op_str, value_register)
    if width is None:
        return ()
    return (_x86_operand("read", width, right_mem, value_register),)


def _x86_operand(
    kind: MemoryKind,
    width: int,
    match: re.Match[str],
    value_register: str,
) -> MemoryOperand:
    return MemoryOperand(
        kind=kind,
        width=width,
        address=MemoryAddress(
            base=match.group("base").lower(),
            displacement=_parse_displacement(match.group("disp"), match.group("sign") or "+"),
        ),
        text=match.group("mem"),
        value_register=value_register,
    )


def _parse_displacement(text: str | None, sign: str) -> int:
    if text is None:
        return 0
    value = int(text.lstrip("+-"), 0)
    if text.startswith("-") or sign == "-":
        return -value
    return value


def _aarch64_register_width(register: str) -> int | None:
    if register.startswith("w"):
        return 4
    if register.startswith("x") or register in {"sp", "fp", "lr"}:
        return 8
    return None


def _x86_width(op_text: str, value_register: str) -> int | None:
    lower = op_text.lower()
    if "qword" in lower:
        return 8
    if "dword" in lower:
        return 4
    if "word" in lower and "dword" not in lower and "qword" not in lower:
        return 2
    if "byte" in lower:
        return 1
    if value_register.startswith("r") and len(value_register) >= 3:
        return 8
    if value_register.startswith("e"):
        return 4
    if value_register.endswith("w"):
        return 2
    if value_register.endswith("b") or value_register in {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"}:
        return 1
    return None
```

- [ ] **Step 4: Run parser tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/memory_operands.py tests/test_extraction_memory_operands.py
uv run pytest tests/test_extraction_memory_operands.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/memory_operands.py tests/test_extraction_memory_operands.py
git commit -m "Add structured memory operand extraction"
```

---

## Task 2: Memory Surface Inference

**Files:**
- Create: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Test: `tests/test_extraction_memory_surfaces.py`

- [ ] **Step 1: Write failing memory surface tests**

Create `tests/test_extraction_memory_surfaces.py`:

```python
from angr_rule_learning.extraction.memory_surfaces import infer_memory_surface
from angr_rule_learning.extraction.models import ExtractedInstruction, InstructionWindow, WindowPair


def _inst(arch: str, address: int, mnemonic: str, op_str: str) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="f",
        source=None,
    )


def _pair(guest: tuple[ExtractedInstruction, ...], host: tuple[ExtractedInstruction, ...]) -> WindowPair:
    return WindowPair(
        region_id="r0",
        stage=(len(guest), len(host)),
        guest=InstructionWindow("r0", "guest", guest),
        host=InstructionWindow("r0", "host", host),
    )


def test_infers_equivalent_load_memory_spec() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),),
        )
    )

    assert surface.skip_reason is None
    assert len(surface.spec.slots) == 1
    assert surface.spec.bindings[0].guest_addr == "x1"
    assert surface.spec.bindings[0].host_addr == "rcx"
    assert surface.spec.accesses[0].kind == "read"
    assert surface.spec.accesses[0].width == 4
    assert surface.input_registers == ()
    assert surface.address_registers == (("x1", "rcx"),)


def test_infers_store_value_register_inputs() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w0, [x1, #4]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx + 4], eax"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "x1 + 4"
    assert surface.spec.bindings[0].host_addr == "rcx + 4"
    assert surface.spec.accesses[0].kind == "write"
    assert surface.input_registers == (("w0", "eax"),)
    assert surface.address_registers == (("x1", "rcx"),)


def test_rejects_memory_access_count_mismatch() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (
                _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),
                _inst("x86-64", 0x2004, "mov", "edx, dword ptr [rbx]"),
            ),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"


def test_rejects_memory_kind_or_width_mismatch() -> None:
    kind = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx], eax"),),
        )
    )
    width = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "rax, qword ptr [rcx]"),),
        )
    )

    assert kind.skip_reason == "unsupported_memory_surface"
    assert width.skip_reason == "unsupported_memory_surface"
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py -v
```

Expected: FAIL because `memory_surfaces.py` does not exist.

- [ ] **Step 3: Implement memory surface inference**

Create `src/angr_rule_learning/extraction/memory_surfaces.py`:

```python
from __future__ import annotations

from dataclasses import dataclass

from angr_rule_learning.extraction.memory_operands import MemoryOperand, extract_memory_operands
from angr_rule_learning.extraction.models import InstructionWindow, WindowPair
from angr_rule_learning.verification.candidate import (
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
)


@dataclass(frozen=True)
class MemorySurface:
    spec: MemorySpec
    input_registers: tuple[tuple[str, str], ...] = ()
    address_registers: tuple[tuple[str, str], ...] = ()
    skip_reason: str | None = None
    guest_operands: tuple[MemoryOperand, ...] = ()
    host_operands: tuple[MemoryOperand, ...] = ()

    @property
    def has_memory(self) -> bool:
        return bool(self.guest_operands or self.host_operands)


def infer_memory_surface(pair: WindowPair) -> MemorySurface:
    guest_operands = _collect(pair.guest)
    host_operands = _collect(pair.host)

    if not guest_operands and not host_operands:
        return MemorySurface(MemorySpec())
    if not guest_operands or not host_operands:
        return MemorySurface(MemorySpec(), skip_reason="unsupported_memory_surface")
    if len(guest_operands) != len(host_operands):
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            guest_operands=guest_operands,
            host_operands=host_operands,
        )

    slots: list[MemorySlot] = []
    bindings: list[MemoryBinding] = []
    accesses: list[MemoryAccessExpectation] = []
    input_registers: list[tuple[str, str]] = []
    address_registers: list[tuple[str, str]] = []

    for index, (guest, host) in enumerate(zip(guest_operands, host_operands, strict=True)):
        if guest.kind != host.kind or guest.width != host.width:
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
        slot_name = f"mem{index}"
        slots.append(MemorySlot(slot_name, guest.width))
        bindings.append(
            MemoryBinding(
                slot_name,
                guest.address.binding_text(),
                host.address.binding_text(),
                guest.kind,
            )
        )
        accesses.append(MemoryAccessExpectation(slot_name, guest.kind, guest.width))
        address_registers.append((guest.address.base, host.address.base))
        if guest.kind == "write":
            input_registers.append((guest.value_register, host.value_register))

    return MemorySurface(
        MemorySpec(tuple(slots), tuple(bindings), tuple(accesses), ()),
        input_registers=tuple(input_registers),
        address_registers=tuple(address_registers),
        guest_operands=guest_operands,
        host_operands=host_operands,
    )


def _collect(window: InstructionWindow) -> tuple[MemoryOperand, ...]:
    operands: list[MemoryOperand] = []
    for instruction in window.instructions:
        operands.extend(extract_memory_operands(instruction))
    return tuple(operands)
```

- [ ] **Step 4: Run memory surface tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_surfaces.py
uv run pytest tests/test_extraction_memory_surfaces.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_surfaces.py
git commit -m "Infer structured memory surfaces"
```

---

## Task 3: Integrate Memory Surfaces into Candidate Extraction

**Files:**
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Test: `tests/test_extraction_surfaces.py`

- [ ] **Step 1: Add failing extraction tests with liveness-backed load and store**

Append to `tests/test_extraction_surfaces.py`:

```python
from angr_rule_learning.extraction.liveness import LivenessAnalyzer
from angr_rule_learning.extraction.models import ExtractedFunction


def _function(arch: str, instructions: tuple[ExtractedInstruction, ...]) -> ExtractedFunction:
    return ExtractedFunction(
        arch=arch,
        name="add",
        address=instructions[0].address,
        size=sum(inst.size for inst in instructions),
        instructions=instructions,
    )


def _mem_inst(
    arch: str,
    address: int,
    mnemonic: str,
    op_str: str,
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="add",
        source=SourceLocation("sample.c", 3),
        read_registers=reads,
        write_registers=writes,
    )


def test_surface_inferer_emits_load_memory_candidate() -> None:
    guest = (
        _mem_inst("aarch64", 0x1000, "ldr", "w0, [x1]", reads=("x1",), writes=("w0",)),
        _mem_inst("aarch64", 0x1004, "ret"),
    )
    host = (
        _mem_inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]", reads=("rcx",), writes=("eax",)),
        _mem_inst("x86-64", 0x2004, "ret"),
    )
    liveness = LivenessAnalyzer().analyze((_function("aarch64", guest), _function("x86-64", host)))
    pair = WindowPair(
        "r0",
        (1, 1),
        InstructionWindow("r0", "guest", guest[:1]),
        InstructionWindow("r0", "host", host[:1]),
    )

    diagnostics = MiningDiagnostics()
    candidate = SurfaceInferer(diagnostics, liveness).infer(pair)

    assert candidate is not None
    assert candidate.input_registers == ()
    assert candidate.output_registers == (("w0", "eax"),)
    assert candidate.memory.accesses[0].kind == "read"
    assert candidate.memory.bindings[0].guest_addr == "x1"
    assert candidate.memory.bindings[0].host_addr == "rcx"


def test_surface_inferer_emits_store_memory_candidate_without_register_output() -> None:
    guest = (
        _mem_inst("aarch64", 0x1000, "str", "w0, [x1]", reads=("w0", "x1")),
        _mem_inst("aarch64", 0x1004, "ret"),
    )
    host = (
        _mem_inst("x86-64", 0x2000, "mov", "dword ptr [rcx], eax", reads=("eax", "rcx")),
        _mem_inst("x86-64", 0x2004, "ret"),
    )
    liveness = LivenessAnalyzer().analyze((_function("aarch64", guest), _function("x86-64", host)))
    pair = WindowPair(
        "r0",
        (1, 1),
        InstructionWindow("r0", "guest", guest[:1]),
        InstructionWindow("r0", "host", host[:1]),
    )

    diagnostics = MiningDiagnostics()
    candidate = SurfaceInferer(diagnostics, liveness).infer(pair)

    assert candidate is not None
    assert candidate.output_registers == ()
    assert candidate.input_registers == (("w0", "eax"),)
    assert candidate.memory.accesses[0].kind == "write"
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_extraction_surfaces.py::test_surface_inferer_emits_load_memory_candidate tests/test_extraction_surfaces.py::test_surface_inferer_emits_store_memory_candidate_without_register_output -v
```

Expected: FAIL because `SurfaceInferer` still uses stack-specific helpers and rejects memory-only store surfaces through liveness.

- [ ] **Step 3: Replace stack-only memory inference in `SurfaceInferer`**

Modify `src/angr_rule_learning/extraction/surfaces.py`:

- Import `infer_memory_surface`:

```python
from angr_rule_learning.extraction.memory_surfaces import infer_memory_surface
```

- In `infer()`, replace `_infer_stack_memory_surface(pair)` with:

```python
memory_surface = infer_memory_surface(pair)
if memory_surface.skip_reason is not None:
    self._diagnostics.record_window_skipped(memory_surface.skip_reason)
    return None
if has_memory and not memory_surface.spec.slots:
    self._diagnostics.record_window_skipped("unsupported_memory_surface")
    return None
```

- Keep liveness surface inference for register outputs.
- Allow memory-only candidates when both sides report `no_verifiable_surface` but `memory_surface.spec.slots` is not empty:

```python
guest_surface = self._surface_inferer.infer(pair.guest)
host_surface = self._surface_inferer.infer(pair.host)
surfaces = (guest_surface, host_surface)
if memory_surface.spec.slots and all(
    surface.skip_reason == "no_verifiable_surface" for surface in surfaces
):
    guest_inputs = ()
    host_inputs = ()
    guest_outputs = ()
    host_outputs = ()
    surface_kind = "memory"
else:
    for surface in surfaces:
        if surface.skip_reason is not None:
            self._diagnostics.record_window_skipped(surface.skip_reason)
            return None
    if len(guest_surface.inputs) != len(host_surface.inputs) or len(
        guest_surface.outputs
    ) != len(host_surface.outputs):
        self._diagnostics.record_window_skipped("ambiguous_register_surface")
        return None
    if guest_surface.kind != host_surface.kind:
        self._diagnostics.record_window_skipped("ambiguous_register_surface")
        return None
    guest_inputs = guest_surface.inputs
    host_inputs = host_surface.inputs
    guest_outputs = guest_surface.outputs
    host_outputs = host_surface.outputs
    surface_kind = guest_surface.kind
```

- Merge store value inputs after liveness inputs:

```python
input_registers = tuple(zip(guest_inputs, host_inputs, strict=True))
input_registers = _remove_register_pairs(
    input_registers,
    memory_surface.address_registers,
)
input_registers = _merge_register_pairs(input_registers, memory_surface.input_registers)
```

- Add local helpers for address-register filtering and exact-pair deduplication:

```python
def _remove_register_pairs(
    pairs: tuple[tuple[str, str], ...],
    removed: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    removed_set = set(removed)
    return tuple(pair for pair in pairs if pair not in removed_set)
```

```python
def _merge_register_pairs(
    left: tuple[tuple[str, str], ...],
    right: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    result: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pair in left + right:
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
    return tuple(result)
```

- Set `memory=memory_surface.spec` in `VerificationCandidate`.
- Record surface kind `("memory",)` when the candidate has memory slots and no register outputs; otherwise keep `("register",)` or `("branch",)`.
- Remove `_infer_stack_memory_surface`, `_collect_stack_accesses`, `_parse_stack_access`, and `_memory_access_width` after tests pass.

- [ ] **Step 4: Run focused extraction tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_surfaces.py
uv run pytest tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_surfaces.py
git commit -m "Emit memory candidates from structured surfaces"
```

---

## Task 4: Verifier Address Binding Regression Coverage

**Files:**
- Modify: `src/angr_rule_learning/verification/addressing.py`
- Modify: `tests/test_verifier_memory.py`

- [ ] **Step 1: Add explicit base-plus-offset verifier tests**

Append to `tests/test_verifier_memory.py`:

```python
def test_verifier_accepts_equivalent_load_with_positive_offset() -> None:
    candidate = VerificationCandidate(
        candidate_id="load32-offset",
        guest=CodeFragment("aarch64", 0x10000, "20 04 40 b9", 1),  # ldr w0, [x1, #4]
        host=CodeFragment("x86-64", 0x8048000, "8b 41 04", 1),  # mov eax, [rcx + 4]
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 4", "rcx + 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_reports_unsupported_index_scale_address_expression() -> None:
    candidate = VerificationCandidate(
        candidate_id="unsupported-index-scale",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_PTR, 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "unsupported"
    assert "unsupported_address_expression" in report.unsupported_features
```

- [ ] **Step 2: Run verifier memory tests**

Run:

```bash
uv run pytest tests/test_verifier_memory.py -v
```

Expected: PASS if current address binding already handles positive offsets and rejects index-scale as unsupported. If the positive-offset machine code differs on the local disassembler path, replace the hex with known-good bytes generated by clang/objdump and keep the test name and assertion.

- [ ] **Step 3: Refactor `addressing.py` without expanding scope**

Keep `parse_address_binding(expression: str) -> AddressBinding` as the public API. Make the supported grammar explicit in constants and keep unsupported forms raising:

```python
ValueError(f"unsupported address expression: {expression}")
```

Do not implement index-scale in this task; the test must document the current unsupported boundary.

- [ ] **Step 4: Run tests and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/verification/addressing.py tests/test_verifier_memory.py
uv run pytest tests/test_verifier_memory.py -v
git add src/angr_rule_learning/verification/addressing.py tests/test_verifier_memory.py
git commit -m "Cover memory address binding boundaries"
```

Expected: PASS and commit succeeds.

---

## Task 5: Memory Placeholders in Rule Output

**Files:**
- Create: `src/angr_rule_learning/rules/memory.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_memory_generalize.py`

- [ ] **Step 1: Write failing memory rule tests**

Create `tests/test_rules_memory_generalize.py`:

```python
from angr_rule_learning.extraction.models import ExtractedInstruction, InstructionWindow, SourceLocation, WindowPair
from angr_rule_learning.rules.generalize import RuleDiagnostics, RuleGeneralizer
from angr_rule_learning.verification.candidate import (
    CodeFragment,
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.report import CheckResult, VerificationReport


def _inst(arch: str, address: int, mnemonic: str, op_str: str) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="sample",
        source=SourceLocation("sample.c", 1),
    )


def _pair(guest: ExtractedInstruction, host: ExtractedInstruction) -> WindowPair:
    return WindowPair(
        "sample:sample.c:1:0",
        (1, 1),
        InstructionWindow("sample:sample.c:1:0", "guest", (guest,)),
        InstructionWindow("sample:sample.c:1:0", "host", (host,)),
    )


def _pass(candidate_id: str) -> VerificationReport:
    return VerificationReport(
        candidate_id,
        "pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )


def test_generalizes_load_memory_address_placeholder() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "ldr", "w0, [x1]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, pair, candidate, _pass(candidate.candidate_id))

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [addr64_1]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [addr64_1]",)


def test_generalizes_store_memory_address_placeholder() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-store",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 4", "rcx + 4", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "str", "w0, [x1, #4]"),
        _inst("x86-64", 0x2000, "mov", "dword ptr [rcx + 4], eax"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, pair, candidate, _pass(candidate.candidate_id))

    assert rule is not None
    assert rule.guest_lines == ("str i32_reg1, [addr64_1]",)
    assert rule.host_lines == ("mov dword ptr [addr64_1], i32_reg1",)
```

- [ ] **Step 2: Run tests and confirm failure**

Run:

```bash
uv run pytest tests/test_rules_memory_generalize.py -v
```

Expected: FAIL because memory operand rewriting is not implemented and concrete base registers remain.

- [ ] **Step 3: Implement memory operand rewriting**

Create `src/angr_rule_learning/rules/memory.py`:

```python
from __future__ import annotations

from angr_rule_learning.extraction.memory_operands import extract_memory_operands
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.verification.candidate import MemorySpec


def rewrite_memory_operands(
    instructions: tuple[ExtractedInstruction, ...],
    lines: tuple[str, ...],
    memory: MemorySpec,
    *,
    side: str,
) -> tuple[str, ...]:
    if not memory.slots:
        return lines
    replacements = _replacement_by_operand_text(instructions, memory, side=side)
    result: list[str] = []
    for line in lines:
        rewritten = line
        for text, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
            rewritten = rewritten.replace(text, replacement)
        result.append(rewritten)
    return tuple(result)


def _replacement_by_operand_text(
    instructions: tuple[ExtractedInstruction, ...],
    memory: MemorySpec,
    *,
    side: str,
) -> dict[str, str]:
    operands = tuple(
        operand
        for instruction in instructions
        for operand in extract_memory_operands(instruction)
    )
    bindings = memory.bindings
    if len(operands) != len(bindings):
        return {}
    result: dict[str, str] = {}
    for index, (operand, binding) in enumerate(zip(operands, bindings, strict=True), start=1):
        expected = binding.guest_addr if side == "guest" else binding.host_addr
        if operand.address.binding_text() != expected:
            return {}
        result[operand.text] = f"[addr64_{index}]"
    return result
```

Modify `src/angr_rule_learning/rules/generalize.py`:

- Import:

```python
from angr_rule_learning.rules.memory import rewrite_memory_operands
```

- In `RuleGeneralizer.generate()`, build raw text lines, rewrite memory operands, then apply register generalization. Replace the existing `_generalize_instructions(...)` calls with this flow:

```python
guest_lines = _instruction_lines(window.guest.instructions)
host_lines = _instruction_lines(window.host.instructions)
guest_lines = rewrite_memory_operands(window.guest.instructions, guest_lines, candidate.memory, side="guest")
host_lines = rewrite_memory_operands(window.host.instructions, host_lines, candidate.memory, side="host")
guest_lines = _generalize_lines(guest_lines, mapping, guest_arch)
host_lines = _generalize_lines(host_lines, mapping, host_arch)
```

- Add helpers:

```python
def _instruction_lines(instructions: tuple[ExtractedInstruction, ...]) -> tuple[str, ...]:
    return tuple(_instruction_text(inst) for inst in instructions)


def _generalize_lines(
    lines: tuple[str, ...],
    mapping: dict[str, str],
    arch: str,
) -> tuple[str, ...]:
    generalized = tuple(_generalize_line(line, mapping, arch) for line in lines)
    if not generalized:
        raise _RuleSkip("unsupported_rule_shape")
    return generalized
```

- Keep `_generalize_instructions()` only if existing tests still import it indirectly. If nothing imports it, remove it after focused tests pass.

- [ ] **Step 4: Run rule tests**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules/memory.py src/angr_rule_learning/rules/generalize.py tests/test_rules_memory_generalize.py
uv run pytest tests/test_rules_generalize.py tests/test_rules_memory_generalize.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src/angr_rule_learning/rules/memory.py src/angr_rule_learning/rules/generalize.py tests/test_rules_memory_generalize.py
git commit -m "Generalize memory operands in rule output"
```

---

## Task 6: End-to-End Memory Sample

**Files:**
- Create: `samples/sources/memory_int.c`
- Modify: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Add memory sample source**

Create `samples/sources/memory_int.c`:

```c
int load_i32(int *p) {
    return *p;
}

void store_i32(int *p, int v) {
    *p = v;
}

int load_add_i32(int *p, int x) {
    return *p + x;
}

int store_add_i32(int *p, int a, int b) {
    int v = a + b;
    *p = v;
    return v;
}
```

- [ ] **Step 2: Add pipeline smoke assertion**

Append a smoke test to `tests/test_extraction_pipeline.py`:

```python
def test_extract_memory_rules_smoke(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = Path(__file__).resolve().parents[1] / "samples" / "sources" / "memory_int.c"
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules.txt"
    rules_diagnostics = tmp_path / "rules_diagnostics.json"

    main(
        [
            "extract",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(output),
            "--diagnostics",
            str(diagnostics_path),
            "--optimization",
            "0",
            "--verify",
            "--rules-output",
            str(rules_output),
            "--rules-diagnostics",
            str(rules_diagnostics),
        ]
    )

    rules = rules_output.read_text(encoding="utf-8")
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))

    assert "[addr64_" in rules
    assert diagnostics["windows_emitted"] > 0
    assert diagnostics.get("surface_kinds", {}).get("memory", 0) > 0
```

- [ ] **Step 3: Run the smoke test**

Run:

```bash
uv run ruff format tests/test_extraction_pipeline.py
uv run pytest tests/test_extraction_pipeline.py::test_extract_memory_rules_smoke -v
```

Expected: PASS on machines with the required clang targets. If clang lacks AArch64 support, keep the same skip behavior style already used by `test_extract_cli_smoke`.

- [ ] **Step 4: Commit**

Run:

```bash
git add samples/sources/memory_int.c tests/test_extraction_pipeline.py
git commit -m "Add memory rule extraction smoke sample"
```

---

## Task 7: Documentation and Full Verification

**Files:**
- Modify: `docs/rule-generalization.md`
- Modify: `docs/architecture.md`

- [ ] **Step 1: Update rule generalization documentation**

In `docs/rule-generalization.md`, add this section:

````markdown
## Memory Operands

Verified memory rules can replace supported memory operands with shared address
placeholders:

```text
Guest:
	ldr i32_reg1, [addr64_1]
Host:
	mov i32_reg1, dword ptr [addr64_1]
```

The first memory-rule implementation supports integer scalar load/store
operands with one memory access per instruction and base-plus-constant
addressing. Unsupported memory forms are skipped during extraction rather than
emitted as unsafe rules.
````

- [ ] **Step 2: Update architecture documentation**

In `docs/architecture.md`, update the extraction package description to mention:

```markdown
Memory surface inference parses supported load/store operands into structured
base-plus-constant address expressions, pairs guest and host memory accesses,
and emits `MemorySpec` slots for the verifier. Rule generation then rewrites
verified memory operands into shared address placeholders.
```

- [ ] **Step 3: Run full verification**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -q
```

Expected:

- `ruff check`: `All checks passed!`
- `pytest -q`: all tests pass.

- [ ] **Step 4: Run manual memory extraction smoke**

Run:

```bash
uv run angr-rule-learning extract samples/sources/memory_int.c \
  --work-dir runs/samples/memory_rule_smoke/work \
  --output runs/samples/memory_rule_smoke/candidates.jsonl \
  --diagnostics runs/samples/memory_rule_smoke/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output runs/samples/memory_rule_smoke/rules.txt \
  --rules-diagnostics runs/samples/memory_rule_smoke/rules_diagnostics.json
```

Expected:

- Command exits with status 0.
- `runs/samples/memory_rule_smoke/rules.txt` contains `[addr64_`.
- `runs/` remains ignored by git.

- [ ] **Step 5: Print smoke summary**

Run:

```bash
python - <<'PY'
from pathlib import Path
import json

root = Path("runs/samples/memory_rule_smoke")
diagnostics = json.loads((root / "diagnostics.json").read_text())
rule_diagnostics = json.loads((root / "rules_diagnostics.json").read_text())
rules = (root / "rules.txt").read_text().splitlines()

print(json.dumps({
    "windows_emitted": diagnostics.get("windows_emitted"),
    "surface_kinds": diagnostics.get("surface_kinds", {}),
    "skip_reasons": diagnostics.get("skip_reasons", {}),
    "rule_diagnostics": rule_diagnostics,
}, indent=2, sort_keys=True))
print("first_rules:")
for line in rules[:40]:
    print(line)
PY
```

- [ ] **Step 6: Commit docs**

Run:

```bash
git add docs/rule-generalization.md docs/architecture.md
git commit -m "Document memory rule learning support"
```

---

## Final Acceptance Criteria

The implementation is complete when all of these are true:

- `uv run ruff check` passes.
- `uv run pytest -q` passes.
- `SurfaceInferer` no longer contains stack-only memory surface inference helpers.
- Simple load candidates include `MemorySpec` read slots and register outputs.
- Simple store candidates include `MemorySpec` write slots and value input registers.
- Rule output for verified memory candidates contains `[addr64_N]` placeholders instead of concrete address registers.
- `samples/sources/memory_int.c` smoke emits at least one verified memory rule.
- Unsupported memory forms still skip as `unsupported_memory_surface`.
- `runs/` output remains untracked.

## Handoff Notes for Claude Code

Use `superpowers:subagent-driven-development` and execute one task per subagent. Review the diff after each task before continuing. Stop after Task 3 if memory store candidates are still rejected as `no_verifiable_surface`; that indicates the extraction surface integration is not handling memory-only candidates correctly.

When reporting completion, include:

- commit list;
- `ruff check` output;
- `pytest -q` output;
- memory smoke diagnostics summary;
- first 5 generated memory rules;
- remaining unsupported memory forms observed in diagnostics.
