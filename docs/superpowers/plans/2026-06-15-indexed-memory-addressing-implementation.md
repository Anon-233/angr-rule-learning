# Indexed Memory Addressing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Support AArch64 and x86-64 indexed memory addressing through a shared address expression model, verifier memory checks, and native-assembly rule output without `[addr64_N]`.

**Architecture:** Add a shared `AddressExpr` model in the verifier addressing module and make extraction memory operands use it. Keep candidate JSON compatible by serializing canonical address strings, but parse those strings back into `AddressExpr` for verification. Rule generation should stop replacing whole memory operands with opaque address placeholders and instead generalize registers and displacement immediates inside each ISA's original memory syntax.

**Tech Stack:** Python 3.14, dataclasses, pytest, ruff, angr/Claripy, Capstone-disassembled instruction text, existing `VerificationCandidate` / `MemorySpec` model.

---

## File Structure

- Modify `src/angr_rule_learning/verification/addressing.py`
  - Owns `AddressExpr`, canonical string parsing, and address witness helpers.
- Modify `src/angr_rule_learning/extraction/memory_operands.py`
  - Parses AArch64/x86-64 memory operands into `AddressExpr`.
- Modify `src/angr_rule_learning/extraction/memory_surfaces.py`
  - Emits canonical address bindings and includes address registers as candidate inputs.
- Modify `src/angr_rule_learning/extraction/surfaces.py`
  - Stops removing address-register input pairs.
- Modify `src/angr_rule_learning/verification/memory.py`
  - Initializes base/index registers from `AddressExpr` witnesses.
- Modify `src/angr_rule_learning/rules/generalize.py`
  - Ensures address registers are part of placeholder mapping and scale literals are not converted to `immN`.
- Modify `src/angr_rule_learning/rules/memory.py`
  - Removes opaque `[addr64_N]` rewriting behavior; keeps validation helpers if useful.
- Modify docs:
  - `docs/rule-generalization.md`
  - `docs/architecture.md`
  - `README.md`
- Add or modify tests:
  - `tests/test_verifier_addressing.py`
  - `tests/test_extraction_memory_operands.py`
  - `tests/test_extraction_memory_surfaces.py`
  - `tests/test_extraction_surfaces.py`
  - `tests/test_verifier_memory.py`
  - `tests/test_rules_memory_generalize.py`
  - `tests/test_extraction_pipeline.py`
- Add sample:
  - `samples/sources/indexed_memory_int.c`

## Task 1: Add Shared `AddressExpr`

**Files:**
- Modify: `src/angr_rule_learning/verification/addressing.py`
- Create: `tests/test_verifier_addressing.py`

- [ ] **Step 1: Write failing tests for canonical address expressions**

Add `tests/test_verifier_addressing.py`:

```python
import pytest

from angr_rule_learning.verification.addressing import (
    AddressExpr,
    parse_address_binding,
)


def test_address_expr_canonical_base_only() -> None:
    expr = AddressExpr(base="X1")

    assert expr.base == "x1"
    assert expr.index is None
    assert expr.scale == 1
    assert expr.displacement == 0
    assert expr.canonical() == "x1"
    assert expr.registers() == ("x1",)


def test_address_expr_canonical_indexed_with_displacement() -> None:
    expr = AddressExpr(base="RCX", index="RDX", scale=4, displacement=8)

    assert expr.canonical() == "rcx + rdx * 4 + 8"
    assert expr.registers() == ("rcx", "rdx")


def test_address_expr_canonical_negative_displacement() -> None:
    expr = AddressExpr(base="x1", index="x2", scale=4, displacement=-16)

    assert expr.canonical() == "x1 + x2 * 4 - 16"


def test_parse_address_binding_base_plus_index_scale_disp() -> None:
    expr = parse_address_binding("rcx + rdx * 4 + 8")

    assert expr == AddressExpr(base="rcx", index="rdx", scale=4, displacement=8)


def test_parse_address_binding_accepts_legacy_base_plus_offset() -> None:
    expr = parse_address_binding("x1 + 4")

    assert expr == AddressExpr(base="x1", displacement=4)


def test_parse_address_binding_rejects_no_base_first_iteration() -> None:
    with pytest.raises(ValueError, match="unsupported address expression"):
        parse_address_binding("rdx * 4 + 8")


def test_address_expr_rejects_invalid_scale_without_index() -> None:
    with pytest.raises(ValueError, match="scale requires index"):
        AddressExpr(base="x1", scale=4)


def test_address_expr_rejects_invalid_x86_scale() -> None:
    with pytest.raises(ValueError, match="unsupported address scale"):
        AddressExpr(base="rcx", index="rdx", scale=3)
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
uv run pytest tests/test_verifier_addressing.py -q
```

Expected: FAIL because `AddressExpr` does not exist and `parse_address_binding()` returns the old base/offset model.

- [ ] **Step 3: Implement `AddressExpr` and parser**

Replace `src/angr_rule_learning/verification/addressing.py` with an implementation shaped like:

```python
from __future__ import annotations

from dataclasses import dataclass
import re


_REGISTER_RE = r"[A-Za-z][A-Za-z0-9_]*"
_INTEGER_RE = r"0x[0-9a-fA-F]+|\d+"

_BASE_RE = re.compile(rf"^\s*(?P<base>{_REGISTER_RE})\s*$")
_BASE_DISP_RE = re.compile(
    rf"^\s*(?P<base>{_REGISTER_RE})\s*"
    rf"(?P<op>[+-])\s*(?P<disp>{_INTEGER_RE})\s*$"
)
_INDEX_RE = re.compile(
    rf"^\s*(?P<base>{_REGISTER_RE})\s*\+\s*"
    rf"(?P<index>{_REGISTER_RE})"
    rf"(?:\s*\*\s*(?P<scale>{_INTEGER_RE}))?"
    rf"(?:\s*(?P<op>[+-])\s*(?P<disp>{_INTEGER_RE}))?\s*$"
)


@dataclass(frozen=True)
class AddressExpr:
    base: str | None
    index: str | None = None
    scale: int = 1
    displacement: int = 0
    width: int = 64

    def __post_init__(self) -> None:
        base = self.base.strip().lower() if self.base is not None else None
        index = self.index.strip().lower() if self.index is not None else None
        object.__setattr__(self, "base", base)
        object.__setattr__(self, "index", index)
        if base is None:
            raise ValueError("address base register is required")
        if index is None and self.scale != 1:
            raise ValueError("scale requires index")
        if self.scale not in {1, 2, 4, 8}:
            raise ValueError("unsupported address scale")
        if self.width != 64:
            raise ValueError("only 64-bit addresses are supported")

    def registers(self) -> tuple[str, ...]:
        result = [self.base] if self.base is not None else []
        if self.index is not None:
            result.append(self.index)
        return tuple(result)

    def canonical(self) -> str:
        parts = [self.base]
        if self.index is not None:
            if self.scale == 1:
                parts.append(self.index)
            else:
                parts.append(f"{self.index} * {self.scale}")
        text = " + ".join(part for part in parts if part)
        if self.displacement > 0:
            text = f"{text} + {self.displacement}"
        elif self.displacement < 0:
            text = f"{text} - {abs(self.displacement)}"
        return text

    def solve_base_for_slot(self, slot_base: int, index_value: int = 0) -> int:
        return slot_base - index_value * self.scale - self.displacement


def parse_address_binding(expression: str) -> AddressExpr:
    expr = expression.strip().lower()
    for parser in (_parse_base, _parse_base_disp, _parse_indexed):
        parsed = parser(expr)
        if parsed is not None:
            return parsed
    raise ValueError(f"unsupported address expression: {expression}")


def _parse_base(expr: str) -> AddressExpr | None:
    match = _BASE_RE.match(expr)
    if match is None:
        return None
    return AddressExpr(base=match.group("base"))


def _parse_base_disp(expr: str) -> AddressExpr | None:
    match = _BASE_DISP_RE.match(expr)
    if match is None:
        return None
    return AddressExpr(
        base=match.group("base"),
        displacement=_signed_int(match.group("disp"), match.group("op")),
    )


def _parse_indexed(expr: str) -> AddressExpr | None:
    match = _INDEX_RE.match(expr)
    if match is None:
        return None
    scale_text = match.group("scale")
    scale = int(scale_text, 0) if scale_text is not None else 1
    disp_text = match.group("disp")
    displacement = 0
    if disp_text is not None:
        displacement = _signed_int(disp_text, match.group("op"))
    return AddressExpr(
        base=match.group("base"),
        index=match.group("index"),
        scale=scale,
        displacement=displacement,
    )


def _signed_int(text: str, sign: str | None) -> int:
    value = int(text, 0)
    return -value if sign == "-" else value
```

- [ ] **Step 4: Run focused tests**

Run:

```bash
uv run pytest tests/test_verifier_addressing.py -q
```

Expected: PASS.

- [ ] **Step 5: Run existing memory verifier tests**

Run:

```bash
uv run pytest tests/test_verifier_memory.py tests/test_memory_events.py -q
```

Expected: Some tests may fail because `MemoryInitializer` still expects `.register` and `.offset`. Those failures are addressed in Task 5.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/angr_rule_learning/verification/addressing.py tests/test_verifier_addressing.py
git commit -m "Add structured address expressions"
```

## Task 2: Parse Indexed Memory Operands

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_operands.py`
- Modify: `tests/test_extraction_memory_operands.py`

- [ ] **Step 1: Add failing memory operand parser tests**

Append tests to `tests/test_extraction_memory_operands.py`:

```python
from angr_rule_learning.verification.addressing import AddressExpr


def test_parses_aarch64_register_offset_addressing() -> None:
    operands = extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, x2]"))

    assert operands == (
        MemoryOperand(
            kind="read",
            width=4,
            address=AddressExpr(base="x1", index="x2"),
            text="[x1, x2]",
            value_register="w0",
        ),
    )


def test_parses_aarch64_lsl_indexed_addressing() -> None:
    operands = extract_memory_operands(
        _inst("aarch64", "ldr", "w0, [x1, x2, lsl #2]")
    )

    assert operands[0].address == AddressExpr(base="x1", index="x2", scale=4)
    assert operands[0].text == "[x1, x2, lsl #2]"


def test_parses_x86_64_indexed_addressing() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "eax, dword ptr [rcx + rdx*4 + 8]")
    )

    assert operands[0].address == AddressExpr(
        base="rcx",
        index="rdx",
        scale=4,
        displacement=8,
    )
    assert operands[0].text == "[rcx + rdx*4 + 8]"


def test_rejects_aarch64_extend_index_addressing() -> None:
    assert (
        extract_memory_operands(_inst("aarch64", "ldr", "w0, [x1, w2, uxtw #2]"))
        == ()
    )


def test_rejects_x86_64_rip_relative_addressing() -> None:
    assert (
        extract_memory_operands(_inst("x86-64", "mov", "eax, dword ptr [rip + 4]"))
        == ()
    )
```

Update the existing `test_rejects_aarch64_register_offset_addressing` so it no longer expects `()`; the new positive test above replaces that old expectation.

- [ ] **Step 2: Run parser tests and verify failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py -q
```

Expected: FAIL on new indexed addressing tests.

- [ ] **Step 3: Implement AArch64 parser changes**

Modify `src/angr_rule_learning/extraction/memory_operands.py`:

```python
from angr_rule_learning.verification.addressing import AddressExpr
```

Replace `MemoryAddress` usage with `AddressExpr` in `MemoryOperand.address`.

Use complete-match regexes for AArch64:

```python
_AARCH64_VALUE_RE = r"(?P<value>[wx]\d+|sp|wsp|fp|x29|x30|lr)"
_AARCH64_BASE_RE = r"(?P<base>[a-z0-9]+)"
_AARCH64_INDEX_RE = r"(?P<index>[x]\d+)"

_AARCH64_MEM_RE = re.compile(
    rf"^{_AARCH64_VALUE_RE}\s*,\s*"
    rf"(?P<mem>\[{_AARCH64_BASE_RE}"
    rf"(?:\s*,\s*#(?P<disp>[+-]?(?:0x[0-9a-fA-F]+|\d+)))?\])$",
    re.IGNORECASE,
)

_AARCH64_INDEX_MEM_RE = re.compile(
    rf"^{_AARCH64_VALUE_RE}\s*,\s*"
    rf"(?P<mem>\[{_AARCH64_BASE_RE}\s*,\s*{_AARCH64_INDEX_RE}"
    rf"(?:\s*,\s*lsl\s*#(?P<shift>[0-3]))?\])$",
    re.IGNORECASE,
)
```

In `_extract_aarch64`, try the displacement regex first, then the index regex:

```python
def _extract_aarch64(mnemonic: str, op_str: str) -> tuple[MemoryOperand, ...]:
    if mnemonic not in {"ldr", "ldur", "str", "stur"}:
        return ()
    match = _AARCH64_MEM_RE.match(op_str)
    if match is not None:
        value = match.group("value").lower()
        width = _aarch64_register_width(value)
        if width is None:
            return ()
        return (
            MemoryOperand(
                kind="read" if mnemonic in {"ldr", "ldur"} else "write",
                width=width,
                address=AddressExpr(
                    base=match.group("base").lower(),
                    displacement=_parse_displacement(match.group("disp"), "+"),
                ),
                text=match.group("mem"),
                value_register=value,
            ),
        )
    match = _AARCH64_INDEX_MEM_RE.match(op_str)
    if match is None:
        return ()
    value = match.group("value").lower()
    width = _aarch64_register_width(value)
    if width is None:
        return ()
    shift = int(match.group("shift") or "0", 10)
    return (
        MemoryOperand(
            kind="read" if mnemonic in {"ldr", "ldur"} else "write",
            width=width,
            address=AddressExpr(
                base=match.group("base").lower(),
                index=match.group("index").lower(),
                scale=1 << shift,
            ),
            text=match.group("mem"),
            value_register=value,
        ),
    )
```

- [ ] **Step 4: Implement x86-64 parser changes**

Replace `_X86_MEM_RE` with a bracket extractor plus address parser:

```python
_X86_BRACKET_RE = re.compile(r"(?P<mem>\[[^\]]+\])", re.IGNORECASE)


def _x86_address_from_mem_text(mem_text: str) -> AddressExpr | None:
    inner = mem_text.strip()[1:-1].strip().lower()
    if inner.startswith("rip"):
        return None
    if ":" in inner:
        return None
    normalized = re.sub(r"\s+", " ", inner)
    normalized = normalized.replace("*", " * ")
    normalized = re.sub(r"\s+", " ", normalized)
    try:
        return parse_address_binding(normalized)
    except ValueError:
        return None
```

Update `_extract_x86_64()` so `left_mem` and `right_mem` come from `_X86_BRACKET_RE.search(...)`, and `_x86_operand()` accepts an `AddressExpr`:

```python
def _x86_operand(
    kind: MemoryKind,
    width: int,
    match: re.Match[str],
    value_register: str,
) -> MemoryOperand | None:
    address = _x86_address_from_mem_text(match.group("mem"))
    if address is None:
        return None
    return MemoryOperand(
        kind=kind,
        width=width,
        address=address,
        text=match.group("mem"),
        value_register=value_register,
    )
```

Make callers return `()` when `_x86_operand()` returns `None`.

- [ ] **Step 5: Run parser tests**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py tests/test_verifier_addressing.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/angr_rule_learning/extraction/memory_operands.py tests/test_extraction_memory_operands.py
git commit -m "Parse indexed memory operands"
```

## Task 3: Surface Inference Preserves Address Register Inputs

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Modify: `tests/test_extraction_memory_surfaces.py`
- Modify: `tests/test_extraction_surfaces.py`

- [ ] **Step 1: Add failing memory surface tests**

Append to `tests/test_extraction_memory_surfaces.py`:

```python
def test_infers_indexed_load_address_register_inputs() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx + rdx*4]"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "x1 + x2 * 4"
    assert surface.spec.bindings[0].host_addr == "rcx + rdx * 4"
    assert surface.input_registers == (("x1", "rcx"), ("x2", "rdx"))


def test_infers_indexed_store_value_and_address_inputs() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx + rdx*4], eax"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.input_registers == (
        ("x1", "rcx"),
        ("x2", "rdx"),
        ("w0", "eax"),
    )
```

- [ ] **Step 2: Add failing `SurfaceInferer` candidate test**

Append to `tests/test_extraction_surfaces.py`:

```python
from angr_rule_learning.extraction.liveness import InstructionLiveness


def _empty_liveness(*instructions: ExtractedInstruction) -> LivenessIndex:
    return LivenessIndex(
        {
            (inst.arch, inst.function, inst.address): InstructionLiveness(
                live_in=frozenset(),
                live_out=frozenset(),
                reads=(),
                writes=(),
                successor_addresses=(),
            )
            for inst in instructions
        }
    )


def test_surface_inferer_emits_indexed_memory_address_inputs() -> None:
    guest = _mem_inst(
        "aarch64",
        0x1000,
        ("x1", "x2"),
        ("w0",),
        mnemonic="ldr",
        op_str="w0, [x1, x2, lsl #2]",
    )
    host = _mem_inst(
        "x86-64",
        0x2000,
        ("rcx", "rdx"),
        ("eax",),
        mnemonic="mov",
        op_str="eax, dword ptr [rcx + rdx*4]",
    )
    pair = _mem_pair(guest, host)
    diagnostics = MiningDiagnostics()

    candidate = SurfaceInferer(diagnostics, _empty_liveness(guest, host)).infer(pair)

    assert candidate is not None
    assert candidate.input_registers == (("x1", "rcx"), ("x2", "rdx"))
    assert candidate.output_registers == ()
    assert candidate.memory.bindings[0].guest_addr == "x1 + x2 * 4"
    assert candidate.memory.bindings[0].host_addr == "rcx + rdx * 4"
```

- [ ] **Step 3: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py -q
```

Expected: FAIL because address registers are not yet included as inputs and indexed forms are not surfaced.

- [ ] **Step 4: Update `memory_surfaces.py`**

Modify `infer_memory_surface()` so it appends address register pairs for every binding:

```python
for index, (guest, host) in enumerate(zip(guest_operands, host_operands, strict=True)):
    if guest.kind != host.kind or guest.width != host.width:
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            guest_operands=guest_operands,
            host_operands=host_operands,
        )
    guest_regs = guest.address.registers()
    host_regs = host.address.registers()
    if len(guest_regs) != len(host_regs):
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            guest_operands=guest_operands,
            host_operands=host_operands,
        )
    input_registers.extend(zip(guest_regs, host_regs, strict=True))
    slot_name = f"mem{index}"
    slots.append(MemorySlot(slot_name, guest.width))
    bindings.append(
        MemoryBinding(
            slot_name,
            guest.address.canonical(),
            host.address.canonical(),
            guest.kind,
        )
    )
    accesses.append(MemoryAccessExpectation(slot_name, guest.kind, guest.width))
    if guest.kind == "write":
        input_registers.append((guest.value_register, host.value_register))
```

Set `address_registers=()` in the returned `MemorySurface`, or remove uses once `surfaces.py` no longer removes address pairs.

- [ ] **Step 5: Update `surfaces.py`**

Remove address-pair removal from `SurfaceInferer.infer()`:

```python
input_registers = tuple(zip(guest_inputs, host_inputs, strict=True))
input_registers = _merge_register_pairs(
    input_registers,
    memory_surface.input_registers,
)
```

Then delete `_remove_register_pairs()` if it becomes unused.

- [ ] **Step 6: Run surface tests**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py
git commit -m "Preserve address registers in memory surfaces"
```

## Task 4: Update Verifier Memory Initialization for Indexed Addresses

**Files:**
- Modify: `src/angr_rule_learning/verification/memory.py`
- Modify: `tests/test_verifier_memory.py`
- Modify: `tests/test_memory_events.py`

- [ ] **Step 1: Add verifier tests for indexed load**

Add constants and tests to `tests/test_verifier_memory.py`:

```python
AARCH64_LDR_W0_X1_X2_LSL2 = "207862b8"
X86_64_MOV_EAX_RCX_RDX_SCALE4 = "8b0491"
X86_64_MOV_EAX_RCX_RDX_SCALE8 = "8b04d1"


def test_verifier_accepts_equivalent_indexed_load() -> None:
    candidate = VerificationCandidate(
        candidate_id="indexed-load32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1_X2_LSL2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_RDX_SCALE4, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(
                MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),
            ),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_rejects_wrong_index_scale() -> None:
    candidate = VerificationCandidate(
        candidate_id="indexed-load32-wrong-scale",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1_X2_LSL2, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX_RDX_SCALE8, 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(
                MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),
            ),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "fail"
    assert any(
        check.reason == "host_memory_address_mismatch" for check in report.checks
    )
```

- [ ] **Step 2: Run verifier memory tests and verify failure**

Run:

```bash
uv run pytest tests/test_verifier_memory.py -q
```

Expected: FAIL because `_write_bound_address()` still expects `binding.register` and `binding.offset`.

- [ ] **Step 3: Implement indexed memory initialization**

Modify `src/angr_rule_learning/verification/memory.py`:

```python
_INDEX_WITNESS = 3


def _address_register_values(expression: str, base: int) -> dict[str, int]:
    expr = parse_address_binding(expression)
    values: dict[str, int] = {}
    index_value = 0
    if expr.index is not None:
        index_value = _INDEX_WITNESS
        values[expr.index] = index_value
    if expr.base is not None:
        values[expr.base] = expr.solve_base_for_slot(base, index_value)
    return values


def _write_bound_address(state: angr.SimState, expression: str, base: int) -> None:
    for register, value in _address_register_values(expression, base).items():
        write_reg(state, register, claripy.BVV(value, state.arch.bits))
```

This keeps current behavior for base-only and base+disp expressions while adding indexed support.

- [ ] **Step 4: Guard repeated register assignments**

In `MemoryInitializer.initialize()`, avoid silently assigning the same register two incompatible concrete values across multiple memory bindings. Add a helper:

```python
def _merge_register_values(
    current: dict[str, int],
    updates: dict[str, int],
) -> None:
    for register, value in updates.items():
        existing = current.get(register)
        if existing is not None and existing != value:
            raise ValueError("unsupported address expression: conflicting bindings")
        current[register] = value
```

Then replace direct `_write_bound_address()` calls with collecting and writing per side:

```python
guest_values: dict[str, int] = {}
host_values: dict[str, int] = {}
for binding in candidate.memory.bindings:
    base = bases[binding.slot]
    _merge_register_values(guest_values, _address_register_values(binding.guest_addr, base))
    _merge_register_values(host_values, _address_register_values(binding.host_addr, base))

for register, value in guest_values.items():
    write_reg(guest_state, register, claripy.BVV(value, guest_state.arch.bits))
for register, value in host_values.items():
    write_reg(host_state, register, claripy.BVV(value, host_state.arch.bits))
```

- [ ] **Step 5: Run verifier tests**

Run:

```bash
uv run pytest tests/test_verifier_memory.py tests/test_memory_events.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/angr_rule_learning/verification/memory.py tests/test_verifier_memory.py tests/test_memory_events.py
git commit -m "Verify indexed memory address bindings"
```

## Task 5: Preserve JSON Compatibility for Extended Address Bindings

**Files:**
- Modify: `src/angr_rule_learning/verification/candidate.py`
- Modify: `src/angr_rule_learning/io/schema.py`
- Modify: `src/angr_rule_learning/extraction/emit.py`
- Modify: `tests/test_candidate_models.py`
- Modify: `tests/test_schema.py`
- Modify: `tests/test_extraction_emit.py`

- [ ] **Step 1: Add schema tests for indexed binding round trip**

Append to `tests/test_schema.py`:

```python
def test_candidate_from_json_accepts_indexed_memory_binding() -> None:
    payload = _candidate_payload()
    payload["memory"]["bindings"][0]["guest_addr"] = "x1 + x2 * 4 + 8"
    payload["memory"]["bindings"][0]["host_addr"] = "rcx + rdx * 4 + 8"

    candidate = candidate_from_json(payload)

    assert candidate.memory.bindings[0].guest_addr == "x1 + x2 * 4 + 8"
    assert candidate.memory.bindings[0].host_addr == "rcx + rdx * 4 + 8"
```

Append to `tests/test_candidate_models.py`:

```python
def test_memory_binding_normalizes_indexed_addresses() -> None:
    binding = MemoryBinding(
        "mem0",
        "X1 + X2 * 4 + 8",
        "RCX + RDX * 4 + 8",
        "read",
    )

    assert binding.guest_addr == "x1 + x2 * 4 + 8"
    assert binding.host_addr == "rcx + rdx * 4 + 8"
```

- [ ] **Step 2: Run schema tests and verify failure**

Run:

```bash
uv run pytest tests/test_schema.py tests/test_candidate_models.py tests/test_extraction_emit.py -q
```

Expected: FAIL if `MemoryBinding` does not canonicalize indexed expressions.

- [ ] **Step 3: Canonicalize binding strings in `MemoryBinding`**

Modify `MemoryBinding.__post_init__()` in `src/angr_rule_learning/verification/candidate.py`:

```python
from angr_rule_learning.verification.addressing import parse_address_binding
```

Then normalize addresses through the parser:

```python
guest_addr = parse_address_binding(self.guest_addr).canonical()
host_addr = parse_address_binding(self.host_addr).canonical()
object.__setattr__(self, "guest_addr", guest_addr)
object.__setattr__(self, "host_addr", host_addr)
```

Keep the existing non-empty checks before parsing so empty strings still produce the current validation error.

- [ ] **Step 4: Keep JSON field names unchanged**

Do not change `MEMORY_BINDING_FIELDS` in `src/angr_rule_learning/io/schema.py`. Candidate JSON should still use:

```json
{
  "slot": "mem0",
  "guest_addr": "x1 + x2 * 4 + 8",
  "host_addr": "rcx + rdx * 4 + 8",
  "access": "read"
}
```

Confirm `src/angr_rule_learning/extraction/emit.py` still writes `guest_addr` and `host_addr` as strings. If the previous tasks changed `MemoryBinding` only, no edit is needed in `emit.py`.

- [ ] **Step 5: Run schema tests**

Run:

```bash
uv run pytest tests/test_schema.py tests/test_candidate_models.py tests/test_extraction_emit.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit Task 5**

```bash
git add src/angr_rule_learning/verification/candidate.py src/angr_rule_learning/io/schema.py src/angr_rule_learning/extraction/emit.py tests/test_schema.py tests/test_candidate_models.py tests/test_extraction_emit.py
git commit -m "Canonicalize indexed memory bindings"
```

## Task 6: Emit Native Memory Operand Rules

**Files:**
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Modify: `src/angr_rule_learning/rules/memory.py`
- Modify: `tests/test_rules_memory_generalize.py`

- [ ] **Step 1: Add failing rule output tests**

Replace the expectations in `tests/test_rules_memory_generalize.py` so memory rules keep native syntax:

```python
def test_generalizes_load_memory_registers_without_addr_placeholder() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("x1", "rcx"),),
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

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [i64_reg2]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [i64_reg2]",)


def test_generalizes_memory_displacement_with_shared_immediate() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load-disp",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("x1", "rcx"),),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + 8", "rcx + 8", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "ldr", "w0, [x1, #8]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx + 8]"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [i64_reg2, #imm1]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [i64_reg2 + imm1]",)


def test_generalizes_indexed_memory_keeps_scale_literals() -> None:
    candidate = VerificationCandidate(
        candidate_id="mem-load-indexed",
        guest=CodeFragment("aarch64", 0x1000, "01020304", 1),
        host=CodeFragment("x86-64", 0x2000, "01020304", 1),
        input_registers=(("x1", "rcx"), ("x2", "rdx")),
        output_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1 + x2 * 4", "rcx + rdx * 4", "read"),),
            accesses=(MemoryAccessExpectation("mem0", "read", 4),),
        ),
    )
    pair = _pair(
        _inst("aarch64", 0x1000, "ldr", "w0, [x1, x2, lsl #2]"),
        _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx + rdx*4]"),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1, pair, candidate, _pass(candidate.candidate_id)
    )

    assert rule is not None
    assert rule.guest_lines == ("ldr i32_reg1, [i64_reg2, i64_reg3, lsl #2]",)
    assert rule.host_lines == ("mov i32_reg1, dword ptr [i64_reg2 + i64_reg3*4]",)
    assert "addr64" not in "\n".join(rule.guest_lines + rule.host_lines)
```

- [ ] **Step 2: Run rule tests and verify failure**

Run:

```bash
uv run pytest tests/test_rules_memory_generalize.py -q
```

Expected: FAIL because `rules.memory.rewrite_memory_operands()` still emits `[addr64_N]` and generic immediate replacement converts scale literals.

- [ ] **Step 3: Stop opaque memory operand rewriting**

Modify `src/angr_rule_learning/rules/generalize.py` and remove these calls from `RuleGeneralizer.generate()`:

```python
guest_lines = rewrite_memory_operands(...)
host_lines = rewrite_memory_operands(...)
```

Remove the import:

```python
from angr_rule_learning.rules.memory import rewrite_memory_operands
```

Keep `src/angr_rule_learning/rules/memory.py` only if it still contains useful validation helpers. If no code imports `rewrite_memory_operands`, delete the function or leave a smaller helper named `memory_operands_match_bindings()` used by tests.

- [ ] **Step 4: Keep scale and shift literals during immediate replacement**

Modify `_replace_immediates_shared()` in `src/angr_rule_learning/rules/generalize.py` so `lsl #2` and `*4` are not converted to `immN`.

Add helper:

```python
def _is_scale_immediate(line: str, match: re.Match[str], arch: str) -> bool:
    arch = normalize_arch_name(arch)
    before = line[: match.start()].lower()
    if arch == "aarch64":
        return before.rstrip().endswith("lsl")
    if arch == "x86-64":
        return before.rstrip().endswith("*")
    return False
```

Use it in both passes that collect and replace immediates:

```python
for line in guest_lines:
    for m in guest_pattern.finditer(line):
        if _is_scale_immediate(line, m, guest_arch_n):
            continue
        c = _imm_canonical(m, guest_arch)
        ...
```

In `_replace_side()`:

```python
def _replacer(match: re.Match[str]) -> str:
    if _is_scale_immediate(line, match, arch):
        return match.group(0)
    c = _imm_canonical(match, arch)
    if c in ("0", "00", "000"):
        return match.group(0)
    return f"{prefix}imm{canonical_to_id[c]}"

return tuple(pattern.sub(_replacer, line) for line in lines)
```

Implement this by making `_replace_side()` iterate line by line so the replacer can close over the current line.

- [ ] **Step 5: Run rule tests**

Run:

```bash
uv run pytest tests/test_rules_memory_generalize.py tests/test_rules_generalize.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit Task 6**

```bash
git add src/angr_rule_learning/rules/generalize.py src/angr_rule_learning/rules/memory.py tests/test_rules_memory_generalize.py
git commit -m "Emit native memory operands in rules"
```

## Task 7: End-to-End Indexed Memory Smoke

**Files:**
- Create: `samples/sources/indexed_memory_int.c`
- Modify: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Add indexed sample source**

Create `samples/sources/indexed_memory_int.c`:

```c
#define KEEP __attribute__((noinline, used))

KEEP int read_indexed(const int *p, int i) {
    return p[i];
}

KEEP void write_indexed(int *p, int i, int v) {
    p[i] = v;
}

KEEP int copy_indexed(int *dst, const int *src, int i) {
    dst[i] = src[i];
    return dst[i];
}

int main(void) {
    int values[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    int out[8] = {0};
    int a = read_indexed(values, 3);
    write_indexed(out, 2, a);
    int b = copy_indexed(out, values, 4);
    return a + b + out[2];
}
```

- [ ] **Step 2: Add pipeline smoke test**

Append to `tests/test_extraction_pipeline.py`:

```python
def test_indexed_memory_rule_smoke(tmp_path: Path) -> None:
    if shutil.which("clang") is None:
        return
    source = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "sources"
        / "indexed_memory_int.c"
    )
    output = tmp_path / "candidates.jsonl"
    diagnostics_path = tmp_path / "diagnostics.json"
    rules_output = tmp_path / "rules.txt"
    rules_diagnostics = tmp_path / "rules_diagnostics.json"
    try:
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
    except RuntimeError as exc:
        if "error: unable to create target" in str(exc).lower():
            return
        if "cannot find clang" in str(exc).lower():
            return
        raise

    rules_text = rules_output.read_text(encoding="utf-8")
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert diagnostics.get("surface_kinds", {}).get("memory", 0) > 0
    assert "addr64_" not in rules_text
    assert "i64_reg" in rules_text
    assert ("*4" in rules_text or "lsl #2" in rules_text), rules_text[:1000]
```

- [ ] **Step 3: Run smoke test and verify failure**

Run:

```bash
uv run pytest tests/test_extraction_pipeline.py::test_indexed_memory_rule_smoke -q
```

Expected: FAIL until previous tasks are integrated and extractor emits indexed memory candidates.

- [ ] **Step 4: Adjust sample only if compiler output lacks indexed addressing**

If the smoke test compiles but does not produce indexed memory rules at `-O0`, inspect disassembly from the extraction work directory and adjust the C sample to make array indexing explicit. Keep the functions noinline and used. Do not add library calls.

Use:

```bash
uv run angr-rule-learning extract samples/sources/indexed_memory_int.c --work-dir /tmp/arl-indexed-debug/work --output /tmp/arl-indexed-debug/candidates.jsonl --diagnostics /tmp/arl-indexed-debug/diagnostics.json --optimization 0 --verify --rules-output /tmp/arl-indexed-debug/rules.txt --rules-diagnostics /tmp/arl-indexed-debug/rules_diagnostics.json
```

Expected after adjustment: `rules.txt` contains at least one native memory operand with `i64_reg` and either `*4` or `lsl #2`.

- [ ] **Step 5: Run smoke test**

Run:

```bash
uv run pytest tests/test_extraction_pipeline.py::test_indexed_memory_rule_smoke -q
```

Expected: PASS.

- [ ] **Step 6: Commit Task 7**

```bash
git add samples/sources/indexed_memory_int.c tests/test_extraction_pipeline.py
git commit -m "Add indexed memory extraction smoke"
```

## Task 8: Documentation Update

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/rule-generalization.md`
- Modify: `docs/candidate-format.md`
- Modify: `docs/superpowers/specs/2026-06-15-indexed-memory-addressing-design.md`

- [ ] **Step 1: Update rule generalization docs**

In `docs/rule-generalization.md`, replace the `[addr64_N]` memory output section with examples:

```text
1.Guest:
	ldr i32_reg1, [i64_reg2, #imm1]
.Host:
	mov i32_reg1, dword ptr [i64_reg2 + imm1]

2.Guest:
	ldr i32_reg1, [i64_reg2, i64_reg3, lsl #2]
.Host:
	mov i32_reg1, dword ptr [i64_reg2 + i64_reg3*4]
```

State that:

- address base/index registers use normal typed register placeholders;
- displacements shared by guest and host use the same `immN`;
- scale/shift literals remain literal in the first indexed-addressing implementation;
- `[addr64_N]` is no longer emitted for new memory rules.

- [ ] **Step 2: Update candidate format docs**

In `docs/candidate-format.md`, update memory binding examples to show canonical address strings:

```json
{
  "slot": "mem0",
  "guest_addr": "x1 + x2 * 4 + 8",
  "host_addr": "rcx + rdx * 4 + 8",
  "access": "read"
}
```

State that JSON remains string-based for compatibility, while the verifier parses these strings into `AddressExpr`.

- [ ] **Step 3: Update architecture and README**

In `docs/architecture.md`, document:

- `AddressExpr` as the shared model for extraction and verifier memory bindings;
- surface inference includes address registers in candidate inputs;
- rule generation preserves native memory syntax.

In `README.md`, update Current Status to say indexed base+index*scale addressing is supported for the scoped AArch64/x86-64 load/store/mov forms.

- [ ] **Step 4: Run docs grep checks**

Run:

```bash
rg -n "addr64|indexed|AddressExpr|guest_addr|host_addr" README.md docs
```

Expected:

- `addr64` appears only in historical/spec text that explicitly says it is old or no longer emitted.
- `AddressExpr` and indexed memory support are documented in architecture/candidate/rule docs.

- [ ] **Step 5: Commit Task 8**

```bash
git add README.md docs/architecture.md docs/rule-generalization.md docs/candidate-format.md docs/superpowers/specs/2026-06-15-indexed-memory-addressing-design.md
git commit -m "Document indexed memory rule output"
```

## Task 9: Final Verification and Manual Smoke

**Files:**
- No source edits expected unless verification finds a regression.

- [ ] **Step 1: Run formatter**

Run:

```bash
uv run ruff format
```

Expected: files are formatted. If files changed, include them in the final commit or create a formatting commit.

- [ ] **Step 2: Run static checks**

Run:

```bash
uv run ruff check
```

Expected: `All checks passed!`

- [ ] **Step 3: Run full test suite**

Run:

```bash
uv run pytest -q
```

Expected: all tests pass. The existing Python 3.14 dependency warnings may remain.

- [ ] **Step 4: Run manual indexed memory smoke**

Run:

```bash
uv run angr-rule-learning extract samples/sources/indexed_memory_int.c \
  --work-dir /tmp/angr-rule-learning-indexed-memory/work \
  --output /tmp/angr-rule-learning-indexed-memory/candidates.jsonl \
  --diagnostics /tmp/angr-rule-learning-indexed-memory/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output /tmp/angr-rule-learning-indexed-memory/rules.txt \
  --rules-diagnostics /tmp/angr-rule-learning-indexed-memory/rules-diagnostics.json
```

Expected:

- command exits 0;
- diagnostics shows `surface_kinds.memory > 0`;
- `rules.txt` contains native memory operands with `i64_reg`;
- `rules.txt` does not contain `[addr64_`;
- at least one rule contains `*4` or `lsl #2`.

- [ ] **Step 5: Inspect smoke output**

Run:

```bash
python3 -m json.tool /tmp/angr-rule-learning-indexed-memory/diagnostics.json
python3 -m json.tool /tmp/angr-rule-learning-indexed-memory/rules-diagnostics.json
sed -n '1,160p' /tmp/angr-rule-learning-indexed-memory/rules.txt
```

Expected: output is readable and confirms indexed memory rule emission.

- [ ] **Step 6: Commit any remaining verification fixes**

If Task 9 produced formatting or verification fixes, commit them:

```bash
git add .
git commit -m "Finalize indexed memory addressing support"
```

If there are no changes, do not create an empty commit.

- [ ] **Step 7: Report final status**

Run:

```bash
git status --short
git log --oneline -n 8
```

Expected:

- `git status --short` is empty;
- recent commits show the indexed addressing task stack.

Final report should include:

- verification command results;
- manual smoke diagnostics summary;
- first indexed memory rule sample;
- remaining unsupported forms: AArch64 writeback, `uxtw/sxtw`, pair load/store, x86 RIP-relative, no-base indexed addressing, segment override, memory-to-memory, read-modify-write instructions.

## Implementation Notes

- Do not reintroduce `[addr64_N]` in new rule output.
- Do not treat placeholder mapping as a substitute for effective-address verification.
- Do not set index witness values to zero in the verifier.
- Keep JSON memory binding fields string-based in this iteration.
- Keep scale/shift literals out of `immN` replacement until scale placeholders are intentionally designed.
- If a supported memory operand parses into `AddressExpr`, it should either verify or fail semantically; it should not be skipped solely because scale or displacement differs.
