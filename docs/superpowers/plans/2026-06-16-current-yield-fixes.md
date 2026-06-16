# Current Yield Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the current rule-learning yield blockers found by running `smoke_int.c`, `memory_int.c`, and `indexed_memory_int.c`: verifier internal errors, bad store-immediate candidates, frame-relative memory address mismatches, and missing sign-extension load support.

**Architecture:** Keep the verifier/candidate boundary typed and conservative. Fix definite bugs first, then add a small frame-relative memory address model that applies only to known stack/frame registers, and finally extend memory operand parsing for one high-frequency sign-extension load family. Avoid adding broad x86 read-modify-write or prologue/epilogue semantics in this plan.

**Tech Stack:** Python 3.14, angr, Claripy, Capstone-derived instruction metadata, pytest, ruff, existing `uv run` workflow.

---

## Baseline Evidence

Use this baseline when checking final results. These numbers came from:

```bash
./scripts/run_all_tests.sh samples/sources/smoke_int.c /private/tmp/arl-current-smoke/work /private/tmp/arl-current-smoke/out 0
./scripts/run_all_tests.sh samples/sources/memory_int.c /private/tmp/arl-current-memory/work /private/tmp/arl-current-memory/out 0
./scripts/run_all_tests.sh samples/sources/indexed_memory_int.c /private/tmp/arl-current-indexed/work /private/tmp/arl-current-indexed/out 0
```

Current `smoke_int.c` baseline:

```text
windows_enumerated: 5070
windows_emitted: 252
windows_verified_pass: 28
rules_emitted: 9
verify statuses: pass=28 fail=194 unsupported=27 error=3
top verify reasons:
  register_mismatch: 150
  host_memory_address_mismatch: 128
  unsupported_address_expression: 27
  verifier_internal_error: 3
```

Current bug examples:

```text
verifier_internal_error:
  Frontend.add() takes from 2 to 3 positional arguments but 5 were given
  unknown register for AMD64: 3

bad candidate input:
  inputs [["x29", "rbp"], ["w8", "3"]]

frame mismatch candidate:
  guest_addr: sp + 12
  host_addr: rbp - 4
```

---

## File Structure

- Modify `src/angr_rule_learning/verification/relations.py`
  - Fix Claripy solver constraint addition for tuple/list constraints.
- Modify `tests/test_relation_checker.py`
  - Add regression coverage for multiple constraints.
- Modify `src/angr_rule_learning/extraction/memory_operands.py`
  - Distinguish register store values from immediate store values.
  - Add `ldrsw` / `movsxd` memory operand parsing.
- Modify `src/angr_rule_learning/extraction/memory_surfaces.py`
  - Reject unsupported store-immediate pairings instead of emitting bogus register inputs.
  - Treat known frame/stack address register pairs as address-only bindings instead of equality inputs.
- Modify `tests/test_extraction_memory_operands.py`
  - Add parser tests for store immediates and sign-extension load operands.
- Modify `tests/test_extraction_memory_surfaces.py`
  - Add surface tests for store-immediate rejection, frame address-only pairs, and sign-extension memory surfaces.
- Modify `src/angr_rule_learning/verification/memory.py`
  - Add frame-relative memory register initialization for stack/frame base pairs.
  - Preserve existing exact shared-input behavior for normal registers.
- Modify `tests/test_verifier_memory.py`
  - Add regression tests for multi-constraint memory checks and frame-relative slots.
- Modify `src/angr_rule_learning/rules/registers.py`
  - Add frame pointer placeholder support (`fp64`) for `x29/fp/rbp`.
- Modify `src/angr_rule_learning/rules/generalize.py`
  - Add memory-binding register placeholders to the rule mapping so frame-only address registers can still generalize.
- Modify `tests/test_rules_registers.py`
  - Add frame placeholder tests.
- Modify `tests/test_rules_memory_generalize.py`
  - Add frame-relative memory rule generalization tests.
- Modify `docs/architecture.md`
  - Document frame-relative memory address treatment and this plan's unsupported boundaries.

Do not implement in this plan:

- x86 read-modify-write memory arithmetic (`add/or/and/xor/sub/cmp reg, [mem]`) as a semantic surface;
- `push/pop` and AArch64 `stp/ldp` prologue/epilogue semantics;
- branch-target equivalence;
- coverage reporting.

Those are still important, but each deserves a separate design once this correctness layer is stable.

---

### Task 1: Fix Claripy Multi-Constraint Relation Checks

**Files:**
- Modify: `src/angr_rule_learning/verification/relations.py`
- Modify: `tests/test_relation_checker.py`

- [ ] **Step 1: Write failing tests for multiple constraints**

Append these tests to `tests/test_relation_checker.py`:

```python
def test_relation_checker_accepts_multiple_constraints() -> None:
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    checker = RelationChecker(
        symbols={"x": x, "y": y},
        constraints=(x == 3, y == 4),
    )

    result = checker.check_equal(
        kind="register",
        guest="x_plus_y",
        host="seven",
        guest_expr=x + y,
        host_expr=claripy.BVV(7, 32),
        mismatch_reason="register_mismatch",
    )

    assert result.status == "pass"


def test_relation_checker_counterexample_with_multiple_constraints() -> None:
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    checker = RelationChecker(
        symbols={"x": x, "y": y},
        constraints=(x == 3, y == 4),
    )

    result = checker.check_equal(
        kind="register",
        guest="x_plus_y",
        host="eight",
        guest_expr=x + y,
        host_expr=claripy.BVV(8, 32),
        mismatch_reason="register_mismatch",
    )

    assert result.status == "fail"
    assert result.reason == "register_mismatch"
    assert result.counterexample["x"] == 3
    assert result.counterexample["y"] == 4
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_relation_checker.py::test_relation_checker_accepts_multiple_constraints tests/test_relation_checker.py::test_relation_checker_counterexample_with_multiple_constraints -q
```

Expected before the fix: at least one test fails with `Frontend.add() takes from 2 to 3 positional arguments`.

- [ ] **Step 3: Implement constraint addition helper**

Modify `src/angr_rule_learning/verification/relations.py`.

Add a private helper near the top:

```python
def _add_constraints(solver: claripy.Solver, constraints: tuple[object, ...]) -> None:
    for constraint in constraints:
        solver.add(constraint)
```

Replace both occurrences of:

```python
solver.add(*self._constraints)
```

with:

```python
_add_constraints(solver, self._constraints)
```

- [ ] **Step 4: Verify the fix**

Run:

```bash
uv run pytest tests/test_relation_checker.py -q
uv run pytest tests/test_verifier_memory.py -q
uv run ruff format src/angr_rule_learning/verification/relations.py tests/test_relation_checker.py
uv run ruff check src/angr_rule_learning/verification/relations.py tests/test_relation_checker.py
```

Expected: tests pass and ruff passes.

- [ ] **Step 5: Commit**

```bash
git add src/angr_rule_learning/verification/relations.py tests/test_relation_checker.py
git commit -m "Fix relation checks with multiple constraints"
```

---

### Task 2: Reject Unsupported Store-Immediate Memory Surfaces

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_operands.py`
- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Modify: `tests/test_extraction_memory_operands.py`
- Modify: `tests/test_extraction_memory_surfaces.py`

**Rationale:** The current extractor can emit `input_registers` like `("w8", "3")` when x86 stores an immediate to memory. The verifier then treats `3` as an AMD64 register and reports `verifier_internal_error`. Until candidate preconditions or explicit immediate value bindings exist, mismatched register/immediate store values must be rejected at surface inference.

- [ ] **Step 1: Add parser test for x86 immediate store source**

Append to `tests/test_extraction_memory_operands.py`:

```python
def test_x86_store_immediate_memory_operand_is_marked_non_register_value() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "mov", "dword ptr [rbp - 4], 3")
    )

    assert len(operands) == 1
    assert operands[0].kind == "write"
    assert operands[0].width == 4
    assert operands[0].address == AddressExpr(base="rbp", displacement=-4)
    assert operands[0].value_register is None
    assert operands[0].value_immediate == "3"
```

- [ ] **Step 2: Add surface test that rejects register/immediate store pairing**

Append to `tests/test_extraction_memory_surfaces.py`:

```python
def test_rejects_register_to_immediate_store_value_pairing() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w8, [x29, #-4]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rbp - 4], 3"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "store_value_immediate_unsupported"
```

- [ ] **Step 3: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py::test_x86_store_immediate_memory_operand_is_marked_non_register_value tests/test_extraction_memory_surfaces.py::test_rejects_register_to_immediate_store_value_pairing -q
```

Expected: tests fail because `MemoryOperand` has no `value_immediate` and surface inference still emits a bad input pair.

- [ ] **Step 4: Extend `MemoryOperand` model**

Modify `src/angr_rule_learning/extraction/memory_operands.py`.

Change the dataclass to:

```python
@dataclass(frozen=True)
class MemoryOperand:
    kind: MemoryKind
    width: int
    address: AddressExpr
    text: str
    value_register: str | None
    value_immediate: str | None = None
```

Add this helper near `_X86_SEGMENT_OVERRIDE_RE`:

```python
_X86_REGISTER_TOKEN_RE = re.compile(
    r"^(?:r(?:[0-9]+|[abcd]x|[sb]p|[sd]i)|e(?:[abcd]x|[sb]p|[sd]i)|"
    r"(?:[abcd][lh])|(?:[abcd]x)|(?:[sb]p)|(?:[sd]i)|r(?:8|9|1[0-5])[bwd]?)$",
    re.IGNORECASE,
)


def _x86_register_or_immediate(text: str) -> tuple[str | None, str | None]:
    value = text.strip().lower()
    if _X86_REGISTER_TOKEN_RE.match(value):
        return value, None
    return None, value
```

In `_extract_x86_64()`, update the write-side branch:

```python
    if left_mem is not None:
        if _X86_SEGMENT_OVERRIDE_RE.search(left):
            return ()
        value_register, value_immediate = _x86_register_or_immediate(right)
        width = _x86_width(left, value_register or "")
        if width is None:
            return ()
        operand = _x86_operand(
            "write",
            width,
            left_mem,
            value_register,
            value_immediate=value_immediate,
        )
        return (operand,) if operand is not None else ()
```

Update `_x86_operand()` signature:

```python
def _x86_operand(
    kind: MemoryKind,
    width: int,
    match: re.Match[str],
    value_register: str | None,
    *,
    value_immediate: str | None = None,
) -> MemoryOperand | None:
```

Return:

```python
    return MemoryOperand(
        kind=kind,
        width=width,
        address=address,
        text=match.group("mem"),
        value_register=value_register,
        value_immediate=value_immediate,
    )
```

Keep read-side operands with `value_register` set to the destination register and `value_immediate=None`.

- [ ] **Step 5: Reject unsupported store-immediate pairings**

Modify `src/angr_rule_learning/extraction/memory_surfaces.py`.

Inside the `if guest.kind == "write":` block, before `_value_is_defined_before(...)`, add:

```python
            if guest.value_register is None or host.value_register is None:
                return MemorySurface(
                    MemorySpec(),
                    skip_reason="unsupported_memory_surface",
                    skip_detail="store_value_immediate_unsupported",
                    guest_operands=guest_operands,
                    host_operands=host_operands,
                )
```

This deliberately rejects all immediate store value pairings in this task. Supporting equivalent immediate stores should be a later candidate-model change.

- [ ] **Step 6: Verify**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py -q
uv run ruff format src/angr_rule_learning/extraction/memory_operands.py src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py
uv run ruff check src/angr_rule_learning/extraction/memory_operands.py src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py
```

Expected: tests and ruff pass.

- [ ] **Step 7: Commit**

```bash
git add src/angr_rule_learning/extraction/memory_operands.py src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py
git commit -m "Reject unsupported store-immediate memory surfaces"
```

---

### Task 3: Add Frame Pointer Rule Placeholders

**Files:**
- Modify: `src/angr_rule_learning/rules/registers.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Modify: `tests/test_rules_registers.py`

**Rationale:** Verified frame-relative rules currently skip with `unknown_register_class` because `rbp/ebp/bp/fp` are treated as allowed literals rather than typed placeholders. Stack pointer placeholders already exist; frame pointer placeholders should mirror that behavior and use no `_regN` suffix.

- [ ] **Step 1: Add failing frame placeholder tests**

Append to `tests/test_rules_registers.py`:

```python
from angr_rule_learning.rules.registers import frame_pointer_placeholder


def test_frame_pointer_placeholder_names() -> None:
    assert frame_pointer_placeholder("aarch64", "x29") == "fp64"
    assert frame_pointer_placeholder("aarch64", "fp") == "fp64"
    assert frame_pointer_placeholder("x86-64", "rbp") == "fp64"
    assert frame_pointer_placeholder("x86-64", "ebp") == "fp32"
    assert frame_pointer_placeholder("x86-64", "bp") == "fp16"
    assert frame_pointer_placeholder("x86-64", "rax") is None
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_rules_registers.py::test_frame_pointer_placeholder_names -q
```

Expected: import failure because `frame_pointer_placeholder` does not exist.

- [ ] **Step 3: Implement frame placeholder helper**

Modify `src/angr_rule_learning/rules/registers.py`.

Add after `_STACK_POINTER_WIDTHS`:

```python
_FRAME_POINTER_WIDTHS = {
    "aarch64": {"x29": 64, "fp": 64},
    "x86-64": {"rbp": 64, "ebp": 32, "bp": 16},
}


def frame_pointer_placeholder(arch: str, register: str) -> str | None:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    width = _FRAME_POINTER_WIDTHS.get(canonical, {}).get(reg)
    if width is None:
        return None
    return f"fp{width}"
```

Do not remove the existing allowed-literal behavior yet. The placeholder helper is used by rule generalization before generic classification.

- [ ] **Step 4: Use frame placeholders in rule mapping**

Modify `src/angr_rule_learning/rules/generalize.py`.

Update the import:

```python
    frame_pointer_placeholder,
```

In `_build_placeholder_map()`, after the stack-pointer placeholder branch and before `_classify_for_rule(...)`, add:

```python
        guest_fp = frame_pointer_placeholder(guest_arch, guest_reg)
        host_fp = frame_pointer_placeholder(host_arch, host_reg)
        if guest_fp is not None or host_fp is not None:
            if guest_fp is None or host_fp is None or guest_fp != host_fp:
                raise _RuleSkip("register_class_mismatch")
            guest_existing = mapping.get(guest_reg)
            host_existing = mapping.get(host_reg)
            existing = guest_existing or host_existing or guest_fp
            if guest_existing not in (None, existing) or host_existing not in (
                None,
                existing,
            ):
                raise _RuleSkip("unsupported_rule_shape")
            mapping[guest_reg] = existing
            mapping[host_reg] = existing
            continue
```

- [ ] **Step 5: Verify**

Run:

```bash
uv run pytest tests/test_rules_registers.py tests/test_rules_generalize.py tests/test_rules_memory_generalize.py -q
uv run ruff format src/angr_rule_learning/rules/registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_registers.py
uv run ruff check src/angr_rule_learning/rules/registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_registers.py
```

Expected: tests and ruff pass.

- [ ] **Step 6: Commit**

```bash
git add src/angr_rule_learning/rules/registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_registers.py
git commit -m "Add frame pointer rule placeholders"
```

---

### Task 4: Verify Frame-Relative Memory Address Equivalence

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Modify: `src/angr_rule_learning/verification/memory.py`
- Modify: `tests/test_extraction_memory_surfaces.py`
- Modify: `tests/test_verifier_memory.py`

**Rationale:** The most common memory verification failures are stack/frame address mismatches. AArch64 frequently uses `sp + positive_offset` or `x29 - offset`, while x86-64 uses `rbp - offset`. Equality of base registers is not the right constraint for frame-relative slots. The verifier should allow frame base witnesses to differ when the effective addresses match the same memory slot.

- [ ] **Step 1: Add extraction test for frame address pairs as address-only inputs**

Append to `tests/test_extraction_memory_surfaces.py`:

```python
def test_frame_address_pairs_are_not_shared_input_registers() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w0, [sp, #12]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rbp - 4], eax"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "sp + 12"
    assert surface.spec.bindings[0].host_addr == "rbp - 4"
    assert ("sp", "rbp") not in surface.input_registers
    assert ("w0", "eax") in surface.input_registers
```

- [ ] **Step 2: Add verifier tests for frame-relative single-slot and two-slot candidates**

Append to `tests/test_verifier_memory.py`:

```python
def test_verifier_accepts_frame_relative_store_with_different_base_offsets() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-store32",
        guest=CodeFragment("aarch64", 0x10000, "e00f00b9", 1),  # str w0, [sp, #12]
        host=CodeFragment("x86-64", 0x8048000, "897dfc", 1),  # mov [rbp-4], edi
        input_registers=(("w0", "edi"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_accepts_consistent_two_slot_frame_relative_stores() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-two-store32",
        guest=CodeFragment(
            "aarch64",
            0x10000,
            "e00f00b9e10b00b9",  # str w0,[sp,#12]; str w1,[sp,#8]
            2,
        ),
        host=CodeFragment(
            "x86-64",
            0x8048000,
            "897dfc8975f8",  # mov [rbp-4],edi; mov [rbp-8],esi
            2,
        ),
        input_registers=(("w0", "edi"), ("w1", "esi")),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(
                MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),
                MemoryBinding("mem1", "sp + 8", "rbp - 8", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 4),
                MemoryAccessExpectation("mem1", "write", 4),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass"


def test_verifier_rejects_inconsistent_frame_relative_layout() -> None:
    candidate = VerificationCandidate(
        candidate_id="frame-inconsistent-store32",
        guest=CodeFragment("aarch64", 0x10000, "e00f00b9e10b00b9", 2),
        host=CodeFragment("x86-64", 0x8048000, "897dfc8975f8", 2),
        input_registers=(("w0", "edi"), ("w1", "esi")),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4), MemorySlot("mem1", 4)),
            bindings=(
                MemoryBinding("mem0", "sp + 12", "rbp - 4", "write"),
                MemoryBinding("mem1", "sp + 8", "rbp - 12", "write"),
            ),
            accesses=(
                MemoryAccessExpectation("mem0", "write", 4),
                MemoryAccessExpectation("mem1", "write", 4),
            ),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status in {"fail", "unsupported"}
```

- [ ] **Step 3: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py::test_frame_address_pairs_are_not_shared_input_registers tests/test_verifier_memory.py::test_verifier_accepts_frame_relative_store_with_different_base_offsets tests/test_verifier_memory.py::test_verifier_accepts_consistent_two_slot_frame_relative_stores -q
```

Expected: extraction test fails because `("sp", "rbp")` is currently an input; verifier tests fail with address mismatch or unsupported conflicting bindings.

- [ ] **Step 4: Add frame pair helpers to memory surface inference**

Modify `src/angr_rule_learning/extraction/memory_surfaces.py`.

Add helpers near `_collect()`:

```python
_AARCH64_FRAME_REGS = {"sp", "wsp", "x29", "fp"}
_X86_64_FRAME_REGS = {"rsp", "esp", "sp", "rbp", "ebp", "bp"}


def _is_frame_address_pair(guest_reg: str, host_reg: str) -> bool:
    return guest_reg.lower() in _AARCH64_FRAME_REGS and host_reg.lower() in _X86_64_FRAME_REGS
```

In the address-register input loop, replace:

```python
        input_registers.extend(zip(guest_addr_regs, host_addr_regs, strict=True))
```

with:

```python
        for guest_reg, host_reg in zip(guest_addr_regs, host_addr_regs, strict=True):
            if _is_frame_address_pair(guest_reg, host_reg):
                continue
            input_registers.append((guest_reg, host_reg))
```

This keeps normal address registers as shared inputs but makes stack/frame address pairs address-only.

- [ ] **Step 5: Add frame-relative binding support to memory initializer**

Modify `src/angr_rule_learning/verification/memory.py`.

Add helpers near `_INDEX_WITNESS`:

```python
_AARCH64_FRAME_REGS = {"sp", "wsp", "x29", "fp"}
_X86_64_FRAME_REGS = {"rsp", "esp", "sp", "rbp", "ebp", "bp"}


def _is_frame_register_pair(guest_reg: str | None, host_reg: str | None) -> bool:
    if guest_reg is None or host_reg is None:
        return False
    return guest_reg.lower() in _AARCH64_FRAME_REGS and host_reg.lower() in _X86_64_FRAME_REGS
```

Refactor `_initialize_memory_registers()` so frame-register bindings are solved as a consistent relation rather than equality:

```python
def _initialize_memory_registers(
    candidate: VerificationCandidate,
    guest_state,
    host_state,
    bases: dict[str, int],
) -> None:
    guest_to_host: dict[str, str] = {}
    host_to_guest: dict[str, str] = {}
    for guest_reg, host_reg in candidate.input_registers:
        guest_to_host[guest_reg] = host_reg
        host_to_guest[host_reg] = guest_reg

    assigned: dict[str, int] = {}
    frame_offsets: dict[tuple[str, str], int] = {}

    for binding in candidate.memory.bindings:
        base = bases[binding.slot]
        guest_expr = parse_address_binding(binding.guest_addr)
        host_expr = parse_address_binding(binding.host_addr)

        _assign_index_witness(assigned, guest_expr, guest_to_host)
        _assign_index_witness(assigned, host_expr, host_to_guest)

        guest_index_val = assigned.get(guest_expr.index, 0) if guest_expr.index else 0
        host_index_val = assigned.get(host_expr.index, 0) if host_expr.index else 0

        if _is_frame_register_pair(guest_expr.base, host_expr.base):
            guest_base_val = guest_expr.solve_base_for_slot(base, guest_index_val)
            host_base_val = host_expr.solve_base_for_slot(base, host_index_val)
            offset = host_base_val - guest_base_val
            key = (guest_expr.base, host_expr.base)
            existing_offset = frame_offsets.get(key)
            if existing_offset is not None and existing_offset != offset:
                raise ValueError("unsupported address expression: inconsistent frame layout")
            frame_offsets[key] = offset
            _assign_witness(assigned, guest_expr.base, guest_base_val)
            _assign_witness(assigned, host_expr.base, host_base_val)
            continue

        guest_base_val = guest_expr.solve_base_for_slot(base, guest_index_val)
        _assign_witness(assigned, guest_expr.base, guest_base_val)
        host_pair = guest_to_host.get(guest_expr.base)
        if host_pair is not None:
            _assign_witness(assigned, host_pair, guest_base_val)

        if host_to_guest.get(host_expr.base) is None:
            host_base_val = host_expr.solve_base_for_slot(base, host_index_val)
            _assign_witness(assigned, host_expr.base, host_base_val)

    for register, value in assigned.items():
        if register in guest_state.arch.registers:
            write_reg(guest_state, register, claripy.BVV(value, guest_state.arch.bits))
        host_pair = guest_to_host.get(register)
        if host_pair is not None:
            write_reg(host_state, host_pair, claripy.BVV(value, host_state.arch.bits))
        elif register in host_state.arch.registers:
            write_reg(host_state, register, claripy.BVV(value, host_state.arch.bits))
```

If this refactor conflicts with Task 1 tests, preserve existing behavior for non-frame pairs first. The important invariant: explicit `input_registers=(("x1", "rcx"),)` must still enforce equality and still reject scale mismatches.

- [ ] **Step 6: Verify focused tests**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py::test_frame_address_pairs_are_not_shared_input_registers -q
uv run pytest tests/test_verifier_memory.py::test_verifier_accepts_frame_relative_store_with_different_base_offsets tests/test_verifier_memory.py::test_verifier_accepts_consistent_two_slot_frame_relative_stores tests/test_verifier_memory.py::test_verifier_rejects_inconsistent_frame_relative_layout tests/test_verifier_memory.py::test_verifier_rejects_binding_scale_mismatch_under_shared_inputs -q
```

Expected: all pass. The existing scale-mismatch test must still fail the candidate; do not regress it.

- [ ] **Step 7: Run broader verification tests**

Run:

```bash
uv run pytest tests/test_verifier_memory.py tests/test_extraction_memory_surfaces.py tests/test_extraction_pipeline.py -q
uv run ruff format src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/verification/memory.py tests/test_extraction_memory_surfaces.py tests/test_verifier_memory.py
uv run ruff check src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/verification/memory.py tests/test_extraction_memory_surfaces.py tests/test_verifier_memory.py
```

Expected: tests and ruff pass.

- [ ] **Step 8: Commit**

```bash
git add src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/verification/memory.py tests/test_extraction_memory_surfaces.py tests/test_verifier_memory.py
git commit -m "Support frame-relative memory address verification"
```

---

### Task 5: Generalize Frame-Relative Memory Rules

**Files:**
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Modify: `tests/test_rules_memory_generalize.py`

**Rationale:** After Task 4, frame address registers may be absent from `candidate.input_registers`, but rule text still contains `x29`, `fp`, `sp`, or `rbp`. Rule generalization must derive placeholders from memory bindings as well as explicit input/output register pairs.

- [ ] **Step 1: Add failing frame memory generalization test**

Append to `tests/test_rules_memory_generalize.py`:

```python
def test_generalizes_frame_relative_memory_registers_from_bindings() -> None:
    window = _window_pair(
        guest=(
            _inst("aarch64", 0x1000, "stur", "w0, [x29, #-4]"),
        ),
        host=(
            _inst("x86-64", 0x2000, "mov", "dword ptr [rbp - 4], eax"),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="frame-memory-store",
        guest=CodeFragment("aarch64", 0x1000, "a8c31fb8", 1),
        host=CodeFragment("x86-64", 0x2000, "8945fc", 1),
        input_registers=(("w0", "eax"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x29 - 4", "rbp - 4", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )
    report = VerificationReport(
        candidate_id="frame-memory-store",
        status="pass",
        checks=(CheckResult("memory", "pass", "mem0", "mem0"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, window, candidate, report)

    assert rule is not None
    assert rule.guest_lines == ("stur i32_reg1, [fp64, #-imm1]",)
    assert rule.host_lines == ("mov dword ptr [fp64 - imm1], i32_reg1",)
```

If `_window_pair`, `_inst`, or imports have different names in the existing file, adapt to the local helpers already in `tests/test_rules_memory_generalize.py`.

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
uv run pytest tests/test_rules_memory_generalize.py::test_generalizes_frame_relative_memory_registers_from_bindings -q
```

Expected: failure with `unmapped_register_surface` or `unknown_register_class`.

- [ ] **Step 3: Add memory binding register pairs to placeholder mapping**

Modify `src/angr_rule_learning/rules/generalize.py`.

Import:

```python
from angr_rule_learning.verification.addressing import parse_address_binding
```

Add helper near `_build_placeholder_map()`:

```python
def _memory_binding_register_pairs(
    candidate: VerificationCandidate,
) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for binding in candidate.memory.bindings:
        try:
            guest_expr = parse_address_binding(binding.guest_addr)
            host_expr = parse_address_binding(binding.host_addr)
        except ValueError as exc:
            raise _RuleSkip("unsupported_rule_shape") from exc
        guest_regs = guest_expr.registers()
        host_regs = host_expr.registers()
        if len(guest_regs) != len(host_regs):
            raise _RuleSkip("unsupported_rule_shape")
        pairs.extend(zip(guest_regs, host_regs, strict=True))
    return tuple(pairs)
```

Change the loop source in `_build_placeholder_map()` from:

```python
    for guest_reg, host_reg in candidate.output_registers + candidate.input_registers:
```

to:

```python
    register_pairs = (
        candidate.output_registers
        + candidate.input_registers
        + _memory_binding_register_pairs(candidate)
    )
    for guest_reg, host_reg in register_pairs:
```

The existing stack/frame placeholder logic should handle duplicated pairs safely.

- [ ] **Step 4: Verify**

Run:

```bash
uv run pytest tests/test_rules_memory_generalize.py tests/test_rules_generalize.py tests/test_rules_registers.py -q
uv run ruff format src/angr_rule_learning/rules/generalize.py tests/test_rules_memory_generalize.py
uv run ruff check src/angr_rule_learning/rules/generalize.py tests/test_rules_memory_generalize.py
```

Expected: tests and ruff pass.

- [ ] **Step 5: Commit**

```bash
git add src/angr_rule_learning/rules/generalize.py tests/test_rules_memory_generalize.py
git commit -m "Generalize frame-relative memory rules"
```

---

### Task 6: Support Sign-Extension Load Memory Operands

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_operands.py`
- Modify: `tests/test_extraction_memory_operands.py`
- Modify: `tests/test_extraction_memory_surfaces.py`
- Modify: `docs/architecture.md`

**Rationale:** `indexed_memory_int.c` shows high-frequency unparsed pairs `aarch64:ldrsw` and `x86-64:movsxd`. These are memory reads with sign extension. The verifier compares output register expressions after execution, so the memory surface only needs to model the read address and read width correctly.

- [ ] **Step 1: Add memory operand parser tests**

Append to `tests/test_extraction_memory_operands.py`:

```python
def test_parses_aarch64_ldrsw_as_32_bit_memory_read() -> None:
    operands = extract_memory_operands(
        _inst("aarch64", "ldrsw", "x0, [x1, x2, lsl #2]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "x0"
    assert operands[0].address == AddressExpr(base="x1", index="x2", scale=4)


def test_parses_x86_movsxd_memory_source_as_32_bit_memory_read() -> None:
    operands = extract_memory_operands(
        _inst("x86-64", "movsxd", "rax, dword ptr [rcx + rdx*4]")
    )

    assert len(operands) == 1
    assert operands[0].kind == "read"
    assert operands[0].width == 4
    assert operands[0].value_register == "rax"
    assert operands[0].address == AddressExpr(base="rcx", index="rdx", scale=4)
```

- [ ] **Step 2: Add memory surface pairing test**

Append to `tests/test_extraction_memory_surfaces.py`:

```python
def test_infers_sign_extension_load_surface() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldrsw", "x0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "movsxd", "rax, dword ptr [rcx + rdx*4]"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.accesses[0].kind == "read"
    assert surface.spec.accesses[0].width == 4
    assert surface.input_registers == (("x1", "rcx"), ("x2", "rdx"))
```

- [ ] **Step 3: Run tests and verify failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py::test_parses_aarch64_ldrsw_as_32_bit_memory_read tests/test_extraction_memory_operands.py::test_parses_x86_movsxd_memory_source_as_32_bit_memory_read tests/test_extraction_memory_surfaces.py::test_infers_sign_extension_load_surface -q
```

Expected: parser tests fail because `ldrsw` and `movsxd` are currently unparsed.

- [ ] **Step 4: Implement `ldrsw` parser support**

Modify `src/angr_rule_learning/extraction/memory_operands.py`.

Change:

```python
    if mnemonic not in {"ldr", "ldur", "str", "stur"}:
```

to:

```python
    if mnemonic not in {"ldr", "ldur", "ldrsw", "str", "stur"}:
```

When computing `width`, override `ldrsw` to read 4 bytes:

```python
        width = 4 if mnemonic == "ldrsw" else _aarch64_register_width(value)
```

Apply that same override in both displacement and indexed AArch64 parsing branches.

- [ ] **Step 5: Implement `movsxd` parser support**

Modify `_extract_x86_64()` in `src/angr_rule_learning/extraction/memory_operands.py`.

Change:

```python
    if mnemonic != "mov":
        return ()
```

to:

```python
    if mnemonic not in {"mov", "movsxd"}:
        return ()
```

After `left, right = parts`, reject memory destination for `movsxd`:

```python
    if mnemonic == "movsxd" and left_mem is not None:
        return ()
```

For the read-side width:

```python
    width = 4 if mnemonic == "movsxd" else _x86_width(op_str, value_register)
```

Do not support `movsxd` without a memory source in this task.

- [ ] **Step 6: Verify**

Run:

```bash
uv run pytest tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py tests/test_extraction_pipeline.py -q
uv run ruff format src/angr_rule_learning/extraction/memory_operands.py tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py
uv run ruff check src/angr_rule_learning/extraction/memory_operands.py tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py
```

Expected: tests and ruff pass.

- [ ] **Step 7: Commit**

```bash
git add src/angr_rule_learning/extraction/memory_operands.py tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py docs/architecture.md
git commit -m "Support sign-extension memory load surfaces"
```

---

### Task 7: End-To-End Regression And Documentation

**Files:**
- Modify: `docs/architecture.md`
- Optionally modify: `scripts/run_all_tests.sh` only if the printed summary needs stable fields; do not make behavior changes.

- [ ] **Step 1: Update architecture docs**

In `docs/architecture.md`, under memory surface inference, add a short paragraph:

```markdown
Frame-relative stack memory is treated specially. When AArch64 stack/frame
registers (`sp`, `x29`, `fp`) align with x86-64 stack/frame registers (`rsp`,
`rbp` and narrower aliases), extraction does not model the base registers as
equal input values. Instead, memory bindings carry the effective address
expressions and the verifier assigns frame base witnesses that make consistent
slots alias across ISAs. This preserves normal equality semantics for ordinary
address registers while allowing common `sp + offset` versus `rbp - offset`
stack-slot rules to verify.
```

Also add:

```markdown
Still unsupported memory forms include full prologue/epilogue modelling
(`push/pop` versus `stp/ldp`) and x86 read-modify-write arithmetic memory
operands. These remain separate planned extensions.
```

- [ ] **Step 2: Run full checks**

Run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
```

Expected: all pass.

- [ ] **Step 3: Run smoke pipelines**

Run:

```bash
./scripts/run_all_tests.sh samples/sources/smoke_int.c /private/tmp/arl-yield-fixes-smoke/work /private/tmp/arl-yield-fixes-smoke/out 0
./scripts/run_all_tests.sh samples/sources/memory_int.c /private/tmp/arl-yield-fixes-memory/work /private/tmp/arl-yield-fixes-memory/out 0
./scripts/run_all_tests.sh samples/sources/indexed_memory_int.c /private/tmp/arl-yield-fixes-indexed/work /private/tmp/arl-yield-fixes-indexed/out 0
```

Expected: all commands exit 0. If sandbox blocks `uv` cache access, rerun the same commands with approval outside the sandbox.

- [ ] **Step 4: Generate comparison summary**

Run:

```bash
uv run python - <<'PY'
import json
from pathlib import Path

baseline = {
    "smoke": {"windows_emitted": 252, "windows_verified_pass": 28, "rules_emitted": 9, "errors": 3},
    "memory": {"windows_emitted": 75, "windows_verified_pass": 12, "rules_emitted": 3, "errors": 8},
    "indexed": {"windows_emitted": 64, "windows_verified_pass": 9, "rules_emitted": 3, "errors": 0},
}
paths = {
    "smoke": Path("/private/tmp/arl-yield-fixes-smoke/out"),
    "memory": Path("/private/tmp/arl-yield-fixes-memory/out"),
    "indexed": Path("/private/tmp/arl-yield-fixes-indexed/out"),
}
for name, path in paths.items():
    diag = json.load(open(path / "diagnostics.json"))
    rules = json.load(open(path / "rules_diagnostics.json"))
    summary_path = path / "verify_summary.json"
    if not summary_path.exists():
        import subprocess
        subprocess.run(
            [
                "uv",
                "run",
                "angr-rule-learning",
                "verify",
                str(path / "candidates.jsonl"),
                "--output",
                str(path / "reports.jsonl"),
                "--summary",
                str(summary_path),
            ],
            check=True,
        )
    verify = json.load(open(summary_path))
    current = {
        "windows_emitted": diag["windows_emitted"],
        "windows_verified_pass": diag["windows_verified_pass"],
        "rules_emitted": rules["rules_emitted"],
        "errors": verify["statuses"].get("error", 0),
    }
    print(f"\n{name}")
    print("baseline", baseline[name])
    print("current ", current)
    print("verify reasons", verify["top_reasons"])
PY
```

Expected:

- `errors` should be `0` for `smoke` and `memory`, or every remaining error must be explained in the final report with candidate IDs.
- `windows_verified_pass` should not decrease for any sample.
- `rules_emitted` should not decrease for any sample.
- `indexed` should show reduced `unparsed_memory_access` for `ldrsw/movsxd`.

- [ ] **Step 5: Commit docs and any final smoke-script-only adjustments**

```bash
git add docs/architecture.md scripts/run_all_tests.sh
git diff --cached --quiet || git commit -m "Document current yield fix boundaries"
```

If there are no doc/script changes after previous commits, skip this commit.

- [ ] **Step 6: Final report**

Report:

- commit stack;
- exact test commands and outputs;
- smoke comparison table for `smoke_int.c`, `memory_int.c`, `indexed_memory_int.c`;
- remaining top skip patterns from `skip_patterns.json`;
- remaining verifier `error` reports, if any;
- whether rule count increased, stayed flat, or decreased, with reasons.

---

## Self-Review

- Spec coverage: The plan covers the identified internal errors, store-immediate bad candidates, frame-relative memory mismatch, frame rule placeholders, and `ldrsw/movsxd` high-frequency unparsed forms.
- Scope control: `push/pop`, `stp/ldp`, and x86 read-modify-write memory arithmetic are explicitly excluded because they require larger semantic modelling.
- Placeholder scan: No unresolved marker words or vague implementation-only steps remain.
- Type consistency: New `MemoryOperand.value_register` becomes `str | None`; all planned checks that read it first reject `None` before using it as a register.
