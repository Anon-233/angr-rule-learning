# Host Semantic Partial Register Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit sound Host-side semantic partial-register rules such as `movzx i32_reg1, lo8(i32_reg2)` and `sete lo8(i32_reg1)` for verified stable kernels.

**Architecture:** Keep verifier input as native Guest/Host fragments. Extend only rule AST/generalization with Host-side semantic operands, backed by architecture capability helpers for sub-register write effects. Guest rule text remains native except existing source-physical views like `lo8(guest.rcx)`.

**Tech Stack:** Python 3.14, pytest, ruff, angr/claripy, existing `angr_rule_learning.rules` and `angr_rule_learning.arch` modules.

---

### Task 1: Add Semantic View AST Nodes

**Files:**
- Modify: `src/angr_rule_learning/rules/ast.py`
- Modify: `src/angr_rule_learning/rules/_fingerprint.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Write failing AST tests**

Add tests under `TestRegViewOpRoundtrip`:

```python
def test_parse_low_bit_slice_roundtrip():
    inst = Instruction.from_text("movzx i32_reg1, lo8(i32_reg2)")
    assert inst.to_text() == "movzx i32_reg1, lo8(i32_reg2)"

def test_parse_nested_zero_extension_roundtrip():
    inst = Instruction.from_text("mov i32_reg1, zext32(lo8(i32_reg2))")
    assert inst.to_text() == "mov i32_reg1, zext32(lo8(i32_reg2))"

def test_slice_width_affects_alpha_equivalence():
    from angr_rule_learning.rules.ast import Rule, rule_alpha_equal

    guest = (Instruction.from_text("and i32_reg1, i32_reg2, #0xff"),)
    a = Rule(1, "a", guest, (Instruction.from_text("movzx i32_reg1, lo8(i32_reg2)"),))
    b = Rule(2, "b", guest, (Instruction.from_text("movzx i32_reg1, lo16(i32_reg2)"),))
    assert not rule_alpha_equal(a, b)
```

- [ ] **Step 2: Run focused tests and confirm failure**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -k 'low_bit_slice or zero_extension or slice_width' -q
```

Expected: failures because `lo8(i32_reg2)` and `zext32(...)` parse as `LitOp`.

- [ ] **Step 3: Implement AST nodes**

Add frozen dataclasses:

```python
@dataclass(frozen=True)
class BitSliceOp:
    base: Operand
    bits: int

    def to_text(self) -> str:
        return f"lo{self.bits}({self.base.to_text()})"

@dataclass(frozen=True)
class ExtOp:
    kind: str
    bits: int
    value: Operand

    def to_text(self) -> str:
        return f"{self.kind}{self.bits}({self.value.to_text()})"
```

Update `Operand`, `Instruction._parse_operand()`, `_walk_rule()`, and `parse_placeholder()` as needed. `loN(guest.rcx)` must still parse as `GuestRegViewOp`; parse physical Guest views before generic `loN(...)`.

- [ ] **Step 4: Implement fingerprint support**

In `_fingerprint.py`, add tags for `BitSliceOp` and `ExtOp`. Fingerprint the nested operand recursively and include width/kind so `lo8(x)`, `lo16(x)`, `zext32(x)`, and `sext32(x)` are distinct.

- [ ] **Step 5: Verify and commit**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -k 'RegViewOpRoundtrip or low_bit_slice or zero_extension or slice_width' -q
uv run ruff check
```

Commit:

```bash
git add src/angr_rule_learning/rules/ast.py src/angr_rule_learning/rules/_fingerprint.py tests/test_rules_generalize.py
git commit -m "feat: add semantic bit-slice rule operands"
```

### Task 2: Add Architecture Write-Effect Helpers

**Files:**
- Modify: `src/angr_rule_learning/arch/registers.py`
- Test: `tests/test_arch_registers.py` or nearest existing arch test file

- [ ] **Step 1: Write failing capability tests**

Add tests for:

```python
assert register_write_effect("x86-64", "al") == RegisterWriteEffect("partial", 8, "rax")
assert register_write_effect("x86-64", "eax") == RegisterWriteEffect("zero_extend", 32, "rax")
assert register_write_effect("x86-64", "rax") == RegisterWriteEffect("full", 64, "rax")
assert register_write_effect("aarch64", "w0") == RegisterWriteEffect("zero_extend", 32, "x0")
assert register_write_effect("aarch64", "x0") == RegisterWriteEffect("full", 64, "x0")
```

- [ ] **Step 2: Implement helper**

Add:

```python
@dataclass(frozen=True)
class RegisterWriteEffect:
    kind: Literal["partial", "zero_extend", "full"]
    written_bits: int
    family: str
```

Implement `register_write_effect(arch, register) -> RegisterWriteEffect | None` using existing `register_family()` and `register_bit_range()`. Keep high-byte x86 registers as `partial` but the rule generalizer will reject them because they are not low slices.

- [ ] **Step 3: Verify and commit**

Run:

```bash
uv run pytest tests/test_arch_registers.py -q
uv run ruff check
```

Commit:

```bash
git add src/angr_rule_learning/arch/registers.py tests/test_arch_registers.py
git commit -m "feat: describe architecture register write effects"
```

### Task 3: Rewrite Host Partial Register Reads

**Files:**
- Create: `src/angr_rule_learning/rules/partial_registers.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Write failing read-view test**

Add a generalizer test:

```python
def test_host_movzx_source_uses_low_bit_slice():
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "and", "w0, w0, #0xff", write_registers=("w0",), read_registers=("w0",)),),
        (_inst("x86-64", 0x2000, "movzx", "eax, dil", write_registers=("eax",), read_registers=("dil",)),),
    )
    candidate = VerificationCandidate(
        candidate_id="movzx-read-view",
        guest=CodeFragment("aarch64", 0x1000, "00000000", 1),
        host=CodeFragment("x86-64", 0x2000, "0000", 1),
        input_registers=(("w0", "edi"),),
        output_registers=(("w0", "eax"),),
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, pair, candidate, _passing_report(candidate.candidate_id))
    assert rule is not None
    assert rule.host_lines == ("movzx i32_reg1, lo8(i32_reg2)",)
```

- [ ] **Step 2: Implement `resolve_partial_register_views()`**

The new module should expose:

```python
@dataclass(frozen=True)
class PartialRegisterReplacement:
    physical_register: str
    replacement_text: str
    reason: str

def resolve_partial_register_views(arch, instruction, mapping, *, side) -> list[PartialRegisterReplacement]:
    ...
```

First phase rules:
- Only apply when `side == "host"`.
- Only low-bit slices are allowed: `register_bit_range(arch, token) == (0, N-1)`.
- Only strict sub-registers are rewritten: mapped register range must be wider than token range.
- Read views are allowed for `movzx` source operands.

- [ ] **Step 3: Wire into generalizer**

In `_generalize_instructions_with_roles()`, run partial replacements after regular mapping and before `resolve_register_views()`. Re-parse to AST as the existing code does.

- [ ] **Step 4: Verify and commit**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -k 'movzx_source_uses_low_bit_slice' -q
uv run ruff check
```

Commit:

```bash
git add src/angr_rule_learning/rules/partial_registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "feat: emit host partial-register read views"
```

### Task 4: Rewrite Safe Host Partial Register Writes

**Files:**
- Modify: `src/angr_rule_learning/rules/partial_registers.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Write failing safe-write test**

Add:

```python
def test_host_setcc_destination_uses_low_bit_slice_after_full_def():
    pair = _window_pair(
        (
            _inst("aarch64", 0x1000, "cmp", "w0, w1", read_registers=("w0", "w1")),
            _inst("aarch64", 0x1004, "cset", "w0, eq", write_registers=("w0",)),
        ),
        (
            _inst("x86-64", 0x2000, "xor", "eax, eax", write_registers=("eax",), read_registers=("eax",)),
            _inst("x86-64", 0x2002, "cmp", "edi, esi", read_registers=("edi", "esi")),
            _inst("x86-64", 0x2004, "sete", "al", write_registers=("al",)),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="setcc-write-view",
        guest=CodeFragment("aarch64", 0x1000, "0000000000000000", 2),
        host=CodeFragment("x86-64", 0x2000, "000000", 3),
        input_registers=(("w0", "edi"), ("w1", "esi")),
        output_registers=(("w0", "eax"),),
    )
    rule = RuleGeneralizer(RuleDiagnostics()).generate(1, pair, candidate, _passing_report(candidate.candidate_id))
    assert rule is not None
    assert "sete lo8(i32_reg1)" in rule.host_lines
```

- [ ] **Step 2: Write failing unsafe-write rejection test**

Use the same pair but remove the `xor eax, eax` instruction. Expected:

```python
assert rule is None
assert diagnostics.skip_reasons.get("unsafe_partial_register_write", 0) == 1
```

- [ ] **Step 3: Implement full-output coverage check**

For a Host partial-write destination:
- Find the semantic output placeholder for the physical family.
- Search earlier Host instructions in the same window for a write to a register in that family whose write effect is `full` or `zero_extend` and whose mapped placeholder is the same output placeholder.
- If found, rewrite the partial destination to `loN(output_placeholder)`.
- If missing, raise `_RuleSkip("unsafe_partial_register_write")`.

- [ ] **Step 4: Verify and commit**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -k 'setcc_destination_uses_low_bit_slice or unsafe_partial_register_write' -q
uv run ruff check
```

Commit:

```bash
git add src/angr_rule_learning/rules/partial_registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "feat: emit safe host partial-register write views"
```

### Task 5: Add Stable Kernel Pipeline Regressions

**Files:**
- Modify: `tests/test_kernel_pipeline.py`
- Optionally modify: `docs/rule-format.md`, `docs/architecture.md`

- [ ] **Step 1: Add stable-kernel assertions**

Add a focused test that runs the stable suite and asserts:

```python
required = {
    "kernel_and_const_i32",
    "kernel_and_const_i64",
    "kernel_icmp_eq_i32",
    "kernel_icmp_slt_i32",
}
statuses = {record.kernel_id: record.status for record in result.records}
assert {kid: statuses[kid] for kid in required} == {kid: "rule_emitted" for kid in required}
assert "movzx" in rules_text
assert "lo8(i32_reg" in rules_text or "lo16(i64_reg" in rules_text
assert "sete lo8(i32_reg" in rules_text or "setl lo8(i32_reg" in rules_text
assert result.diagnostics["verifier_internal_error"] == 0 if "verifier_internal_error" in result.diagnostics else True
```

- [ ] **Step 2: Update docs**

Document:
- `loN(iM_regK)` Host semantic operand.
- `zextN(...)` and `sextN(...)` reserved/AST-supported forms.
- Unsafe partial writes are rejected unless full-width output coverage is proven.

- [ ] **Step 3: Run full verification**

Run:

```bash
uv run ruff format
uv run ruff check
uv run pytest -q
./scripts/run_all_tests.sh ./runs/ir-based/work ./runs/ir-based
./scripts/run_all_tests.sh ./runs/ir-based-reverse/work ./runs/ir-based-reverse 1 x86-64 aarch64
```

Expected:
- `ruff check`: pass.
- `pytest`: pass.
- Stable emitted rules increase from the current `66/84` default direction by at least the recovered partial-register families.

- [ ] **Step 4: Commit**

```bash
git add tests/test_kernel_pipeline.py docs/rule-format.md docs/architecture.md
git commit -m "test: require stable partial-register rules"
```

## Self-Review

- Spec coverage: all goals in `2026-07-01-host-semantic-partial-register-design.md` map to Tasks 1-5.
- Scope: magic-constant division and general immediate inference remain out of scope.
- Type consistency: `BitSliceOp`, `ExtOp`, `RegisterWriteEffect`, and `PartialRegisterReplacement` are introduced before use.
- Placeholder scan: no TBD/TODO placeholders are present.
