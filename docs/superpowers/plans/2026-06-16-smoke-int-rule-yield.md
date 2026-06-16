# Smoke Int Rule Yield Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Increase rules emitted from the existing `samples/sources/smoke_int.c` without changing that source file, the default optimization level, or verifier strictness.

**Architecture:** Keep semantic verification unchanged. Improve rule yield by fixing extraction surface inputs for memory writes, adding opt-in detailed rule skip diagnostics, allowing guest-anchored semantic register coalescing in the rule generalizer, and treating stack pointers as special rule placeholders such as `sp64`.

**Tech Stack:** Python, pytest, ruff, angr/claripy, existing `ExtractionPipeline`, `RuleGeneralizer`, and `MemorySurface` modules.

---

## Current Baseline

Use the current `runs/all_test` O0 output as the baseline:

```text
windows_emitted: 269
windows_verified_pass: 28
rules_emitted: 9
rules_skipped: 19
skip reasons: duplicate_rule=7, register_class_mismatch=3, unknown_register_class=6, unmapped_register_surface=1, unsupported_rule_shape=2
```

Do not modify `samples/sources/smoke_int.c` in this plan.

Before starting implementation, run:

```bash
git status --short
```

Expected: no unrelated changes except this plan if it has not been committed by the caller.

---

## File Structure

Modify:

- `src/angr_rule_learning/rules/generalize.py`
  - Add opt-in detailed skip records to `RuleDiagnostics`.
  - Add guest-anchored semantic register coalescing in `_build_placeholder_map`.
- `src/angr_rule_learning/rules/registers.py`
  - Add stack-pointer classification helpers and `sp64` / `sp32` placeholder support.
- `src/angr_rule_learning/rules/writer.py`
  - Let diagnostics writing choose aggregate-only or detailed JSON.
- `src/angr_rule_learning/extraction/pipeline.py`
  - Thread a new optional detailed rules diagnostics output path.
- `src/angr_rule_learning/cli.py`
  - Add the new CLI switch for detailed rules diagnostics.
- `src/angr_rule_learning/extraction/memory_surfaces.py`
  - Stop treating internally produced store value registers as external inputs.
- `docs/rule-generalization.md`
  - Document detailed diagnostics, semantic coalescing, and `sp64`.

Modify tests:

- `tests/test_rules_generalize.py`
- `tests/test_rules_registers.py`
- `tests/test_rules_writer.py`
- `tests/test_extraction_memory_surfaces.py`
- `tests/test_extraction_pipeline.py`
- `tests/test_batch_cli.py`

---

## Task 1: Add Opt-In Detailed Rule Skip Diagnostics

**Files:**

- Modify: `src/angr_rule_learning/rules/generalize.py`
- Modify: `src/angr_rule_learning/rules/writer.py`
- Modify: `src/angr_rule_learning/extraction/pipeline.py`
- Modify: `src/angr_rule_learning/cli.py`
- Test: `tests/test_rules_generalize.py`
- Test: `tests/test_rules_writer.py`
- Test: `tests/test_extraction_pipeline.py`
- Test: `tests/test_batch_cli.py`

- [ ] **Step 1: Write failing unit test for default aggregate-only diagnostics**

Add to `tests/test_rules_generalize.py`:

```python
def test_rule_diagnostics_omits_details_by_default() -> None:
    diagnostics = RuleDiagnostics()
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "x8, x0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("x0", "edi"),), outputs=(("x8", "eax"),))

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    payload = diagnostics.to_json()
    assert payload["skip_reasons"] == {"register_class_mismatch": 1}
    assert "skipped_rules" not in payload
```

- [ ] **Step 2: Write failing unit test for opt-in detailed skip records**

Add to `tests/test_rules_generalize.py`:

```python
def test_rule_diagnostics_records_detailed_skip_when_enabled() -> None:
    diagnostics = RuleDiagnostics(collect_details=True)
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "mov", "x8, x0"),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )
    candidate = _candidate(inputs=(("x0", "edi"),), outputs=(("x8", "eax"),))

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is None
    payload = diagnostics.to_json(include_details=True)
    assert payload["skip_reasons"] == {"register_class_mismatch": 1}
    assert payload["skipped_rules"] == [
        {
            "candidate_id": candidate.candidate_id,
            "reason": "register_class_mismatch",
            "guest_lines": ["mov x8, x0"],
            "host_lines": ["mov eax, edi"],
            "input_registers": [["x0", "edi"]],
            "output_registers": [["x8", "eax"]],
            "memory_bindings": [],
        }
    ]
```

- [ ] **Step 3: Verify these tests fail**

Run:

```bash
uv run pytest tests/test_rules_generalize.py::test_rule_diagnostics_omits_details_by_default tests/test_rules_generalize.py::test_rule_diagnostics_records_detailed_skip_when_enabled -q
```

Expected: fail because `RuleDiagnostics` does not accept `collect_details` and `to_json` does not support details.

- [ ] **Step 4: Implement diagnostics detail model**

In `src/angr_rule_learning/rules/generalize.py`, add a dataclass near `GeneratedRule`:

```python
@dataclass(frozen=True)
class RuleSkipDetail:
    candidate_id: str
    reason: str
    guest_lines: tuple[str, ...]
    host_lines: tuple[str, ...]
    input_registers: tuple[tuple[str, str], ...]
    output_registers: tuple[tuple[str, str], ...]
    memory_bindings: tuple[dict[str, str], ...]

    def to_json(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "reason": self.reason,
            "guest_lines": list(self.guest_lines),
            "host_lines": list(self.host_lines),
            "input_registers": [list(pair) for pair in self.input_registers],
            "output_registers": [list(pair) for pair in self.output_registers],
            "memory_bindings": list(self.memory_bindings),
        }
```

Change `RuleDiagnostics` to:

```python
@dataclass
class RuleDiagnostics:
    collect_details: bool = False
    rules_considered: int = 0
    rules_emitted: int = 0
    skip_reasons: Counter[str] = field(default_factory=Counter)
    skipped_rules: list[RuleSkipDetail] = field(default_factory=list)

    @property
    def rules_skipped(self) -> int:
        return sum(self.skip_reasons.values())

    def record_considered(self) -> None:
        self.rules_considered += 1

    def record_emitted(self) -> None:
        self.rules_emitted += 1

    def record_skipped(
        self,
        reason: str,
        detail: RuleSkipDetail | None = None,
    ) -> None:
        self.skip_reasons.update((reason,))
        if self.collect_details and detail is not None:
            self.skipped_rules.append(detail)

    def to_json(self, *, include_details: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "rules_considered": self.rules_considered,
            "rules_emitted": self.rules_emitted,
            "rules_skipped": self.rules_skipped,
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
        }
        if include_details:
            payload["skipped_rules"] = [
                detail.to_json() for detail in self.skipped_rules
            ]
        return payload
```

In `RuleGeneralizer.generate`, compute `guest_lines` and `host_lines` before the `try`, and on `_RuleSkip` call:

```python
detail = RuleSkipDetail(
    candidate_id=candidate.candidate_id,
    reason=exc.reason,
    guest_lines=guest_lines,
    host_lines=host_lines,
    input_registers=candidate.input_registers,
    output_registers=candidate.output_registers,
    memory_bindings=tuple(
        {
            "slot": binding.slot,
            "guest_addr": binding.guest_addr,
            "host_addr": binding.host_addr,
            "access": binding.access,
        }
        for binding in candidate.memory.bindings
    ),
)
self.diagnostics.record_skipped(exc.reason, detail)
```

For duplicate rules, call `record_skipped("duplicate_rule", detail)` with the same shape and generalized lines if they are available.

- [ ] **Step 5: Add writer support for aggregate and detailed modes**

In `src/angr_rule_learning/rules/writer.py`, change:

```python
def write_rule_diagnostics_json(
    path: Path,
    diagnostics: RuleDiagnostics,
    *,
    include_details: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            diagnostics.to_json(include_details=include_details),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
```

Add to `tests/test_rules_writer.py` a test that writes with `include_details=True` and asserts `skipped_rules` is present. Use `RuleDiagnostics(collect_details=True)` and `record_skipped` with a manually constructed `RuleSkipDetail`.

- [ ] **Step 6: Add CLI and pipeline switch**

Use this CLI name:

```text
--rules-debug-diagnostics PATH
```

Rationale: `--rules-diagnostics` remains cheap aggregate diagnostics. `--rules-debug-diagnostics` explicitly opts into potentially large per-skipped-candidate details.

In `ExtractionPipeline.run`, add:

```python
rules_debug_diagnostics_output: Path | None = None,
```

Set:

```python
rule_generation_requested = (
    rules_output is not None
    or rules_diagnostics_output is not None
    or rules_debug_diagnostics_output is not None
)
rule_diagnostics = RuleDiagnostics(
    collect_details=rules_debug_diagnostics_output is not None
)
```

Write outputs:

```python
if rules_diagnostics_output is not None:
    write_rule_diagnostics_json(
        rules_diagnostics_output,
        rule_diagnostics,
        include_details=False,
    )
if rules_debug_diagnostics_output is not None:
    write_rule_diagnostics_json(
        rules_debug_diagnostics_output,
        rule_diagnostics,
        include_details=True,
    )
```

In `src/angr_rule_learning/cli.py`, add:

```python
extract_parser.add_argument("--rules-debug-diagnostics", type=Path)
```

Update the `--verify` guard to include `args.rules_debug_diagnostics`.

- [ ] **Step 7: Add CLI/pipeline tests**

Add to `tests/test_batch_cli.py`:

```python
def test_extract_cli_rejects_rules_debug_diagnostics_without_verify(tmp_path) -> None:
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
                "--rules-debug-diagnostics",
                str(tmp_path / "rules_debug_diagnostics.json"),
            ]
        )

    assert excinfo.value.code == 2
```

Add to `tests/test_extraction_pipeline.py` a focused fake verifier test that passes `rules_debug_diagnostics_output=...` and forces one rule skip. Assert the debug JSON contains `skipped_rules`, while `rules_diagnostics_output` does not.

- [ ] **Step 8: Run tests and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules/generalize.py src/angr_rule_learning/rules/writer.py src/angr_rule_learning/extraction/pipeline.py src/angr_rule_learning/cli.py tests/test_rules_generalize.py tests/test_rules_writer.py tests/test_extraction_pipeline.py tests/test_batch_cli.py
uv run ruff check
uv run pytest tests/test_rules_generalize.py tests/test_rules_writer.py tests/test_extraction_pipeline.py tests/test_batch_cli.py -q
```

Expected: all pass.

Commit:

```bash
git add src/angr_rule_learning/rules/generalize.py src/angr_rule_learning/rules/writer.py src/angr_rule_learning/extraction/pipeline.py src/angr_rule_learning/cli.py tests/test_rules_generalize.py tests/test_rules_writer.py tests/test_extraction_pipeline.py tests/test_batch_cli.py
git commit -m "Add opt-in detailed rule diagnostics"
```

---

## Task 2: Fix Store Value External Input Inference

**Files:**

- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Test: `tests/test_extraction_memory_surfaces.py`

- [ ] **Step 1: Write failing test for internally produced store values**

Add to `tests/test_extraction_memory_surfaces.py`:

```python
def test_does_not_treat_internally_defined_store_value_as_input() -> None:
    surface = infer_memory_surface(
        _pair(
            (
                ExtractedInstruction(
                    arch="aarch64",
                    address=0x1000,
                    size=4,
                    code_bytes=b"\x01\x02\x03\x04",
                    mnemonic="add",
                    op_str="w8, w1, #1",
                    function="f",
                    source=None,
                    read_registers=("w1",),
                    write_registers=("w8",),
                ),
                ExtractedInstruction(
                    arch="aarch64",
                    address=0x1004,
                    size=4,
                    code_bytes=b"\x01\x02\x03\x04",
                    mnemonic="str",
                    op_str="w8, [x9]",
                    function="f",
                    source=None,
                    read_registers=("w8", "x9"),
                    write_registers=(),
                ),
            ),
            (
                ExtractedInstruction(
                    arch="x86-64",
                    address=0x2000,
                    size=3,
                    code_bytes=b"\x01\x02\x03",
                    mnemonic="lea",
                    op_str="eax, [rsi + 1]",
                    function="f",
                    source=None,
                    read_registers=("rsi",),
                    write_registers=("eax",),
                ),
                ExtractedInstruction(
                    arch="x86-64",
                    address=0x2003,
                    size=2,
                    code_bytes=b"\x01\x02",
                    mnemonic="mov",
                    op_str="dword ptr [rdi], eax",
                    function="f",
                    source=None,
                    read_registers=("rdi", "eax"),
                    write_registers=(),
                ),
            ),
        )
    )

    assert surface.skip_reason is None
    assert surface.input_registers == (("x9", "rdi"),)
```

- [ ] **Step 2: Write failing test for external store values still being inputs**

Keep the existing `test_infers_store_value_register_inputs` expectation:

```python
assert surface.input_registers == (("x1", "rcx"), ("w0", "eax"))
```

If this test already exists, do not duplicate it.

- [ ] **Step 3: Verify the new test fails**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py::test_does_not_treat_internally_defined_store_value_as_input -q
```

Expected: fail because `("w8", "eax")` is currently included as an input.

- [ ] **Step 4: Implement collected operand context**

In `src/angr_rule_learning/extraction/memory_surfaces.py`, add:

```python
@dataclass(frozen=True)
class _CollectedMemoryOperand:
    instruction: object
    operand: MemoryOperand
```

Change `_collect` to return collected operands:

```python
def _collect(window: InstructionWindow) -> tuple[_CollectedMemoryOperand, ...]:
    operands: list[_CollectedMemoryOperand] = []
    for instruction in window.instructions:
        operands.extend(
            _CollectedMemoryOperand(instruction, operand)
            for operand in extract_memory_operands(instruction)
        )
    return tuple(operands)
```

In `infer_memory_surface`, derive public operand tuples for `MemorySurface`:

```python
guest_collected = _collect(pair.guest)
host_collected = _collect(pair.host)
guest_operands = tuple(item.operand for item in guest_collected)
host_operands = tuple(item.operand for item in host_collected)
```

Keep `MemorySurface.guest_operands` and `host_operands` as `tuple[MemoryOperand, ...]`.

- [ ] **Step 5: Implement store value external input check**

Add helper:

```python
def _value_is_defined_before(
    collected: tuple[_CollectedMemoryOperand, ...],
    target: _CollectedMemoryOperand,
) -> bool:
    value_family = family_for_register(
        target.instruction.arch,
        target.operand.value_register,
    )
    for item in collected:
        if item is target:
            return False
        written = {
            family_for_register(item.instruction.arch, register)
            for register in item.instruction.write_registers
        }
        if value_family in written:
            return True
    return False
```

Import `family_for_register` from `angr_rule_learning.extraction.liveness`.

When handling write operands:

```python
guest_value_internal = _value_is_defined_before(guest_collected, guest_item)
host_value_internal = _value_is_defined_before(host_collected, host_item)
if guest.kind == "write":
    if guest_value_internal != host_value_internal:
        return MemorySurface(
            MemorySpec(),
            skip_reason="unsupported_memory_surface",
            guest_operands=guest_operands,
            host_operands=host_operands,
        )
    if not guest_value_internal:
        input_registers.append((guest.value_register, host.value_register))
```

- [ ] **Step 6: Run tests and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_surfaces.py
uv run ruff check
uv run pytest tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py tests/test_extraction_pipeline.py -q
```

Commit:

```bash
git add src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_surfaces.py
git commit -m "Infer external store value inputs conservatively"
```

---

## Task 3: Add Guest-Anchored Semantic Register Coalescing

**Files:**

- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Write failing test for ABI pre/post carrier coalescing**

Add to `tests/test_rules_generalize.py`:

```python
def test_generalizer_coalesces_host_pre_and_post_carriers_by_guest_family() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w0, w1, w0"),),
        (_inst("x86-64", 0x2000, "lea", "eax, [rdi + rsi]"),),
    )
    candidate = _candidate(
        inputs=(("w0", "rdi"), ("w1", "rsi")),
        outputs=(("w0", "eax"),),
    )
    diagnostics = RuleDiagnostics()

    rule = RuleGeneralizer(diagnostics).generate(1, pair, candidate, _passing_report())

    assert rule is not None
    assert rule.guest_lines == ("add i32_reg1, i32_reg2, i32_reg1",)
    assert rule.host_lines == ("lea i32_reg1, [i32_reg1 + i32_reg2]",)
```

- [ ] **Step 2: Verify the test fails**

Run:

```bash
uv run pytest tests/test_rules_generalize.py::test_generalizer_coalesces_host_pre_and_post_carriers_by_guest_family -q
```

Expected: fail with `rule is None` and `unsupported_rule_shape`.

- [ ] **Step 3: Implement guest-anchored coalescing only**

In `_build_placeholder_map`, keep iterating `candidate.output_registers + candidate.input_registers`.

Change the branch:

```python
elif guest_existing is not None and host_existing is None:
    existing = guest_existing
```

Do not add the symmetric case `guest_existing is None and host_existing is not None`. That symmetric case would make this unsafe candidate pass:

```python
inputs=(("w0", "eax"), ("w8", "ecx")),
outputs=(("w8", "eax"),)
```

The existing `test_generalizer_rejects_conflicting_physical_register_mapping` must keep passing.

- [ ] **Step 4: Add explicit regression for symmetric unsafe coalescing**

If `test_generalizer_rejects_conflicting_physical_register_mapping` already covers it, keep it. If not, add:

```python
def test_generalizer_does_not_coalesce_by_host_carrier_alone() -> None:
    diagnostics = RuleDiagnostics()
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "add", "w8, w0, w8"),),
        (_inst("x86-64", 0x2000, "add", "eax, ecx"),),
    )
    candidate = _candidate(
        inputs=(("w0", "eax"), ("w8", "ecx")),
        outputs=(("w8", "eax"),),
    )

    rule = RuleGeneralizer(diagnostics).generate(
        1,
        pair,
        candidate,
        _passing_report(candidate.candidate_id),
    )

    assert rule is None
    assert diagnostics.skip_reasons["unsupported_rule_shape"] == 1
```

- [ ] **Step 5: Run tests and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
uv run ruff check
uv run pytest tests/test_rules_generalize.py -q
```

Commit:

```bash
git add src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "Coalesce guest-anchored rule registers"
```

---

## Task 4: Add Stack Pointer Rule Placeholder

**Files:**

- Modify: `src/angr_rule_learning/rules/registers.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_registers.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Write failing tests for stack pointer placeholders**

Replace the stack pointer part of `test_stack_and_frame_registers_are_literals` in `tests/test_rules_registers.py` with separate tests:

```python
def test_stack_pointer_placeholder_names() -> None:
    from angr_rule_learning.rules.registers import stack_pointer_placeholder

    assert stack_pointer_placeholder("aarch64", "sp") == "sp64"
    assert stack_pointer_placeholder("aarch64", "wsp") == "sp32"
    assert stack_pointer_placeholder("x86-64", "rsp") == "sp64"
    assert stack_pointer_placeholder("x86-64", "esp") == "sp32"
    assert stack_pointer_placeholder("x86-64", "rbp") is None
```

Keep a frame-register literal test:

```python
def test_frame_registers_remain_literals() -> None:
    for reg in ("fp", "rbp", "ebp", "bp"):
        arch = "aarch64" if reg == "fp" else "x86-64"
        assert is_allowed_literal_register(arch, reg)
        with pytest.raises(RegisterClassError):
            classify_register(arch, reg)
```

Add to `tests/test_rules_generalize.py`:

```python
def test_generalizer_uses_stack_pointer_placeholder_without_reg_suffix() -> None:
    pair = _window_pair(
        (_inst("aarch64", 0x1000, "sub", "sp, sp, #16"),),
        (_inst("x86-64", 0x2000, "sub", "rsp, 16"),),
    )
    candidate = _candidate(
        inputs=(("sp", "rsp"),),
        outputs=(("sp", "rsp"),),
    )

    rule = RuleGeneralizer(RuleDiagnostics()).generate(
        1,
        pair,
        candidate,
        _passing_report(candidate.candidate_id),
    )

    assert rule is not None
    assert rule.guest_lines == ("sub sp64, sp64, #imm1",)
    assert rule.host_lines == ("sub sp64, imm1",)
```

- [ ] **Step 2: Verify tests fail**

Run:

```bash
uv run pytest tests/test_rules_registers.py::test_stack_pointer_placeholder_names tests/test_rules_generalize.py::test_generalizer_uses_stack_pointer_placeholder_without_reg_suffix -q
```

Expected: fail because `stack_pointer_placeholder` does not exist and `sp/rsp` are currently literal/unknown for mapping.

- [ ] **Step 3: Implement stack pointer helper**

In `src/angr_rule_learning/rules/registers.py`, add:

```python
_STACK_POINTER_WIDTHS = {
    "aarch64": {"sp": 64, "wsp": 32},
    "x86-64": {"rsp": 64, "esp": 32, "sp": 16},
}


def stack_pointer_placeholder(arch: str, register: str) -> str | None:
    canonical = canonical_arch_name(arch)
    reg = normalize_register_name(register)
    width = _STACK_POINTER_WIDTHS.get(canonical, {}).get(reg)
    if width is None:
        return None
    return f"sp{width}"
```

Keep `sp/rsp` in `known_register_tokens`.

- [ ] **Step 4: Use stack pointer helper in placeholder mapping**

In `src/angr_rule_learning/rules/generalize.py`, import:

```python
stack_pointer_placeholder
```

At the start of the loop in `_build_placeholder_map`, before `_classify_for_rule`, add:

```python
guest_sp = stack_pointer_placeholder(guest_arch, guest_reg)
host_sp = stack_pointer_placeholder(host_arch, host_reg)
if guest_sp is not None or host_sp is not None:
    if guest_sp is None or host_sp is None or guest_sp != host_sp:
        raise _RuleSkip("register_class_mismatch")
    guest_existing = mapping.get(guest_reg)
    host_existing = mapping.get(host_reg)
    existing = guest_existing or host_existing or guest_sp
    if guest_existing not in (None, existing) or host_existing not in (None, existing):
        raise _RuleSkip("unsupported_rule_shape")
    mapping[guest_reg] = existing
    mapping[host_reg] = existing
    continue
```

This maps `sp/rsp` to `sp64` and does not allocate `_regN`.

- [ ] **Step 5: Run tests and commit**

Run:

```bash
uv run ruff format src/angr_rule_learning/rules/registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_registers.py tests/test_rules_generalize.py
uv run ruff check
uv run pytest tests/test_rules_registers.py tests/test_rules_generalize.py -q
```

Commit:

```bash
git add src/angr_rule_learning/rules/registers.py src/angr_rule_learning/rules/generalize.py tests/test_rules_registers.py tests/test_rules_generalize.py
git commit -m "Add stack pointer rule placeholder"
```

---

## Task 5: Smoke Int Measurement And Documentation

**Files:**

- Modify: `docs/rule-generalization.md`
- Optional test updates: `tests/test_extraction_pipeline.py`

- [ ] **Step 1: Update documentation**

In `docs/rule-generalization.md`, document:

```markdown
## Detailed Rule Diagnostics

`--rules-diagnostics` writes aggregate rule counts only. `--rules-debug-diagnostics`
adds per-skipped-rule records and should be used for debugging or small samples,
not default large-scale runs.

## Semantic Register Coalescing

The rule generator may coalesce host pre-state and post-state carrier registers
when the same guest register family anchors both mappings. For example,
`w0 -> rdi` as input and `w0 -> eax` as output may both become `i32_reg1`.
The reverse host-only coalescing is intentionally not allowed.

## Stack Pointer Placeholder

Stack pointer registers use fixed placeholders such as `sp64` and `sp32`.
They do not use `_regN` suffixes because they are architectural special
registers, not arbitrary general-purpose rule variables.
```

- [ ] **Step 2: Run focused smoke for `smoke_int.c`**

Run:

```bash
rm -rf /private/tmp/arl-smoke-yield
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir /private/tmp/arl-smoke-yield/work \
  --output /private/tmp/arl-smoke-yield/candidates.jsonl \
  --diagnostics /private/tmp/arl-smoke-yield/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output /private/tmp/arl-smoke-yield/rules.txt \
  --rules-diagnostics /private/tmp/arl-smoke-yield/rules_diagnostics.json \
  --rules-debug-diagnostics /private/tmp/arl-smoke-yield/rules_debug_diagnostics.json
```

Expected:

- Command exits 0.
- `rules_diagnostics.json` does not contain `skipped_rules`.
- `rules_debug_diagnostics.json` contains `skipped_rules`.
- `rules.txt` emits more than the baseline 9 rules, or the debug diagnostics clearly explain why additional verified-pass candidates are still not emitted.

- [ ] **Step 3: Print measurement summary for reviewer**

Run:

```bash
python3 - <<'PY'
import json
from pathlib import Path
base = Path('/private/tmp/arl-smoke-yield')
for name in ('diagnostics.json', 'rules_diagnostics.json'):
    print(name)
    print(json.dumps(json.loads((base / name).read_text()), indent=2, sort_keys=True))
print('rules.txt')
print((base / 'rules.txt').read_text())
debug = json.loads((base / 'rules_debug_diagnostics.json').read_text())
print('debug skipped count', len(debug.get('skipped_rules', [])))
PY
```

Include this output summary in the final report to the reviewer.

- [ ] **Step 4: Run full verification**

Run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
```

Expected:

- ruff format reports all files formatted.
- ruff check passes.
- pytest passes.

- [ ] **Step 5: Commit documentation and any final test updates**

Commit:

```bash
git add docs/rule-generalization.md tests/test_extraction_pipeline.py
git commit -m "Document rule yield diagnostics and stack placeholders"
```

If `tests/test_extraction_pipeline.py` was not modified, omit it from `git add`.

---

## Final Review Checklist

Before reporting completion:

- [ ] `uv run ruff format --check` passes.
- [ ] `uv run ruff check` passes.
- [ ] `uv run pytest -q` passes.
- [ ] Smoke run on unchanged `samples/sources/smoke_int.c` completed.
- [ ] `--rules-diagnostics` remains aggregate-only.
- [ ] `--rules-debug-diagnostics` is the only detailed per-skip output.
- [ ] `rules_emitted` is compared against the baseline of 9.
- [ ] Remaining skip reasons are reported with at least three representative debug records if yield does not increase.
- [ ] `git status --short` is clean.

## Handoff Prompt For Claude

Use this prompt when handing the task to Claude:

```text
You are working in /Users/anon/Workspace/rule-learning/angr-rule-learning.

Implement docs/superpowers/plans/2026-06-16-smoke-int-rule-yield.md task-by-task.

Hard constraints:
- Do not modify samples/sources/smoke_int.c.
- Do not weaken SemanticVerifier checks.
- Preserve current --rules-diagnostics as cheap aggregate output.
- Add detailed per-skipped-rule diagnostics only behind a new explicit switch: --rules-debug-diagnostics.
- Use TDD for each behavior: write failing tests, verify they fail, implement, verify passing.
- Run ruff format after edits.
- Commit after each task with the commit messages in the plan.

Expected implementation themes:
- Add opt-in detailed rule skip diagnostics.
- Fix memory store value input inference so internally produced store values are not treated as external inputs.
- Add guest-anchored semantic register coalescing, but do not allow host-only coalescing.
- Add special stack pointer placeholders such as sp64/sp32, without _regN suffix.
- Measure unchanged smoke_int.c and report whether rules_emitted increased beyond the baseline of 9.

Final report must include:
- Commit stack.
- ruff format --check, ruff check, pytest -q output summary.
- smoke_int diagnostics summary.
- rules emitted count and the generated rules.
- rules debug diagnostics summary for remaining skipped verified-pass candidates.
```
