# AST Migration for Rule Generalization Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace text/regex operations in `RuleGeneralizer.generate()` with AST-based operations, eliminating the text→AST conversion at rule emission.

**Architecture:** Five phases, each migrating one stage of the pipeline. Register generalization first (largest impact), then dead writes, labels, immediates, and final integration. Each phase is independently testable and committable.

---

## Phase 0: ImmOp neg field (1 task)

### Task 0: Add `neg: bool` field to ImmOp

**Files:** Modify `src/angr_rule_learning/rules/ast.py:31-43`

- [ ] Add `neg: bool = False` to `ImmOp`
- [ ] Update `to_text()`: prefix `"-"` when `neg` is True
- [ ] Update `_parse_operand()` to detect negative `#-immN`/`-immN`
- [ ] Update `_op_equal()` to compare `a.neg == b.neg`
- [ ] Test: `ImmOp(id=1, neg=True, aarch64_hash=True).to_text()` == `"#-imm1"`
- [ ] Commit: `Add neg field to ImmOp for negative immediate support`

---

## Phase C: Register Generalization (4 tasks)

### Task C.1: Build AST from extracted instructions

**Files:** Modify `src/angr_rule_learning/rules/generalize.py`

- [ ] Add `_instructions_to_ast(instructions: tuple[ExtractedInstruction, ...]) -> tuple[Instruction, ...]`:
  ```python
  def _instructions_to_ast(instructions):
      return tuple(Instruction.from_text(_instruction_text(inst)) for inst in instructions)
  ```
- [ ] Add `_validate_no_remaining_registers(insts, arch)`:
  Walk all operands. For `LitOp` and `RegTextOp`, check if the text matches `known_register_tokens(arch)`. Raise `_RuleSkip("unmapped_register_surface")` if any remain.
- [ ] Test: `test_instructions_to_ast_produces_correct_operands` — verify `ldr w0, [x1]` parses to `Instruction(mnemonic="ldr", operands=[LitOp("w0"), LitOp("[x1]")])`.
- [ ] Test: `test_validate_remaining_registers_raises` — `LitOp("x0")` with known register token raises `_RuleSkip`.
- [ ] Commit

### Task C.2: Implement AST register generalization with roles

**Files:** Modify `src/angr_rule_learning/rules/generalize.py`

- [ ] Add `_generalize_instructions_with_roles(insts, extracted, mapping, role_split, arch) -> tuple[Instruction, ...]`:
  For each `(inst, ext)` pair:
  1. Handle role-split registers first. For each register in `role_split`, walk operands and track occurrences. First occurrence gets `out_ph`, subsequent get `in_ph`. Replace matching `LitOp`/`RegTextOp` with `RegOp` (using `_text_to_regop(placeholder)` helper).
  2. Handle regular mapping. For each `(register, placeholder)` in mapping (sorted longest first), replace matching operands with `RegOp`.
  3. Call `_validate_no_remaining_registers` at end.
- [ ] Test: `test_generalize_ast_replaces_registers` — `add w8, w0, w1` with mapping → operands become RegOp.
- [ ] Test: `test_generalize_ast_role_split` — split case from existing `test_splits_guest_register_when_output_and_input_pair_differently`.
- [ ] Commit

### Task C.3: Wire AST register generalization into generate()

**Files:** Modify `src/angr_rule_learning/rules/generalize.py:188-213`

- [ ] Replace `_instruction_lines()` → `_instructions_to_ast()` calls
- [ ] Replace `_generalize_lines_with_roles()` → `_generalize_instructions_with_roles()` calls
- [ ] Keep `guest_raw_lines`/`host_raw_lines` for skip detail recording (computed from AST via `to_text()`)
- [ ] Run all existing tests — must pass
- [ ] Commit

### Task C.4: Remove text-based register generalization

- [ ] Remove `_generalize_line`, `_generalize_lines`, `_generalize_lines_with_roles`, `_remaining_registers`
- [ ] Update any remaining callers
- [ ] Full test suite must pass
- [ ] Commit

---

## Phase A: Dead Write Annotation (3 tasks)

### Task A.1: Implement MetaOp-based dead write annotation

**Files:** Modify `src/angr_rule_learning/rules/generalize.py:996-1055`

- [ ] Change `_annotate_dead_writes` to accept/return `tuple[Instruction, ...]` instead of text
- [ ] Replace text-line insertion in `_apply` with MetaOp creation:
  ```python
  inst = Instruction(mnemonic=inst.mnemonic, operands=inst.operands,
                     meta=(MetaOp(kind="save", regs=save_regs),))
  ```
- [ ] Test: `test_dead_write_produces_meta_ops` — verify `inst.meta` contains `MetaOp(kind="save")` / `MetaOp(kind="restore")`.
- [ ] Commit

### Task A.2: Wire AST dead writes into generate()

- [ ] Update call in `generate()` to pass `guest_insts`/`host_insts` instead of text
- [ ] All tests involving `save`/`restore` must pass
- [ ] Commit

### Task A.3: Clean up

- [ ] Remove old text-based `_apply` implementation
- [ ] Commit

---

## Phase B: Label Replacement (3 tasks)

### Task B.1: AST branch and hex detection helpers

**Files:** Modify `src/angr_rule_learning/rules/generalize.py`

- [ ] Add `_is_branch_instruction(inst: Instruction, arch: str) -> bool` — checks mnemonic against branch sets
- [ ] Add `_extract_hex_target(inst: Instruction, arch: str) -> Operand | None` — finds the operand containing a hex target
- [ ] Test: branch detection and hex extraction for both arches
- [ ] Commit

### Task B.2: AST label replacement

- [ ] Replace `_replace_labels_shared` to work on `tuple[Instruction, ...]`
- [ ] Walk operands, replace hex-containing `LitOp` with `LabelOp(id=N, aarch64_hash=...)`
- [ ] Test: label replacement produces correct LabelOp nodes
- [ ] Commit

### Task B.3: Wire AST labels + update consistency check

- [ ] Update `_labels_are_consistent` to walk AST for `LabelOp.id` comparison
- [ ] Update call in `generate()`
- [ ] All label tests must pass
- [ ] Commit

---

## Phase D: Immediate Replacement (5 tasks)

### Task D.1: AST immediate collection

**Files:** Modify `src/angr_rule_learning/rules/generalize.py`

- [ ] Add `_collect_immediates_from_ast(guest_insts, guest_extracted, host_insts, host_extracted, guest_arch, host_arch)`:
  Walk operands for `LitOp` with integer values. Compute canonical forms, assign IDs. Track scale shifts and bit positions using context helpers.
- [ ] Test: collection produces same canonical_to_id as text-based version
- [ ] Commit

### Task D.2: AST immediate replacement

- [ ] Add `_replace_immediates_in_ast(insts, extracted, arch, canonical_to_id, scale_shifts, reserved_literals)`:
  Replace `LitOp` immediates with `ImmOp(id=N, aarch64_hash=..., neg=...)`. Skip reserved literals and scale immediates.
- [ ] Test: replacement produces correct ImmOp nodes
- [ ] Commit

### Task D.3: Expression derivation on AST

- [ ] Add `_set_derived_expressions(insts, host_only_ids, guest_values, scale_shifts, all_values, implicit_ids)`:
  For host-only `ImmOp` nodes, compute derivation using existing `_derive_host_expression()`, set `ImmOp.derived`.
- [ ] Test: derivation test from existing suite passes
- [ ] Commit

### Task D.4: Wire AST immediates into generate()

- [ ] Replace `_replace_immediates_shared()` call with three-step AST process
- [ ] Update `_host_immediates_are_derivable` to walk AST for `ImmOp.id` comparison
- [ ] All immediate tests must pass
- [ ] Commit

### Task D.5: Remove text-based immediate code

- [ ] Remove `_replace_immediates_shared`, `_replace_side`, `_replacer`, `_inline_derived_expressions`
- [ ] Keep `_derive_host_expression`, `_is_scale_immediate`, `_is_bit_position`, `_imm_canonical`
- [ ] Full test suite must pass
- [ ] Commit

---

## Phase E: Final Integration (4 tasks)

### Task E.1: Build Rule AST directly

**Files:** Modify `src/angr_rule_learning/rules/generalize.py:258-263`

- [ ] Replace `GeneratedRule.from_text_lines(...)` with direct `Rule` construction:
  ```python
  rule = GeneratedRule(rule_id=rule_id, candidate_id=candidate.candidate_id,
      rule=AstRule(rule_id=rule_id, candidate_id=candidate.candidate_id,
          guest=guest_insts, host=host_insts))
  ```
- [ ] Update `_build_skip_detail` to accept AST and compute text on demand
- [ ] All tests must pass
- [ ] Commit

### Task E.2: Structural dedup

- [ ] Change `_emitted_keys` to store AST tuples: `list[tuple[tuple[Instruction, ...], tuple[Instruction, ...]]]`
- [ ] Use `_insts_equal()` from ast.py for comparison
- [ ] Update `_insts_equal` to also compare `Instruction.meta`
- [ ] Test: two structurally identical rules with different placeholder numbering are deduplicated
- [ ] Commit

### Task E.3: Remove text-parsing from AST

**Files:** Modify `src/angr_rule_learning/rules/ast.py`

- [ ] Remove `Instruction.from_text()`, `_parse_operands()`, `_parse_operand()`, `_split_operands()`
- [ ] Remove `Rule.from_generated()`
- [ ] Keep all `to_text()` methods
- [ ] All tests must pass
- [ ] Commit

### Task E.4: Final cleanup

- [ ] Remove `GeneratedRule.from_text_lines` classmethod
- [ ] Remove any remaining text-based function stubs
- [ ] Full test suite: `uv run pytest -q` — all pass
- [ ] Smoke test: `./scripts/run_all_tests.sh samples/sources/smoke_int.c ...` — output unchanged
- [ ] Commit

---

## Verification

After all phases:
```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
./scripts/run_all_tests.sh samples/sources/smoke_int.c /tmp/arl-ast-final/work /tmp/arl-ast-final/out 0
```

Expected: 308+ tests pass, smoke output identical to pre-migration.
