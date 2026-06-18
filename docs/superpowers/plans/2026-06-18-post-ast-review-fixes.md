# Post-AST Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore rule-generation soundness after the AST migration, preserve placeholder relationships during deduplication, constrain immediate derivation to proven templates, and complete the typed rule contract.

**Architecture:** Keep `Rule` and `Instruction` as the canonical in-memory representation. Metadata ordering and placeholder comparison must be represented structurally rather than inferred from rendered text. Immediate derivation becomes a small set of instruction-aware strategies; any remaining host-only placeholder is rejected. Temporary registers carry the same kind/width information as ordinary register placeholders.

**Tech Stack:** Python 3.14, dataclasses, pytest, Ruff, angr-rule-learning extraction pipeline.

---

## Review Baseline

Execution baseline: current `main` at `e5a7956`. Original review range: `fa7c67c..42245db`.

Commit `e5a7956` additionally parameterizes AArch64 `lsl #N` and x86 `*N` scale operands. Preserve that feature, but do not emit independent Guest/Host scale placeholders. For indexed addressing, the host multiplier must be derived from the guest shift as `1 << shift`.

Known-good command status before fixes:

- `uv run pytest -q`: 315 passed, 5 third-party deprecation warnings.
- `uv run ruff format --check`: 83 files formatted.
- `uv run ruff check`: clean.

Observed incorrect smoke output:

```text
save i32_reg1
and i32_reg1, ${(1 << 0)}
restore i32_reg1
cmp i32_reg1, 0
je label1
```

The required order is `save -> and -> cmp -> restore -> je`.

## File Responsibility Map

- `src/angr_rule_learning/rules/ast.py`: rule node types, metadata placement, placeholder alpha-normalization, structural equality.
- `src/angr_rule_learning/rules/derivation.py`: instruction-aware host-immediate derivation only.
- `src/angr_rule_learning/rules/generalize.py`: candidate-to-rule orchestration, dead-write annotation, strict host-placeholder validation, typed temporary discovery.
- `src/angr_rule_learning/extraction/memory_operands.py`: correct memory width extraction for x86 memory-source arithmetic.
- `tests/test_rules_generalize.py`: metadata order, alpha-equivalence, host-only immediate rejection, embedded-register validation.
- `tests/test_rules_memory_generalize.py`: typed temporaries and safe immediate derivation templates.
- `tests/test_extraction_memory_operands.py`: byte/word/dword/qword RMW parsing.
- `docs/architecture.md`, `docs/rule-generalization.md`, `docs/rule-format.md`, `README.md`: current implementation contract and support boundaries.

### Task 1: Preserve save/restore execution order in the AST

**Files:**
- Modify: `src/angr_rule_learning/rules/ast.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Add a failing final-output regression test**

Construct the existing `tbz -> and/cmp/je` rule through `RuleGeneralizer.generate()`. Change `GeneratedRule.guest_lines` and `host_lines` to flatten rendered instructions with `splitlines()`, so each tuple item is exactly one assembly or metadata line. Assert the complete host sequence:

```python
assert rule.host_lines == (
    "save i32_reg1",
    "and i32_reg1, ${(1 << 0)}",
    "cmp i32_reg1, 0",
    "restore i32_reg1",
    "je label1",
)
assert all("\n" not in line for line in rule.host_lines)
```

- [ ] **Step 2: Run the regression test and confirm the current order fails**

Run:

```bash
uv run pytest tests/test_rules_generalize.py -k "restore and branch" -vv
```

Expected: failure showing `restore` before `cmp`.

- [ ] **Step 3: Represent pre- and post-instruction metadata explicitly**

Keep `Instruction.meta` as pre-instruction metadata for compatibility and add post-instruction metadata:

```python
@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    operands: tuple[Operand, ...]
    meta: tuple[MetaOp, ...] = ()
    post_meta: tuple[MetaOp, ...] = ()

    def to_text(self) -> str:
        instruction = self.mnemonic
        if self.operands:
            instruction += " " + ", ".join(op.to_text() for op in self.operands)
        return "\n".join(
            [
                *(op.to_text() for op in self.meta),
                instruction,
                *(op.to_text() for op in self.post_meta),
            ]
        )
```

Update every AST reconstruction helper (`substitute_imm`, derivation, label replacement, immediate replacement, and register generalization) to preserve both fields.

- [ ] **Step 4: Attach restore after the last relevant register access**

Replace the `last_read` model with `last_access`: after the first dead write, track subsequent reads and writes. If no later access exists, the first write is the last access. Attach `restore` to `post_meta` of that instruction.

The branch case must attach `restore` after `cmp`, not before it. A one-instruction dead write must still receive a matching restore after that instruction.

- [ ] **Step 5: Remove metadata-destroying instruction round trips**

In `_replace_immediates_ast()`, do not call `inst.to_text()` followed by `Instruction.from_text()` for the complete instruction. Rewrite each operand independently and reconstruct with:

```python
Instruction(
    mnemonic=inst.mnemonic,
    operands=new_operands,
    meta=inst.meta,
    post_meta=inst.post_meta,
)
```

Compound operands may remain `LitOp` strings temporarily, but metadata must never pass through the assembly parser.

- [ ] **Step 6: Add invariant tests**

Cover all of:

- restore after the final read;
- restore after a single dead write with no read;
- every emitted `save` has one matching `restore`;
- immediate replacement preserves both pre- and post-metadata;
- `GeneratedRule.guest_lines` and `host_lines` return actual lines, with no embedded newline characters.

- [ ] **Step 7: Verify and commit**

```bash
uv run pytest tests/test_rules_generalize.py -q
uv run ruff format
uv run ruff check
git add src/angr_rule_learning/rules/ast.py src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "Fix rule metadata execution order"
```

### Task 2: Implement relationship-preserving alpha-equivalence

**Files:**
- Modify: `src/angr_rule_learning/rules/ast.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Add failing alias-relationship tests**

The following pairs must not compare equal:

```python
add_a = (Instruction("add", (r(1), r(1), r(2))),)
add_b = (Instruction("add", (r(1), r(2), r(1))),)
assert not instruction_sequences_alpha_equal(add_a, add_b)
```

Also cover:

- `sub reg1, reg1, reg2` versus `sub reg1, reg2, reg1`;
- `add reg1, imm1` versus `add reg1, imm2` when the guest/host sharing pattern differs;
- two labels with the same target versus two distinct targets;
- embedded placeholders in memory operands;
- rules that differ only by consistent renumbering and therefore must compare equal.

- [ ] **Step 2: Confirm the current comparator fails**

```bash
uv run pytest tests/test_rules_generalize.py -k "alpha or alias or renumber" -vv
```

- [ ] **Step 3: Add a canonical rule fingerprint**

Implement `rule_fingerprint(guest, host)` in `rules/ast.py`. Traverse guest then host in deterministic instruction/operand order. Maintain independent canonical-ID maps for:

- integer/float/vector register placeholders, keyed by `(prefix, bits, original_id)`;
- temporary placeholders, keyed by the current `original_id`; Task 4 must extend this key to `(kind, bits, original_id)` when typed temporaries are introduced;
- immediate placeholders;
- label placeholders.

The first distinct variable in each namespace becomes ID 1, the next becomes ID 2. Repeated occurrences must reuse the same canonical ID across both sides. Normalize placeholders embedded in `LitOp` and `RegTextOp`, including memory expressions and derived immediate expressions.

Include mnemonic, operand type, literal punctuation/text, `meta`, and `post_meta` in the fingerprint. Special fixed placeholders such as `sp64` and `fp64` are literals by role and must not consume variable IDs.

- [ ] **Step 4: Replace unsafe equality consumers**

Use the fingerprint for:

- `RuleGeneralizer._emitted_keys` duplicate detection;
- `structurally_equal()` used by consolidation.

Delete or make private any comparator that independently ignores operand IDs without maintaining a mapping.

- [ ] **Step 5: Add an end-to-end duplicate regression**

Feed two verifier-passing candidates whose rules are:

```text
add i32_reg1, i32_reg1, i32_reg2
add i32_reg1, i32_reg2, i32_reg1
```

Assert both are emitted. Then feed a third rule with only consistent placeholder renumbering and assert it is diagnosed as `duplicate_rule`.

- [ ] **Step 6: Verify and commit**

```bash
uv run pytest tests/test_rules_generalize.py -q
uv run ruff format
uv run ruff check
git add src/angr_rule_learning/rules/ast.py src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "Preserve placeholder relationships in rule equality"
```

### Task 3: Make immediate derivation template-specific and strict

**Files:**
- Modify: `src/angr_rule_learning/rules/derivation.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`
- Test: `tests/test_rules_memory_generalize.py`

- [ ] **Step 1: Add failing unsoundness tests**

Add these cases:

1. `tbz #1` must produce `${(1 << imm1)}`, never `${(1 << 1)}`.
2. `eor #1; eor #2` versus host `xor 3` must not infer OR/add solely because the concrete values match.
3. A non-memory rule with guest `imm1` and unresolved host `imm2` must be skipped with `unpaired_host_immediate`.
4. Existing `mov + movk -> movabs` and `tbz/tbnz -> mask` tests must continue to pass.
5. Indexed memory `[base, index, lsl #2]` versus `[base + index*4]` must emit a guest shift placeholder and derive the host scale from it; it must not emit an independent host-only `immN`.

- [ ] **Step 2: Confirm the failures**

```bash
uv run pytest tests/test_rules_generalize.py tests/test_rules_memory_generalize.py -k "tbz or derived or host_immediate or bitwise" -vv
```

- [ ] **Step 3: Remove generic value-only expression search**

Delete the unrestricted L1/L2/L3 search that accepts an expression merely because it equals one concrete target. Replace it with explicit strategies that inspect the AST context:

```python
DerivationStrategy = Callable[[DerivationContext, str], str | None]
```

Implement only:

- `derive_tbz_mask`: require guest `tbz`/`tbnz`, use its bit-position operand, and require a compatible host `and` mask path;
- `derive_movk_constant`: require the guest `mov`/`movk` construction and compatible host `movabs`; when the `lsl` amount is parameterized, reference that guest shift placeholder in the derived expression;
- `derive_index_scale`: require a paired AArch64 indexed memory operand using `lsl #immN` and x86 indexed memory using `*immM`; replace the host scale with `${(1 << immN)}`.

Do not add generic add/sub/OR derivation in this repair. Unsupported shapes must remain unpaired and be skipped.

- [ ] **Step 4: Separate implicit constants from guest placeholders**

Do not place the literal base `1` used by `tbz` in the same ID namespace as a guest immediate whose concrete value is also one. Build the expression directly from the bit-position `ImmOp`; for a parameterized bit position use `immN`, and for the reserved literal zero use `0`.

- [ ] **Step 5: Enforce host-placeholder derivability for every rule**

Replace the frame-memory-only check with a universal invariant after derivation:

```python
host_references <= guest_bindable_immediates
```

A host `ImmOp` whose own ID remains and is absent from the guest must cause `_RuleSkip("unpaired_host_immediate")`, regardless of whether the candidate has memory bindings. Derived expressions count only the guest IDs referenced inside the expression.

Keep fixed literals as literals. Do not silently turn an unresolved host placeholder back into a literal after guest values have already been generalized; reject the rule instead.

- [ ] **Step 6: Verify and commit**

```bash
uv run pytest tests/test_rules_generalize.py tests/test_rules_memory_generalize.py -q
uv run ruff format
uv run ruff check
git add src/angr_rule_learning/rules/derivation.py src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py tests/test_rules_memory_generalize.py
git commit -m "Constrain immediate derivation to proven templates"
```

### Task 4: Add type and width to temporary placeholders

**Files:**
- Modify: `src/angr_rule_learning/rules/ast.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`
- Test: `tests/test_rules_memory_generalize.py`

- [ ] **Step 1: Add failing typed-temporary tests**

Update the RMW rule expectation to:

```text
ldr i32_tmp1, [i64_reg2, #imm1]
add i32_reg1, i32_reg1, i32_tmp1
```

Add a 64-bit temporary case expecting `i64_tmp1`. Assert no emitted rule matches the untyped-token regex `(?<![A-Za-z0-9_])tmp\d+`.

- [ ] **Step 2: Confirm current `tmp1` output fails**

```bash
uv run pytest tests/test_rules_memory_generalize.py -k "temporary or rmw" -vv
```

- [ ] **Step 3: Extend `TmpOp`**

Use:

```python
@dataclass(frozen=True)
class TmpOp:
    kind: RegisterKind
    bits: int
    id: int

    def to_text(self) -> str:
        return f"{self.kind}{self.bits}_tmp{self.id}"
```

Avoid importing `RegisterKind` from `rules.registers` if that creates a cycle; define the narrow literal type in `ast.py` or a small shared type module.

Update `parse_placeholder()`, text parsing kept for external/test compatibility, fingerprinting, and all temporary regexes to support `i32_tmp1`, `i64_tmp1`, `f32_tmp1`, and `v128_tmp1`.

Update the Task 2 fingerprint namespace for temporaries from `original_id` to `(kind, bits, original_id)` and rerun the alpha-equivalence tests.

- [ ] **Step 4: Classify the concrete temporary register**

In `_identify_internal_temps()`, call `_classify_for_rule(arch, reg_n)` and generate:

```python
reg_class = _classify_for_rule(arch, reg_n)
placeholder = f"{reg_class.placeholder_prefix}_tmp{next_tmp}"
```

Unsupported float/vector registers must continue to produce an explicit unsupported skip; do not label them as integer temporaries.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/test_rules_generalize.py tests/test_rules_memory_generalize.py -q
uv run ruff format
uv run ruff check
git add src/angr_rule_learning/rules/ast.py src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py tests/test_rules_memory_generalize.py
git commit -m "Add type and width to rule temporaries"
```

### Task 5: Correct RMW widths and embedded-register validation

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_operands.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_extraction_memory_operands.py`
- Test: `tests/test_rules_generalize.py`

- [ ] **Step 1: Add failing RMW-width tests**

Cover memory-source forms:

```text
add al, byte ptr [rcx]       -> width 1
sub ax, word ptr [rcx]       -> width 2
xor eax, dword ptr [rcx]     -> width 4
imul rax, qword ptr [rcx]    -> width 8
```

Also assert memory-destination `add dword ptr [rcx], eax` remains unsupported.

- [ ] **Step 2: Replace the hardcoded width**

Keep `movsxd` as a four-byte read, but use `_x86_width(op_str, value_register)` for `_X86_RMW_MNEMONICS`.

- [ ] **Step 3: Add a failing embedded-register validation test**

```python
inst = Instruction("ldr", (LitOp("i32_reg1"), LitOp("[x1]")))
with pytest.raises(_RuleSkip, match="unmapped_register_surface"):
    _validate_no_remaining_registers((inst,), "aarch64")
```

- [ ] **Step 4: Tokenize compound operands during validation**

Scan identifier tokens inside `LitOp` and `RegTextOp`, compare each token with `known_register_tokens(arch)`, and ignore allowed architectural literals plus recognized typed placeholders. This must detect `[x1]`, `dword ptr [rcx + rdx*4]`, and similar operands without treating `dword`, `ptr`, or placeholder fragments as registers.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/test_extraction_memory_operands.py tests/test_rules_generalize.py -q
uv run ruff format
uv run ruff check
git add src/angr_rule_learning/extraction/memory_operands.py src/angr_rule_learning/rules/generalize.py tests/test_extraction_memory_operands.py tests/test_rules_generalize.py
git commit -m "Fix RMW widths and compound register validation"
```

### Task 6: Synchronize documentation and run full acceptance tests

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/rule-generalization.md`
- Modify: `docs/rule-format.md`
- Modify: `src/angr_rule_learning/extraction/pipeline.py`
- Test: `tests/test_extraction_pipeline.py`
- Test: full suite and end-to-end scripts

- [ ] **Step 1: Update architecture documentation**

Make these concrete corrections:

- add `rules/ast.py` and `rules/derivation.py` to the package map;
- remove the deleted `rules/memory.py` entry;
- describe Rule AST as the canonical internal rule model;
- document pre/post metadata ordering;
- document relationship-preserving alpha-equivalence and consolidation;
- state that x86 memory-source arithmetic is supported for `add/sub/and/or/xor/imul`, while memory-destination RMW remains unsupported;
- state that immediate derivation is limited to explicit `tbz/tbnz`, `mov/movk`, and indexed-address scale templates.

- [ ] **Step 2: Update rule format and generalization documentation**

Document typed temporaries as `i32_tmpN`, `i64_tmpN`, `f32_tmpN`, or `v128_tmpN`; remove all normative `tmpN` examples. Correct the stale statement that immediates are always literal and list `unpaired_host_immediate` as a universal rejection condition.

Document scale placeholders explicitly: AArch64 shift amounts are bindable Guest immediates, while the corresponding x86 multiplier is a derived expression `1 << shift`, not an independent Host placeholder.

- [ ] **Step 3: Link the detailed rule-format document from README**

Add `docs/rule-format.md` to the README Documentation section and update Current Status/unsupported memory forms consistently.

- [ ] **Step 4: Run static checks and full tests**

```bash
uv run ruff format
uv run ruff format --check
uv run ruff check
uv run pytest -q
git diff --check
```

Expected: all tests pass; only the five known third-party Python 3.14 deprecation warnings may remain.

- [ ] **Step 5: Run both end-to-end pipelines**

```bash
./scripts/run_all_tests.sh samples/sources/smoke_int.c \
  /private/tmp/arl-post-ast-smoke/work \
  /private/tmp/arl-post-ast-smoke/out 0

./scripts/run_all_tests.sh samples/sources/rich_int.c \
  /private/tmp/arl-post-ast-rich/work \
  /private/tmp/arl-post-ast-rich/out 0
```

Acceptance requirements:

- no verifier errors;
- branch rule order is `save -> and -> cmp -> restore -> branch`;
- no untyped `tmpN` appears;
- no concrete non-literal register leaks into rules;
- every host immediate placeholder is present on Guest or inside an approved derived expression referencing Guest placeholders;
- indexed memory rules derive the x86 multiplier from the AArch64 shift and contain no independent host-only scale placeholder;
- both add operand-relationship variants are retained unless an explicit, tested semantic commutativity normalization is introduced;
- `rules_diagnostics.json` counts match the final emitted rule file after consolidation.

- [ ] **Step 6: Fix post-consolidation diagnostics**

Update diagnostics so `rules_emitted` always equals the number written after `consolidate_rules()`. Record each removal under the stable reason `subsumed_rule`; ensure `rules_considered == rules_emitted + rules_skipped` remains true.

Add a pipeline test containing one literal rule subsumed by a parameterized rule and assert both the file count and diagnostics count.

- [ ] **Step 7: Commit documentation and final integration**

```bash
git add README.md docs/architecture.md docs/rule-generalization.md docs/rule-format.md \
  docs/superpowers/plans/2026-06-18-post-ast-review-fixes.md \
  src/angr_rule_learning/extraction/pipeline.py tests/test_extraction_pipeline.py
git commit -m "Document sound AST rule generation"
git status --short
```

Expected: clean working tree.

## Implementation Status

### Completed

- [x] **Task 1: Preserve save/restore execution order in AST** -- commit `2d3277a`
  - `Instruction.post_meta` field added; restore attached after last access
  - Metadata preserved through all AST reconstruction helpers
- [x] **Task 2: Relationship-preserving alpha-equivalence** -- commit `4dbbdcf`
  - `canonicalize_rule()` fingerprint preserves placeholder relationships
  - Replaced unsafe equality consumers in dedup and consolidation
- [x] **Task 3: Template-specific immediate derivation** -- commit `829653b`
  - Removed generic value-only expression search
  - Only `tbz`/`tbnz`, `mov`/`movk`, and index-scale templates allowed
  - `unpaired_host_immediate` now universal rejection condition
- [x] **Task 4: Typed temporary placeholders** -- commit `0068b5d`
  - `TmpOp` carries `prefix` and `bits`; emits `i32_tmpN`, `i64_tmpN`, etc.
  - `_identify_internal_temps()` classifies via `_classify_for_rule()`
- [x] **Task 5: RMW widths and embedded-register validation** -- commit `d639c29`
  - Memory-source arithmetic widths parsed from operand text
  - `_validate_no_remaining_registers()` tokenizes compound operands
- [x] **Task 6: Documentation and diagnostics** -- pending commit
  - Documentation updated: architecture, rule-generalization, rule-format, README
  - Post-consolidation diagnostics: `rules_subsumed` tracking, invariant `considered == emitted + skipped + subsumed`
  - Pipeline test for consolidation diagnostics

## Final Report Requirements

Report all of the following:

1. commit hash and subject for every task;
2. files changed by task;
3. new regression tests grouped by the review issue they cover;
4. exact Ruff and pytest results;
5. smoke and rich diagnostics (`windows_emitted`, `windows_verified_pass`, `rules_emitted`, skip reasons);
6. the corrected branch rule and one typed-temporary RMW rule;
7. any intentionally deferred limitation;
8. `git status --short` output.

Do not merge or push. Commit all work on the current feature branch and leave the working tree clean for review.
