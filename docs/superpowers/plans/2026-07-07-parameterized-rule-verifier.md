# Parameterized Rule Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Phase 0-2 parameterized rule verifier that records immediate provenance, rejects invalid parameterized immediate rules, and verifies derived immediate expressions with SMT.

**Architecture:** Introduce a deep `param_verify` module with a small `ParameterizedRuleVerifier.verify(request)` interface. The first implementation validates the generated rule AST against the original concrete candidate using Claripy-level expression semantics for a narrow integer/LEA/movzx subset; the interface is intentionally compatible with a future pyvex post-lift rewriter backend.

**Tech Stack:** Python 3.14, dataclasses, Claripy, existing rule AST/generalizer, pytest, ruff.

---

### Task 1: Immediate Metadata

**Files:**
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_rules_generalize.py`

- [ ] Write failing tests proving immediate replacement returns provenance for shared immediates and leaves single-sided immediates as literals.
- [ ] Add `ImmediateOccurrence`, `ImmediateMetadata`, and `ImmediateReplacementResult` dataclasses.
- [ ] Keep `_replace_immediates_ast()` backward compatible while adding `_replace_immediates_with_metadata()`.
- [ ] Verify focused tests pass.

### Task 2: Rule Semantics Evaluator

**Files:**
- Create: `src/angr_rule_learning/param_verify/__init__.py`
- Create: `src/angr_rule_learning/param_verify/model.py`
- Create: `src/angr_rule_learning/param_verify/semantics.py`
- Test: `tests/test_param_verify.py`

- [ ] Write failing tests for `and #imm`, fixed `and #0xff`, `movzx lo8`, `add imm`, and LEA scale expressions.
- [ ] Implement a narrow rule-AST evaluator that maps placeholders and immediates to Claripy expressions.
- [ ] Support `add/sub/and/orr/eor/xor/mov/movzx/lsl/lsr/asr/lea`.
- [ ] Report unsupported instructions instead of guessing.

### Task 3: Parameterized Equivalence Checker

**Files:**
- Create: `src/angr_rule_learning/param_verify/checker.py`
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Test: `tests/test_param_verify.py`
- Test: `tests/test_kernel_pipeline.py`

- [ ] Write failing tests where `and #imm1 <-> movzx lo8` fails and `and #0xff <-> movzx lo8` passes.
- [ ] Add derived expression support for `(1 << immN)` and `log2(immN)` over bounded allowed values.
- [ ] Gate generated rules when parameterized verification fails.
- [ ] Keep unsupported parameterized verification non-fatal in the first integration, but record diagnostics.

### Task 4: Verification

**Files:**
- Modify tests only if needed for deterministic expectations.

- [ ] Run `uv run ruff format`.
- [ ] Run `uv run ruff check`.
- [ ] Run `uv run pytest -q`.
- [ ] Run forward IR-kernel smoke.
- [ ] Commit implementation on `feature/parameterized-rule-verifier`.

