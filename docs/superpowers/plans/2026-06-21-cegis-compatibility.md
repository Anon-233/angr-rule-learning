# CEGIS Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve positional candidate coverage in `cegis` mode while using semantic selector search wherever the current verifier can prove a mapping.

**Architecture:** Keep transfer-assisted CEGIS for straight-line register windows and add a bounded verifier-driven selector search for memory and branch windows. Carry the complete memory surface through the binding boundary, and use positional only as an observable fallback for unsupported or inconclusive searches.

**Tech Stack:** Python 3.14, angr, Claripy, pytest, Ruff

---

### Task 1: Carry Complete Memory Context And Fallback Metadata

**Files:**
- Modify: `src/angr_rule_learning/extraction/register_bindings.py`
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Modify: `src/angr_rule_learning/extraction/diagnostics.py`
- Test: `tests/test_extraction_register_bindings.py`
- Test: `tests/test_extraction_surfaces.py`

- [ ] Write failing tests requiring `BindingProblem.memory_surface`, optional fallback metadata on a successful binding result, and a `register_binding_fallbacks` diagnostics counter.
- [ ] Run the focused tests and confirm failures are caused by the absent fields and recorder.
- [ ] Replace `has_memory` with `memory_surface`, add `fallback_detail` to `RegisterBindingResult`, and record successful fallbacks separately in `SurfaceInferer`.
- [ ] Run the focused tests and Ruff on modified files.

### Task 2: Support Empty And Bounded Selector Surfaces

**Files:**
- Modify: `src/angr_rule_learning/extraction/register_cegis.py`
- Test: `tests/test_extraction_register_cegis.py`

- [ ] Write failing tests for zero-input constant transfer, zero-output selector domains, and explicit side/role/count details when a surface exceeds four registers.
- [ ] Run the focused tests and confirm the zero-input case is rejected by the current `count < 1` check.
- [ ] Permit zero cardinality, retain equal-cardinality and exact-width requirements, and split the four-register limit details by side and role.
- [ ] Run the focused tests and Ruff on modified files.

### Task 3: Add Verifier-Driven Selector Search

**Files:**
- Modify: `src/angr_rule_learning/extraction/register_cegis.py`
- Test: `tests/test_extraction_register_cegis.py`
- Test: `tests/test_verifier_memory.py`
- Test: `tests/test_verifier_branches.py`

- [ ] Write failing tests showing a parsed load mapping and a terminal conditional-branch mapping are found despite swapped same-width inputs.
- [ ] Add a regression assertion that the verifier receives the real memory slots, bindings, and access expectations instead of an empty `MemorySpec`.
- [ ] Implement deterministic exact-width mapping generation with all-different assignments, product input/output proposals, complete candidate construction, and first-pass termination.
- [ ] Return `register_binding_unsat` only after every supported mapping fails; return an inconclusive result for verifier unsupported/error outcomes.
- [ ] Run the focused CEGIS, memory, and branch tests.

### Task 4: Add Positional Compatibility Fallback

**Files:**
- Modify: `src/angr_rule_learning/extraction/register_cegis.py`
- Modify: `src/angr_rule_learning/extraction/register_bindings.py`
- Test: `tests/test_extraction_register_cegis.py`
- Test: `tests/test_extraction_pipeline.py`

- [ ] Write failing tests proving unsupported, inconclusive, and over-limit searches call positional fallback, while exhaustive unsat does not.
- [ ] Inject a fallback solver into `CegisRegisterBindingSolver` and preserve successful pairs with an explicit `fallback_detail`.
- [ ] Add an end-to-end test requiring CEGIS mode to emit immediate, load/store, and fixed-role shift rule families together.
- [ ] Run all extraction and pipeline tests.

### Task 5: Documentation And Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/superpowers/specs/2026-06-21-cegis-register-binding-design.md`

- [ ] Document the two internal CEGIS search modes, four-register limit, complete-memory verification, and positional fallback semantics.
- [ ] Run `uv run ruff format`, `uv run ruff check`, and `uv run pytest -q`.
- [ ] Run `rich_int.c -O1` with both positional and CEGIS strategies into separate temporary output directories.
- [ ] Compare diagnostics and assert CEGIS output contains immediate, load/store, and fixed-role shift rules with no verifier internal errors.
- [ ] Review the final diff, run `git diff --check`, and commit the implementation with a Codex co-author trailer.
