# ISA Memory Recognizers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move all ISA-specific memory operand recognition and implicit stack behavior into per-ISA packages under `arch/` without changing extraction behavior.

**Architecture:** `arch.memory` owns the shared `MemoryOperand` model and architecture-dispatch facade. `arch.aarch64.memory` and `arch.x86_64.memory` own instruction syntax, supported memory forms, register-width rules, broad memory-access detection, and stack-pointer deltas. Extraction code consumes only the facade and remains architecture-neutral.

**Tech Stack:** Python 3.14, dataclasses, regular expressions, pytest, Ruff

---

### Task 1: Define the architecture memory boundary

**Files:**
- Create: `src/angr_rule_learning/arch/memory.py`
- Create: `tests/test_arch_memory.py`

- [x] Add tests that import `MemoryOperand`, `extract_memory_operands`, `has_any_memory_access`, and `stack_pointer_delta` from `angr_rule_learning.arch.memory`.
- [x] Verify the tests fail because the facade does not exist.
- [x] Add the shared model, recognizer protocol, canonical-architecture dispatch, and public facade functions.
- [x] Verify unsupported registered architectures return no operands, no memory access, and zero stack delta.

### Task 2: Move AArch64 recognition

**Files:**
- Create: `src/angr_rule_learning/arch/aarch64/__init__.py`
- Create: `src/angr_rule_learning/arch/aarch64/memory.py`
- Modify: `tests/test_arch_memory_recognizers.py`
- Modify: `src/angr_rule_learning/extraction/memory_operands.py`

- [x] Move AArch64 load/store, indexed, pair, memory-presence, width, displacement, and stack-delta tests to the recognizer test module.
- [x] Verify tests fail against the new module path.
- [x] Move the AArch64 regular expressions and implementation behind an AArch64 recognizer.
- [x] Run the focused AArch64 tests and preserve all existing results.

### Task 3: Move x86-64 recognition

**Files:**
- Create: `src/angr_rule_learning/arch/x86_64/__init__.py`
- Create: `src/angr_rule_learning/arch/x86_64/memory.py`
- Modify: `tests/test_arch_memory_recognizers.py`
- Modify: `src/angr_rule_learning/extraction/memory_operands.py`

- [x] Move x86-64 mov, movsxd, memory-source RMW, push/pop, address, width, memory-presence, and stack-delta tests to the recognizer test module.
- [x] Verify tests fail against the new module path.
- [x] Move x86-64 regular expressions and implementation behind an x86-64 recognizer.
- [x] Run the focused x86-64 tests and preserve all existing results.

### Task 4: Remove extraction-layer ISA knowledge

**Files:**
- Delete: `src/angr_rule_learning/extraction/memory_operands.py`
- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Modify: `src/angr_rule_learning/analysis/skip_patterns.py`
- Modify: relevant tests and architecture documentation

- [x] Update production imports to use `arch.memory`.
- [x] Replace `_instruction_sp_delta` and all imported private ISA regexes with `stack_pointer_delta`.
- [x] Delete the obsolete mixed-ISA extraction module and update tests so no source code imports it.
- [x] Document the per-ISA package boundary and extension procedure.

### Task 5: Verify and commit

**Files:**
- Verify all changed source, tests, and documentation.

- [x] Run `uv run ruff format --check src tests`.
- [x] Run `uv run ruff check`.
- [x] Run `uv run pytest -q`.
- [ ] Run the existing rich integer extraction smoke and compare diagnostics/rules with the baseline. (Blocked by the execution environment's escalation quota on 2026-06-22.)
- [x] Review `git diff --check` before committing the complete refactor to `main`.
