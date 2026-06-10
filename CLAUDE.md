# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
uv run pytest

# Run a single test file
uv run pytest tests/test_verifier_registers.py -v

# Format and lint
uv run ruff format
uv run ruff check

# Run the verifier CLI against a JSONL batch
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output report.jsonl --summary summary.json
```

## Architecture

This is a binary translation rule learning pipeline. The first milestone is an **angr-backed semantic verifier** that checks whether an AArch64 machine-code fragment is semantically equivalent to an x86-64 fragment. It injects shared symbolic inputs with Claripy, executes both fragments with angr, and proves output equivalence by contradiction: if `guest_output != host_output` is UNSAT, the outputs are equivalent; if SAT, the model is a counterexample.

### Package layout

```
src/angr_rule_learning/
  __init__.py          # re-exports core public API (SemanticVerifier, BatchVerifier, etc.)
  cli.py               # thin argparse wrapper → readers → BatchVerifier → writers

  verification/        # core verifier logic (the "API-first" layer)
    candidate.py       # typed dataclasses: VerificationCandidate, CodeFragment, MemorySpec, etc.
    report.py          # typed dataclasses: VerificationReport, CheckResult
    verifier.py        # SemanticVerifier — orchestrates execution + checks
    batch.py           # BatchVerifier + BatchSummary aggregation
    execution.py       # FragmentExecutor — angr shellcode loading, state creation, stepping
    checks.py          # check_register_pair — Claripy SMT equivalence queries
    config.py          # VerificationConfig — tunables (memory base, max successors)
    errors.py          # VerificationError exception

  io/                  # external JSON/JSONL boundary only
    schema.py          # candidate_from_json(), report_to_json() — strict field validation
    readers.py         # read_candidates(path) — JSON, JSONL, or directory of JSON files
    writers.py         # write_reports_jsonl(), write_summary_json()

  arch/
    registry.py        # angr_arch_name() — maps user-facing arch strings to angr names

  smt/
    solver.py          # fit_width, align_widths, merged_solver — Claripy helpers
```

**Legacy modules** (`models.py`, `verifier.py` at the package root) predate the refactored layout and use a different schema (`init_map` / `def_regs`). New code should use `verification.candidate.VerificationCandidate` and the `io.schema` strict schema, which rejects legacy fields like `init_map`.

### Data flow

1. External JSON/JSONL → `io/readers.py` → `io/schema.py:candidate_from_json()` → `VerificationCandidate`
2. `BatchVerifier.verify_many()` calls `SemanticVerifier.verify()` per candidate
3. `SemanticVerifier.verify()`:
   - Rejects unsupported features early (flag outputs, `may_alias`)
   - Creates angr states via `FragmentExecutor.make_state()`
   - Initializes shared symbolic input registers (Claripy BVS)
   - Executes both fragments via `FragmentExecutor.execute()` (expects exactly one successor)
   - Runs relational checks (currently: `check_register_pair` — width-aligned, contradiction-based)
   - Short-circuits on first failing check
   - Returns a `VerificationReport` with status `pass`, `fail`, or `unsupported`
4. `io/writers.py` serializes reports to JSONL and summary to JSON

### Key design rules

- **JSON is an external boundary.** Pipeline code should construct `VerificationCandidate` objects directly and call `SemanticVerifier.verify()`, not shell out to the CLI.
- **The schema is strict.** `io/schema.py` rejects unknown fields — no silent acceptance of legacy keys.
- **The verifier checks one successor path only.** Multi-successor fragments return `unsupported` with reason `multi_successor_unsupported`.
- **Register widths are normalized.** Guest and host registers may differ in width (e.g., `w0` vs `eax`); the SMT layer zero-extends to the wider width before comparison.
- **Batch summary aggregates** status counts and failure reasons via `collections.Counter`.

### What's implemented vs. planned

Implemented: register output equivalence, memory model types (slots/bindings/accesses/alias), JSON/JSONL I/O, batch CLI, strict schema validation.

Not yet implemented: memory load/store event recording and checks, flag/condition-code equivalence, branch guard equivalence, candidate extraction from compiler debug info, rule generalization.
