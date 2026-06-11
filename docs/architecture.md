# Architecture

`angr-rule-learning` is being rebuilt as a rule-learning pipeline with explicit
data boundaries and independently testable components. The current repository
implements the verifier-first core; candidate extraction, rule generalization,
rule storage, and coverage evaluation are planned around the same data model.

## Pipeline Shape

The intended full pipeline is:

```text
Compiler/Debug Info
  -> Candidate Extraction
  -> Semantic Verification
  -> Rule Generalization
  -> Rule Store
  -> Coverage Evaluation
```

Only the semantic verification stage is implemented today. The existing CLI
accepts candidate JSON/JSONL directly so verifier work can proceed before source
mapping and candidate extraction are rebuilt.

## Package Structure

```text
src/angr_rule_learning/
  cli.py
  arch/
    registry.py
    flags.py
  io/
    readers.py
    schema.py
    writers.py
  smt/
    solver.py
  verification/
    candidate.py
    config.py
    execution.py
    context.py
    relations.py
    checks.py
    memory.py
    memory_checks.py
    flags.py
    branches.py
    report.py
    batch.py
    verifier.py
```

The package boundaries are:

- `arch`: maps project architecture names to angr names and extracts
  architecture-specific flag expressions.
- `io`: converts strict JSON dictionaries into typed verifier models and writes
  report/summary JSON.
- `smt`: holds shared bit-vector width helpers used by relation checks.
- `verification`: owns the verifier data model, execution setup, semantic
  checks, report model, and batch API.
- `cli.py`: provides a thin command-line wrapper over `BatchVerifier`.

## Data Flow

```text
candidate JSON/JSONL
  -> io.readers.read_candidates()
  -> io.schema.candidate_from_json()
  -> verification.BatchVerifier.verify_many()
  -> verification.SemanticVerifier.verify()
  -> io.schema.report_to_json()
  -> io.writers.write_reports_jsonl()
  -> io.writers.write_summary_json()
```

The CLI is intentionally outside the verifier core. Future pipeline code should
construct `VerificationCandidate` values directly, call `SemanticVerifier` or
`BatchVerifier`, and consume `VerificationReport` values without depending on
subprocess execution.

## Verifier Core

The verifier compares semantic surfaces rather than instruction families. angr
provides lifting and symbolic execution, Claripy provides symbolic expressions
and solver queries, and `RelationChecker` performs equivalence checks by
contradiction:

```text
guest_expr != host_expr is UNSAT  => equivalent for that check
guest_expr != host_expr is SAT    => counterexample found
```

The verifier currently checks:

- register output pairs;
- memory access count, kind, width, address, and value;
- explicit flag output pairs for the stable flag subset;
- terminal conditional branch taken-guard equivalence.

Detailed verifier behavior and support boundaries are documented in
[Verifier](verifier.md).

## Candidate Boundary

The request boundary is JSON-shaped and intentionally strict. All top-level
fields are required, unknown fields are rejected, and parsed payloads become
frozen dataclass models under `verification.candidate`.

This gives later pipeline stages a stable contract:

- candidate extraction emits structured candidates;
- verification emits structured reports;
- rule generalization consumes successful reports;
- coverage evaluation can aggregate report summaries and rejected features.

The current JSON fields and report shape are documented in
[Candidate Format](candidate-format.md).

## Status And Diagnostics

Every verification report has one of four top-level statuses:

- `pass`: all requested checks passed;
- `fail`: the verifier found a semantic counterexample;
- `unsupported`: the candidate requires a known but unsupported verifier
  capability;
- `error`: the verifier itself failed unexpectedly.

`unsupported` is an expected pipeline outcome and should be tracked as coverage
loss. `error` indicates a verifier bug, environment issue, or uncategorized
failure that should be investigated.

## Extension Points

Near-term extensions should preserve the existing verifier API and add new
semantic surfaces behind focused modules:

- precondition parsing and SMT constraint injection;
- direct branch target mapping checks;
- indirect branch target expression equivalence;
- richer memory alias constraints;
- candidate extraction from compiler debug/source mappings;
- rule generalization and storage;
- coverage reporting against an external rule table.

When adding a new capability, prefer a typed model change in
`verification.candidate`, a small checker module, schema updates in `io`, and
focused tests that exercise both Python API and JSON/CLI behavior.
