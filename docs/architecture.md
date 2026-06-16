# Architecture

`angr-rule-learning` is a rule-learning pipeline with explicit data boundaries
and independently testable components. The repository implements the verifier
core, single-source candidate extraction, and verified text rule generation.
Rule storage and coverage evaluation remain planned.

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

The extractor package (`src/angr_rule_learning/extraction/`) implements the
first two stages:

```text
single C source
  -> extraction.ExtractionPipeline
  -> candidate JSONL
  -> verification.BatchVerifier
```

The pipeline compiles source to guest/host objects, extracts functions and
debug information, builds alignment regions, mines bounded semantic windows,
infers verifier surfaces, and emits candidate JSONL compatible with the
existing verifier boundary.

With `--verify --rules-output`, the pipeline also runs verification and
produces plain text rules with typed register placeholders. The existing CLI
accepts candidate JSON/JSONL directly so verifier work can proceed
independently of extraction.

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
  extraction/
    config.py
    build.py
    object.py
    blocks.py
    align.py
    windows.py
    surfaces.py
    memory_operands.py
    memory_surfaces.py
    liveness.py
    diagnostics.py
    emit.py
    pipeline.py
  analysis/
    skip_patterns.py
  rules/
    registers.py
    memory.py
    generalize.py
    writer.py
```

The package boundaries are:

- `arch`: maps project architecture names to angr names and extracts
  architecture-specific flag expressions.
- `io`: converts strict JSON dictionaries into typed verifier models and writes
  report/summary JSON.
- `smt`: holds shared bit-vector width helpers used by relation checks.
- `verification`: owns the verifier data model, execution setup, semantic
  checks, report model, and batch API.
- `extraction`: compiles source, extracts functions and debug information,
  builds alignment regions, mines bounded windows, infers verifier surfaces,
  and orchestrates the source-to-candidate pipeline.
- `rules`: classifies registers, generalizes verified extraction windows into
  typed placeholder rules, and writes plain text rule output with diagnostics.
- `analysis`: read-only diagnostics/observability tools.  Reuses extraction
  components to aggregate skip patterns but never participates in candidate
  extraction, verification, or rule generation decisions.  Exposed via the
  `diagnose-skips` CLI subcommand.
- `cli.py`: provides a thin command-line wrapper over `BatchVerifier`,
  `ExtractionPipeline`, and `SkipPatternAnalyzer`.

## Data Flow

```text
single C source
  -> extraction.ExtractionPipeline
     -> WindowMiner (enumerate instruction windows)
     -> SurfaceInferer
        -> memory_surfaces.infer_memory_surface (AddressExpr pairing)
        -> liveness.WindowSurfaceInferer (register/liveness surface)
     -> VerificationCandidate values + candidate JSONL
  -> verification.BatchVerifier
     -> addressing.parse_address_binding (AddressExpr for memory bindings)
  -> VerificationReport values
  -> rules.RuleGeneralizer
     -> rules.registers (register classification + generalization)
  -> plain text rules + rule diagnostics
```

### Memory Surface Inference

The extractor explicitly distinguishes "no memory access" from "memory access
exists but is unsupported."  Structured memory operand parsing
(`memory_operands.extract_memory_operands`) parses supported AArch64 and x86-64
memory addressing forms into a shared `AddressExpr` model.  The surface inferer
checks for broader memory access patterns via `has_any_memory_access` and emits
`unsupported_memory_surface` in diagnostics when memory access is present but
cannot be modelled.  This prevents windows with unsupported memory forms
(push/pop, ldp/stp, writeback, extension-indexed) from being silently treated
as register-only candidates.

Address base and index registers are included in candidate `input_registers`
so rule generalization can emit typed register placeholders for them.

Extraction diagnostics preserve coarse skip counters in `skip_reasons`. For
broad categories that hide actionable causes, the pipeline also emits
`skip_details`, keyed by the same coarse reason. For example,
`unsupported_memory_surface` may contain `memory_access_count_mismatch`,
`memory_width_mismatch`, or `unparsed_memory_access`; the sum of those detail
counts should match the corresponding coarse reason when every skip path in
that category reports a detail.

Frame-relative stack memory is treated specially. When AArch64 stack/frame
registers (`sp`, `x29`, `fp`) align with x86-64 stack/frame registers (`rsp`,
`rbp` and narrower aliases), extraction does not model the base registers as
equal input values. Instead, memory bindings carry the effective address
expressions and the verifier assigns frame base witnesses that make consistent
slots alias across ISAs. This preserves normal equality semantics for ordinary
address registers while allowing common `sp + offset` versus `rbp - offset`
stack-slot rules to verify.

Store-immediate surfaces are rejected at extraction time. Until the verifier
supports explicit immediate value bindings, a store pair where either side
uses an immediate value (e.g. `mov dword ptr [rbp-4], 3`) returns
``store_value_immediate_unsupported`` rather than emitting a bogus register
input.

Sign-extension memory loads (`ldrsw` for AArch64, `movsxd` for x86-64) are
parsed as 32-bit memory reads. The verifier compares output register
expressions after execution, so the memory surface only needs the read address
and width; the sign extension is checked via the output register relation.

Still unsupported memory forms include full prologue/epilogue modelling
(`push/pop` versus `stp/ldp`) and x86 read-modify-write arithmetic memory
operands. These remain separate planned extensions.

Rule generation consumes `WindowPair + VerificationCandidate + VerificationReport`
and produces text rules with typed register placeholders such as `i32_reg1`
in each ISA's native assembly syntax.  Memory rules keep the original operand
text and generalize only registers and shared displacement immediates.

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

### Skip Pattern Analysis

The `diagnose-skips` CLI is a read-only observability tool for large skip
categories. It reuses extraction alignment and window enumeration, classifies
selected memory skip details, and writes pattern reports for
`unparsed_memory_access` and `one_sided_memory_access`. These reports are used
to decide whether the next improvement should extend memory operand parsing,
refine window pairing, or add a stack/frame abstraction. The analyzer must not
change candidate emission, verification, or rule generation behavior.

## Extension Points

Near-term extensions should preserve the existing verifier API and add new
semantic surfaces behind focused modules:

- precondition parsing and SMT constraint injection;
- direct branch target mapping checks;
- indirect branch target expression equivalence;
- richer memory alias constraints (may_alias, multi-slot memory surfaces);
- richer extraction beyond single-source smoke inputs;
- generalized memory rules for complex addressing (push/pop, ldp/stp, writeback);
- generalized branch-target rule output;
- rule store and coverage reporting against an external rule table.

When adding a new capability, prefer a typed model change in
`verification.candidate`, a small checker module, schema updates in `io`, and
focused tests that exercise both Python API and JSON/CLI behavior.
