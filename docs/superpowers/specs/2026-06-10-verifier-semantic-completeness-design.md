# Verifier Semantic Completeness Design

Date: 2026-06-10

## Context

The current project has a usable verifier MVP for short machine-code fragments.
It supports typed candidates, strict JSON/JSONL I/O, batch verification,
register output equivalence, basic memory load/store event checks, `must_alias`
memory layout, and explicit `may_alias` unsupported reporting.

The next stage should keep the verifier as the project core. Candidate
extraction, rule generalization, rule storage, and coverage reporting remain
important pipeline stages, but they should build on a verifier whose semantic
checks and diagnostics are already reliable.

The verifier should remain ISA-agnostic. It should not hand-code semantics for
specific guest or host instructions. Instruction semantics come from angr. The
verifier defines semantic observation surfaces and uses SMT checks to compare
guest and host behavior.

## Goals

- Strengthen verifier correctness for memory, flags, and terminal branch
  guards.
- Keep JSON/JSONL at the external boundary and keep verifier internals typed.
- Introduce shared verifier kernel concepts so each semantic surface does not
  duplicate solver, counterexample, and diagnostic logic.
- Extend reports from three states to four states: `pass`, `fail`,
  `unsupported`, and `error`.
- Improve batch diagnostics so future coverage analysis can distinguish semantic
  mismatches, unsupported features, and verifier/tool failures.

## Non-Goals

- Do not implement candidate extraction from compiler debug information in this
  stage.
- Do not implement rule generalization, rule storage, or coverage scoring in
  this stage.
- Do not build a general-purpose symbolic execution framework on top of angr.
- Do not support arbitrary path exploration or branch target equivalence.
- Do not implement a full expression language for address bindings.
- Do not treat concrete instruction families as verifier support boundaries.
  Concrete instructions may be used as fixtures, but support is defined by
  semantic surfaces.

## Recommended Architecture

Use a small verifier kernel plus surface-specific checkers.

### Execution Kernel

The execution kernel creates angr states, initializes shared symbolic inputs,
initializes memory, installs event recorders, executes guest and host fragments,
and captures execution outcomes.

It should produce an `ExecutionResult` or equivalent internal structure that can
represent:

- final guest and host states;
- successor shape for each side;
- recorded memory events;
- branch successor guards when present;
- execution exceptions and angr errors.

The execution kernel should not decide semantic equivalence. It provides the
material that semantic checkers need.

### Check Context

Introduce a shared `CheckContext` or equivalent object for one verification run.
It should provide:

- the `VerificationCandidate`;
- guest and host final states;
- input symbols for counterexample extraction;
- memory layout and memory events;
- collected guest and host constraints;
- configuration knobs such as `fail_fast`.

This prevents register, memory, flag, and branch checkers from each rebuilding
solver state and counterexample logic.

### Relation Checker

Introduce a shared relation checker for SMT equivalence of two Claripy
expressions.

The relation checker should:

- align bit-vector widths where appropriate;
- merge guest and host state constraints;
- ask whether `guest_expr != host_expr` is satisfiable;
- return a standard `CheckResult`;
- include counterexample values when a mismatch is satisfiable;
- report errors through the report taxonomy instead of raising bare exceptions.

Register outputs, memory values, explicit flags, and terminal branch guards
should all use this relation checker.

### Semantic Surface Checkers

Each semantic surface should be responsible for extracting its own expressions
or events and then delegating relational checks to the shared relation checker.

The first surfaces are:

- `register`: explicit output register equivalence;
- `memory`: memory event address, width, kind, value, and alias/disjoint checks;
- `flag`: explicit output flag equivalence;
- `branch`: terminal conditional branch guard equivalence.

This avoids an over-general event IR while still keeping SMT and diagnostics
consistent.

## Verification Flow

### Candidate Validation

The schema layer continues to validate external JSON structure only. The
verifier entry point performs semantic capability checks, such as unsupported
flags, unsupported address expressions, unsupported branch shapes, or
inconsistent alias declarations.

Unsupported capabilities should produce `unsupported`, not a generic exception.
Unexpected internal or angr failures should produce `error`.
Malformed typed candidates or contradictory declarations that should have been
rejected before execution should be reported as `error` if they reach the
verifier core. They are not semantic mismatches.

### State Setup

State setup should:

- create guest and host angr states;
- write shared symbolic inputs to paired input registers;
- initialize logical memory slots with shared symbolic content;
- make `must_alias` slots share the same logical object;
- enforce or record `disjoint` layout invariants;
- support memory address bindings in the subset `reg`, `reg + const`, and
  `reg - const`;
- return `unsupported_address_expression` for more complex address bindings.

If alias declarations contradict each other, such as declaring the same slots
both `must_alias` and `disjoint`, setup should stop before execution and report
an `error` reason that identifies the invalid declaration.

### Execution

Straight-line fragments continue to require one successor.

Terminal conditional branch fragments may produce two successors, but only when
the split is caused by the final instruction. The verifier does not explore both
paths or compare branch targets. It only extracts and compares the taken guard.

Unsupported branch shapes should be reported precisely, for example:

- `branch_shape_unsupported`;
- `non_terminal_branch_unsupported`;
- `multi_branch_unsupported`;
- `indirect_branch_unsupported`;
- `unmatched_successor_shape`.

### Surface Check Order

The default check order should be:

1. memory behavior;
2. terminal branch guard;
3. explicit flags;
4. explicit register outputs.

Memory checks run first because memory mismatches often cause later register
mismatches, and reporting the root cause is more useful.

The verifier should collect all check results by default. A
`VerificationConfig.fail_fast` option may stop after the first non-pass result
for performance-sensitive batches.

## Semantic Surface Scope

### Memory

Memory checks should:

- merge guest and host state constraints in address and value SMT queries;
- produce counterexamples for address and value mismatches when possible;
- keep stable reasons for count, kind, width, address, and value mismatches;
- enforce `must_alias` as shared logical memory;
- enforce `disjoint` as non-overlapping logical memory;
- support address bindings in the subset `reg`, `reg + const`, and
  `reg - const`.

More complex memory address expressions are out of scope for this stage and
should return `unsupported_address_expression`.

### Flags

`outputs.flags` should become a supported semantic surface.

The verifier should use an architecture flag registry to map stable external
flag names to Claripy expressions extracted from angr state. The initial scope
should include:

- AArch64 `nzcv.n`, `nzcv.z`, `nzcv.c`, `nzcv.v`;
- x86-64 common integer flags such as `cf`, `zf`, `sf`, and `of`.

Flags such as `af` or `pf` may be returned as `unsupported_flag` if extraction
is unreliable in the first implementation.

The flag checker should not encode instruction semantics directly. It reads the
post-execution state expressions that angr provides and compares them through
the relation checker.

### Terminal Branch Guards

The branch checker supports only a terminal conditional branch.

It should:

- identify straight-line fragments versus terminal conditional branch fragments;
- extract the taken guard expression from each side;
- compare guest and host guards through the relation checker;
- avoid exploring branch targets or validating target address equivalence.

Any non-terminal branch, multiple branch, indirect branch, or unmatched
successor shape should return `unsupported` with a precise reason.

### Registers

Register output equivalence should keep the current external behavior but move
onto the shared relation checker. Counterexample format should match memory,
flag, and branch mismatches.

## Report Taxonomy

Verification reports should use four top-level statuses:

- `pass`: all requested semantic checks passed;
- `fail`: a supported semantic check found a mismatch;
- `unsupported`: the candidate requires a verifier capability that is not
  implemented;
- `error`: angr, environment, or internal verifier failure prevented a semantic
  result.

`fail` means the verifier reached a semantic conclusion. `unsupported` means the
candidate is outside the verifier's current capability boundary. `error` means
the verifier or environment failed and the candidate should not be counted as a
semantic mismatch.

### Check Results

Each `CheckResult` should support:

- `kind`: `register`, `memory`, `flag`, or `branch`;
- `status`: `pass`, `fail`, `unsupported`, or `error`;
- `guest` and `host`: the compared objects or event identifiers;
- `reason`: a stable machine-readable reason;
- `counterexample`: symbolic input assignments when available;
- `metadata`: optional JSON-shaped details such as event index, width, address
  expression, flag name, or branch successor information.

Unsupported and error outcomes should be represented as check results where
possible, not only as top-level strings. Top-level `unsupported_features` may
remain for summary compatibility, but downstream tools should be able to locate
the exact surface that produced the result.

### Batch Summary

Batch summary should continue to aggregate top-level statuses and reasons. It
should also add:

- counts by check kind and status;
- top reasons sorted by frequency;
- enough stable identifiers in detail JSONL for later coverage joins.

Coverage analysis itself is outside this stage, but report data should be ready
for it.

## Milestones

### 1. Verifier Kernel Refactor

Introduce the internal execution/checking structures and migrate register
checks to the shared relation checker.

Acceptance:

- existing register, memory, schema, and CLI tests pass;
- register mismatch counterexamples retain useful input values;
- no report behavior regression except intentional schema additions.

### 2. Memory Correctness Upgrade

Upgrade memory checking to use shared constraints, explicit counterexamples,
binding expression parsing, and real `disjoint` semantics.

Acceptance:

- tests cover address/value/count/kind/width mismatches;
- tests cover `must_alias` and `disjoint`;
- tests cover `reg`, `reg + const`, `reg - const`, and unsupported address
  expressions;
- memory failures include stable reasons and useful metadata.

### 3. Report Taxonomy Upgrade

Add top-level `error`, per-check unsupported/error results, `metadata`, and
batch summary by check kind.

Acceptance:

- batch CLI can distinguish `fail`, `unsupported`, and `error`;
- report JSON is stable and covered by schema tests;
- existing detail JSONL remains JSON-shaped and line-oriented.

### 4. Flag Surface

Add architecture flag extraction and explicit `outputs.flags` verification for
the first stable flag subset.

Acceptance:

- AArch64 NZCV and x86-64 common integer flags can be checked when extractable;
- unsupported flags produce `unsupported_flag`;
- flag mismatches use the shared relation checker and counterexample format.

### 5. Terminal Branch Guard Surface

Add terminal conditional branch guard extraction and equivalence checks.

Acceptance:

- equivalent terminal branch guards pass;
- mismatched terminal branch guards fail with a branch reason;
- non-terminal, multiple, indirect, or unmatched branch shapes return precise
  unsupported reasons;
- no branch target equivalence or path exploration is implemented.

## Testing Strategy

Tests may use concrete AArch64 and x86-64 instructions as fixtures, but test
names and assertions should target semantic surfaces rather than instruction
family support.

Each milestone should include:

- positive equivalence tests;
- negative mismatch tests with counterexamples where applicable;
- unsupported feature tests;
- error classification tests where a controlled error can be induced;
- JSON/JSONL report shape tests when report output changes;
- CLI smoke tests when batch output changes.

Before completion of each milestone, run:

```bash
uv run ruff format
uv run ruff check
uv run pytest
uv run angr-rule-learning verify examples/aarch64_x86_64_batch.jsonl --output /tmp/angr-rule-learning-report.jsonl --summary /tmp/angr-rule-learning-summary.json
```

Third-party Python deprecation warnings from angr dependencies should be tracked
separately from project failures. Normal CLI usage should not emit project
warnings or angr environment noise to stderr.
