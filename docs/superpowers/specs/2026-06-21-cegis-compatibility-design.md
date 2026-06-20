# CEGIS Compatibility Design

## Goal

Make the opt-in `cegis` register-binding strategy preserve the candidate
coverage previously available through `positional`, while retaining semantic
binding synthesis for ambiguous register orderings.

## Binding Modes

`CegisRegisterBindingSolver` remains the single public solver selected by the
`cegis` CLI option. Internally it uses two search modes:

1. Straight-line register-only windows use the existing transfer-assisted
   CEGIS loop. Guest and Host transfer functions are extracted once, finite
   samples constrain selector variables, and the semantic verifier proves the
   first proposed mapping that survives synthesis.
2. Memory and branch windows use verifier-driven selector search. Candidate
   input and output mappings are generated from exact-width, all-different
   domains and checked with the complete `MemorySurface` and branch semantics.
   Search stops at the first verifier-proved mapping.

The solver permits zero inputs or zero outputs when both sides have equal
cardinality. This restores constant-producing rules and permits memory-only or
branch-only observable effects. Internal one-sided temporaries remain outside
the external binding surface and continue to be generalized as typed `tmpN`
placeholders.

## Limits And Fallback

Each Guest/Host input and output surface may contain at most four registers.
The limit bounds selector permutations and verifier calls. Limit failures must
identify the side, role, observed count, and limit.

When CEGIS cannot model or execute a surface, reaches an inconclusive state, or
exceeds the configured register limit, it invokes the existing positional
solver as a heuristic compatibility fallback. A positional result is still
subject to the normal batch semantic verifier before rule generation.

An exhaustive CEGIS search that proves no selector mapping works returns
`register_binding_unsat` and does not fall back. This distinguishes an
unsupported search mechanism from a supported search space with no valid
mapping.

Fallback use is recorded separately from skip diagnostics, including its
reason, so successful compatibility recovery remains observable without being
reported as a skipped window.

## Memory Data Flow

`BindingProblem` carries the complete `MemorySurface`, not only a Boolean.
Verifier-driven proposals are built with that surface so address expressions,
slot initialization, aliases, access kinds, widths, values, and ordering are
part of every proof. Removing the old blanket memory rejection must never
reintroduce the previous empty-`MemorySpec` behavior.

Existing structurally inferred memory register pairs remain constraints for
memory-only surfaces in this change. Generalizing every memory base/index/value
pair into an unconstrained selector domain is a separate extension because it
requires changing the memory-surface representation from paired to side-local
register sets.

## Acceptance Criteria

- `cegis` emits the prior immediate and load/store rules as well as fixed-role
  shift rules in the same `rich_int.c -O1` run.
- Zero-input constant-producing windows are accepted by transfer-assisted
  CEGIS.
- Parsed memory and terminal conditional-branch candidates are checked with
  their complete semantic candidate.
- Search stops after the first passing mapping.
- Unsupported, inconclusive, and over-limit cases use positional fallback and
  record an explicit reason.
- Proven-unsatisfiable mappings do not use positional fallback.
- Ruff, the full pytest suite, and positional/CEGIS end-to-end smoke runs pass.
