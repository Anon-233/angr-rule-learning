# Semantic Verifier

The semantic verifier is the current core of `angr-rule-learning`. It receives a
paired guest/host fragment, initializes shared symbolic inputs, executes both
fragments with angr, and checks requested semantic surfaces with Claripy SMT
queries.

The initial target pair is AArch64 integer code to x86-64 integer code. The
implementation is not instruction-family based: instruction semantics come from
angr, while this project decides which observed expressions and events must be
related.

## Verification Flow

`SemanticVerifier.verify()` performs these steps:

1. Reject known unsupported candidate-level features, such as non-empty
   preconditions or `may_alias`.
2. Create angr shellcode states for guest and host fragments.
3. Initialize paired input registers with the same Claripy symbols.
4. Initialize memory slots and address bindings.
5. Install memory event breakpoints.
6. Execute each fragment for its declared instruction count.
7. Classify unsupported control-flow shapes.
8. Build a `CheckContext` containing states, symbols, constraints, memory layout,
   and recorded memory events.
9. Run memory, flag, branch, and register checks.
10. Return a `VerificationReport`.

Unexpected exceptions are converted into `error` reports with reason
`verifier_internal_error`. Known verifier limitations should return
`unsupported`, not `error`.

## SMT Relation Checks

Most semantic checks use `RelationChecker.check_equal()`. It aligns expression
widths, then asks whether a mismatch is satisfiable:

```text
guest_expr != host_expr is UNSAT  => pass
guest_expr != host_expr is SAT    => fail with counterexample
```

The solver receives constraints from both executed states. Counterexamples are
reported over the shared input symbols.

## Supported Semantic Surfaces

### Registers

`outputs.registers` lists guest/host register pairs. Each pair is read from the
post-execution states and compared with the shared SMT relation checker.

Register names are normalized to lowercase and must be known to angr for the
corresponding architecture.

### Memory

Memory checking is slot-based. A candidate declares memory slots, address
bindings, expected access events, and alias declarations.

Supported memory behavior:

- symbolic slot initialization;
- `reg`, `reg + const`, and `reg - const` address bindings;
- read and write access event recording;
- access count, kind, width, guest address, host address, and value checks;
- `must_alias` slots sharing one base;
- `disjoint` slots receiving separate layout bases;
- `may_alias` reported as `unsupported_may_alias`.

Known memory limits:

- slot initial contents are symbolic only;
- address bindings do not support full expressions such as `x1 + x2`;
- `disjoint` is represented by layout choice, not explicit SMT non-overlap
  constraints;
- preconditions cannot yet restrict pointer ranges or alias cases.

### Flags

`outputs.flags` lists guest/host flag pairs. The first stable subset is:

- AArch64 `nzcv.n`, `nzcv.z`, `nzcv.c`, `nzcv.v`;
- x86-64 `cf`, `zf`, `sf`, `of`.

Unsupported or architecture-mismatched flag names return `unsupported_flag`.
Flag expression correctness depends on angr's lifting for the executed
instruction sequence.

### Branches

Branch support is intentionally narrow:

- straight-line fragments are supported;
- fragments ending in one conditional branch are supported by comparing the
  taken-branch guard expressions;
- memory events and explicit flag outputs before the terminal branch are still
  checked;
- register outputs for branch fragments are reported as
  `branch_register_outputs_unsupported`.

Unsupported branch/control-flow shapes include:

- non-terminal control flow;
- terminal direct unconditional branches, such as AArch64 `b` or x86-64 `jmp`;
- terminal indirect branches, such as AArch64 `br x0` or x86-64 `jmp rax`;
- `ret`, `call`, syscall, interrupt, and unmatched successor shapes;
- more than two successors.

These cases are expected to return `unsupported`, commonly with one of:

- `non_terminal_branch_unsupported`;
- `unconditional_branch_unsupported`;
- `branch_shape_unsupported`;
- `multi_branch_unsupported`.

This branch boundary affects rule-learning coverage. Semantically valid rules
that require branch target equivalence are rejected today. Future work should
add separate checks for direct branch target mapping and indirect branch target
expression equivalence; those are different from conditional guard comparison.

## Report Statuses

The verifier emits four top-level statuses:

- `pass`: every requested check passed;
- `fail`: at least one requested semantic relation was disproved;
- `unsupported`: the candidate requires a known unsupported feature;
- `error`: the verifier failed unexpectedly.

Overall status priority is:

```text
error > unsupported > fail > pass
```

`unsupported` should be treated as coverage loss in the rule-learning pipeline,
not as a verifier crash.

## Current Coverage Risks

The current verifier can validate many short integer register/memory rules, but
coverage is limited by:

- unsupported preconditions;
- unsupported branch target equivalence;
- limited memory address expression parsing;
- lack of explicit SMT alias/non-overlap constraints for disjoint regions;
- the first stable subset of flag extraction;
- dependence on angr's architecture lifting quality.

These limits should be visible in batch summaries through `unsupported` reports
and machine-readable reason counts.
