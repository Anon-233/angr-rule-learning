# Condition Code Policy Design

Date: 2026-06-11

## Context

The first rule-generalization smoke run over `samples/sources/smoke_int.c`
emits mostly `mov` rules. The sample contains arithmetic, bitwise, branch, and
memory code, so the narrow rule output is not caused by the source input alone.

The immediate cause is extraction-time filtering. `SurfaceInferer` currently
treats any `nzcv` or `rflags` read/write as `unsupported_flag_surface`. On
x86-64, arithmetic and bitwise instructions commonly write `rflags`, so
register-only arithmetic windows are discarded before the verifier sees them.

The desired backend rule table does not need condition-code side effects for
ordinary integer rules because backend code generation has separate condition
code handling. However, terminal conditional branch rules are different:
branches consume condition codes, and learning them without checking the local
condition-code definition can produce context-dependent rules that are unsafe to
reuse.

## Goals

- Learn ordinary integer arithmetic and bitwise register rules even when source
  or target instructions write condition-code registers.
- Keep condition-code side effects out of ordinary rule surfaces.
- Allow terminal conditional branch rules only when their condition-code
  dependency is local to the candidate window.
- Continue using SMT verification for branch guard equivalence when learning a
  branch rule.
- Prevent rule generalization from emitting invalid placeholder mappings for
  two-address host instructions.
- Keep the first implementation scoped to register and branch surfaces; memory
  rule learning remains separate.

## Non-Goals

- Do not model condition-code outputs for ordinary arithmetic rules.
- Do not emit flag-output rules in this stage.
- Do not learn branch rules whose condition-code definition is outside the
  candidate window.
- Do not implement memory rules.
- Do not implement immediate generalization.
- Do not change the candidate JSON schema.
- Do not change verifier semantics for explicit `output_flags`.

## Policy

The rule learner uses two condition-code policies depending on rule shape.

### Register Rules

For ordinary register-output rules, condition codes are ignored:

- `nzcv` and `rflags` are removed from inferred input registers.
- `nzcv` and `rflags` are removed from inferred output registers.
- `nzcv` and `rflags` are not added to `output_flags`.
- `nzcv` and `rflags` are not added to `clobbers`.
- condition-code writes do not cause extraction skips.

The verifier still checks the requested ordinary register outputs. This allows
rules such as:

```text
Guest:
	add w8, w0, w8
Host:
	add eax, ecx
```

when the candidate maps `w8/eax` as the output and maps the two source operands
as inputs.

### Branch Rules

For terminal conditional branch rules, condition codes are part of the branch
guard dependency and must be handled explicitly:

- A branch candidate must end in a supported conditional branch on both sides.
- If a terminal conditional branch reads `nzcv` or `rflags`, the same candidate
  window must include a local instruction that writes the corresponding
  condition-code register.
- If the condition-code definition is not in the candidate window, skip the
  candidate with `external_condition_code_dependency`.
- If the local condition-code definition exists, keep the candidate eligible for
  the existing verifier branch guard equivalence check.
- Condition-code registers are still not emitted as rule outputs.

This keeps `cmp + jcc`, `test + jcc`, `subs + b.cond`, and similar local
compare-and-branch windows possible, while rejecting branch windows whose guard
depends on flags produced earlier by unrelated code.

## Extraction Changes

`SurfaceInferer` should distinguish ordinary register surfaces from terminal
branch surfaces before flag filtering.

For register surfaces:

- collect reads and writes from instruction register metadata;
- remove `nzcv` and `rflags` from the read/write sets;
- build `input_registers` and `output_registers` from the remaining registers;
- do not set `output_flags`;
- do not set flag clobbers.

For branch surfaces:

- identify terminal conditional branches using the existing branch mnemonic
  helpers;
- detect whether the terminal branch reads a condition-code register;
- require at least one earlier instruction in the same side of the window to
  write that condition-code register;
- keep the candidate if both sides satisfy the local dependency requirement;
- skip with `external_condition_code_dependency` if either side reads flags
  without a local flag definition.

The extraction diagnostics should record:

- normal register rule emission under the existing `register` surface kind;
- branch rule emission under the existing `branch` surface kind;
- `external_condition_code_dependency` skips for incomplete branch windows.

## Register Pairing

Allowing arithmetic candidates exposes x86-64 two-address instructions, where a
host register can be both an input and the output. The extractor should pair
read registers with output alias awareness:

- first pair any read register that is also an output register on both guest and
  host sides;
- then pair the remaining reads in their existing order;
- if counts still differ, skip with `ambiguous_register_surface`.

Example:

```text
Guest: add w8, w0, w8
Host:  add eax, ecx
```

should infer:

```text
outputs: w8/eax
inputs:  w8/eax, w0/ecx
```

This keeps the in-place host operand aligned with the guest output/input
register.

## Rule Generalization

The rule generalizer must reject conflicting placeholder assignments. Repeated
identical register pairs are valid, but a physical register cannot silently
join two different semantic placeholders.

Valid:

```text
outputs: w8/eax
inputs:  w8/eax, w0/ecx
```

emits:

```text
Guest:
	add i32_reg1, i32_reg2, i32_reg1
Host:
	add i32_reg1, i32_reg2
```

Invalid:

```text
outputs: w8/eax
inputs:  w0/eax, w8/ecx
```

must skip with `unsupported_rule_shape` because `eax` would need to represent
both `w8` and `w0`.

## Verifier Behavior

The verifier should not change for ordinary register rules. It already checks
only the surfaces present in `VerificationCandidate`:

- ordinary output registers;
- explicit output flags;
- memory accesses;
- terminal branch guards.

Because extraction removes implicit condition-code registers from ordinary
register candidates, arithmetic flag side effects are ignored naturally.

For branch candidates, continue using the existing terminal branch guard
equivalence check. The extraction stage is responsible for rejecting incomplete
condition-code dependencies before verification.

## Testing Strategy

Unit tests should cover:

- arithmetic windows that only write `rflags` remain candidate-eligible;
- arithmetic windows that write `nzcv` remain candidate-eligible;
- inferred ordinary register surfaces exclude `nzcv` and `rflags`;
- terminal conditional branches that read flags without a local flag definition
  are skipped as `external_condition_code_dependency`;
- terminal conditional branches with local flag definitions are emitted as
  branch candidates;
- x86 two-address read/output aliases are paired with the matching guest
  read/output alias;
- conflicting rule placeholder mappings are rejected;
- alias-compatible two-address arithmetic emits a valid generalized rule.

Pipeline smoke should run `extract --verify --rules-output` on
`samples/sources/smoke_int.c` and assert that, when the local toolchain emits any
rules, the output contains at least one arithmetic mnemonic such as `add`,
`sub`, `xor`, `eor`, `and`, `orr`, or `or`.

Manual inspection should confirm:

- concrete registers such as `w0`, `w8`, `eax`, and `ecx` do not leak into
  emitted generalized rules;
- `rules_diagnostics.json` has nonzero `rules_emitted`;
- branch rules, if emitted, come from local condition-code definition windows.
