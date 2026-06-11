# Liveness-Based Surface Design

Date: 2026-06-11

## Context

The first rule-generalization smoke run over `samples/sources/smoke_int.c`
emits mostly `mov` rules even though the source contains arithmetic, bitwise,
branch, and memory code. Investigation showed that this is not only a sample
quality issue. The extractor currently derives verifier surfaces from raw
instruction read/write metadata and then applies broad filters, especially
around condition-code registers.

Two coarse policies were considered and rejected:

- always compare condition codes;
- always ignore condition codes.

Both are wrong. Whether a register matters depends on liveness. A register write
is part of the window's observable effect only if the written value is live
after the window. This applies equally to general-purpose registers,
callee-saved registers, stack/frame registers, and condition-code registers.

## Core Principle

The candidate semantic surface is liveness-based:

```text
candidate outputs = register writes inside window that are live out of the window
candidate inputs  = live-in values needed to compute those outputs or branch guard
```

Memory effects remain a separate semantic surface. The first implementation may
continue skipping memory windows until memory rule learning is enabled.

Condition-code registers are not special-cased by policy. They are compared only
when they are live and semantically needed:

- dead flag writes from arithmetic instructions are ignored;
- branch guard dependencies are checked when the branch is inside the window;
- external live-in flags make the window non-local and are skipped.

## Goals

- Replace raw read/write surface inference with function-level liveness-based
  surface inference.
- Learn ordinary arithmetic and bitwise register rules when their non-flag
  outputs are live.
- Avoid comparing dead temporary registers and dead condition-code writes.
- Preserve ABI-visible outputs at function exits, including return registers and
  callee-saved preservation state.
- Support terminal conditional branch rules only when their condition inputs are
  defined locally in the same candidate window.
- Reject windows whose semantics depend on externally live condition codes.
- Prevent rule generalization from emitting invalid placeholder mappings for
  two-address host instructions.

## Non-Goals

- Do not implement memory rule learning in this stage.
- Do not implement immediate generalization.
- Do not change the candidate JSON schema.
- Do not change verifier semantics for explicit `output_flags`.
- Do not infer interprocedural liveness across calls.
- Do not model complete platform ABI behavior beyond the initial exit live-out
  seed.

## Function-Level CFG Liveness

Liveness should be computed at function scope, not only inside one basic block.
The implementation should build a conservative function CFG and run backward
dataflow until a fixed point.

For each instruction, record:

```text
live_in
live_out
```

For an instruction:

```text
live_in  = reads ∪ (live_out - writes)
live_out = union(live_in of successor instructions)
```

The sets operate over canonical register alias families, not raw register names.
For example:

- AArch64 `w0` and `x0` are one family;
- x86-64 `al`, `ax`, `eax`, and `rax` are one family;
- AArch64 `nzcv` is one condition-code family;
- x86-64 `rflags` and named x86 flags such as `zf` belong to one condition-code
  family when they appear in metadata.

The concrete register name still matters later for verifier and rule output
widths. Liveness uses alias families only to determine whether definitions and
uses overlap.

## CFG Construction

The current `BasicBlockBuilder` splits functions at control-flow instructions
but does not store successor edges. The liveness implementation should add a
small CFG helper rather than overloading unrelated models.

Recommended module:

```text
src/angr_rule_learning/extraction/liveness.py
```

The helper should:

- index blocks and instructions by address;
- add fallthrough successors for ordinary blocks;
- add branch-target successors for direct conditional branches when the target
  address can be parsed from disassembly text;
- add both branch target and fallthrough successors for conditional branches;
- add only the target successor for direct unconditional branches;
- add no normal successor for returns;
- conservatively mark unresolved indirect control flow as unsupported for
  liveness-sensitive extraction.

The first implementation can keep call-containing windows unsupported through
the existing control-flow filter. Calls do not need full interprocedural
liveness yet.

## ABI Exit Live-Out Seed

Function exits need explicit live-out seeds. Without ABI seeds, return values
and callee-saved preservation state look dead at `ret`.

Initial AArch64 exit seed:

- return family: `x0` / `w0`;
- callee-saved families: `x19`-`x28`, `fp/x29`, `lr/x30`, `sp`.

Initial x86-64 SysV exit seed:

- return family: `rax` / `eax`;
- callee-saved families: `rbx`, `rbp`, `r12`-`r15`, `rsp`.

These are liveness seeds, not automatic rule outputs. A register appears in a
candidate output only if the window writes that alias family and the family is
live after the window.

Callee-saved registers are ABI-visible preservation state. If a window writes a
callee-saved family and the value remains live out, the verifier should see that
effect. If a larger window restores the value before its end, the restored
state should not force an intermediate dead write into the candidate output.

## Window Surface Inference

For each candidate window, use the liveness state at the end of the window:

```text
window_live_out = live_out(last_instruction)
window_defs     = union(register writes in window)
semantic_outputs = window_defs ∩ window_live_out
```

Then compute needed inputs by walking the window backward:

1. Initialize `needed` with `semantic_outputs`.
2. If the window ends in a terminal conditional branch, add the branch guard
   dependency family, usually `nzcv` or `rflags`, to `needed`.
3. Walk instructions backward.
4. For each instruction whose writes intersect `needed`, remove those written
   families from `needed` and add the instruction's read families.
5. At the start of the window, remaining `needed` families are live-in inputs.

If `needed` contains a condition-code family at the start of the window, skip
the candidate with:

```text
external_live_condition_code_dependency
```

This rejects windows like a standalone `jcc` or `b.cond` whose guard depends on
flags defined outside the window.

If a terminal conditional branch's guard is defined inside the same window, keep
the candidate eligible for the existing branch guard equivalence check.

## Register Pairing

The extractor should infer guest and host surfaces separately, then pair
register families conservatively.

Initial pairing policy:

- output counts must match, otherwise skip with `ambiguous_register_surface`;
- input counts must match, otherwise skip with `ambiguous_register_surface`;
- pair any read family that is also an output family on both sides first;
- pair remaining inputs in their stable window-slice order;
- pair outputs in stable definition order.

This supports x86-64 two-address instructions, where a host register can be
both input and output.

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

## Branch Rules

Terminal conditional branch rules remain verifier-backed:

- both sides must end in supported conditional branch instructions;
- branch guard dependencies must be defined within the window;
- windows with external live condition-code dependencies are skipped;
- branch guard equivalence continues to use the existing SMT verifier path.

This allows local compare-and-branch windows:

```text
cmp eax, ecx
jl label
```

and:

```text
subs w8, w0, w1
b.lt label
```

but rejects a standalone branch whose flags are live-in from earlier code.

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

The verifier should not change for ordinary register rules. It checks only the
surfaces present in `VerificationCandidate`:

- ordinary output registers;
- explicit output flags;
- memory accesses;
- terminal branch guards.

The extractor is responsible for choosing the correct liveness-based surfaces.
If a condition-code value is dead, it is absent from the candidate. If it is a
branch guard dependency, the branch verifier checks the guard equivalence. If it
is live-in from outside the window, the extractor skips the candidate.

## Diagnostics

Add or use skip reasons that explain liveness-driven pruning:

- `external_live_condition_code_dependency`;
- `ambiguous_register_surface`;
- `unsupported_liveness_cfg`;
- `no_verifiable_surface`.

Extraction diagnostics should continue reporting:

- window sizes;
- emitted surface kinds;
- skipped reason counts;
- verified pass counts.

## Testing Strategy

Unit tests should cover:

- alias family normalization for AArch64 `w0/x0` and x86 `eax/rax`;
- ABI exit seeds keep return registers live at function exits;
- ABI exit seeds keep callee-saved families live at function exits;
- dead `rflags` writes from arithmetic do not become outputs;
- dead `nzcv` writes from arithmetic do not become outputs;
- live arithmetic output registers remain candidate outputs;
- standalone conditional branches with external live flags are skipped as
  `external_live_condition_code_dependency`;
- local compare-and-branch windows remain branch candidates;
- x86 two-address input/output aliases pair with matching guest aliases;
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
- branch rules, if emitted, come from windows with local condition-code
  definitions.
