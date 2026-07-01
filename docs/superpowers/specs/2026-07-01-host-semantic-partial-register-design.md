# Host-Semantic Partial Register Design

## Context

The IR-kernel constructive pipeline currently verifies all stable kernels, but
some verified candidates cannot be emitted as rules.  A major remaining class is
partial-register and zero-extension semantics on x86-64:

- `and_const_i32/i64` lowers to `movzx eax, dil/di` on x86-64.
- `icmp_eq` and `icmp_slt` lower to `xor eax, eax; cmp ...; setcc al`.
- x86-64 fixed-role shift counts use `cl`, while AArch64 shift counts use a
  normal register operand.

The existing rule model can express whole semantic registers
(`i32_regN`, `i64_regN`), same-family width views (`reg64(i32_regN)`), and a
Guest physical view for fixed-role shift counts (`lo8(guest.rcx)`).  It cannot
yet express that an instruction reads or writes only a bit slice of a semantic
register, nor that an instruction zero-extends or sign-extends a slice.

The project direction is now explicit: **Guest rules should remain close to
native matchable ISA text, while Host rules may contain richer semantic operand
expressions**.  This keeps source matching practical and gives the translator
enough information to generate correct Host code.

## Goals

- Add a rule-level way to express Host-side bit-slice reads and writes.
- Add a rule-level way to express zero/sign-extension where the target ISA
  instruction requires it or where a pseudo operand must state it explicitly.
- Preserve the current `save`/`restore`, `reg64(...)`, and
  `lo8(guest.rcx)` behavior.
- Recover at least these stable kernel families:
  - `kernel_and_const_i32`
  - `kernel_and_const_i64`
  - `kernel_icmp_eq_i32`
  - `kernel_icmp_slt_i32`
  - the corresponding reverse-direction forms when the rule is semantically
    representable.
- Keep verifier soundness: no rule may claim a full register output is defined
  by a partial write unless the surrounding Host sequence defines the remaining
  bits.

## Non-Goals

- Solving magic-constant division/remainder rules.
- Solving general immediate-expression inference.
- Supporting arbitrary SIMD/vector partial-lane expressions.
- Making Guest rule text pseudo-ISA.  Guest-side semantic views are allowed only
  for explicit source-ISA physical views such as `lo8(guest.rcx)`.
- Adding a sidecar metadata format for this phase; the rule text remains the
  primary artifact.

## Rule Expressions

The rule AST should support the following operand expressions:

```text
lo8(i32_reg1)
lo16(i32_reg1)
lo32(i64_reg1)
zext32(lo8(i32_reg1))
sext32(lo8(i32_reg1))
lo8(guest.rcx)
```

`loN(x)` means the low `N` bits of `x`.  For first-stage support, only low-bit
slices are required; high-byte x86 names such as `ah`/`ch` remain unsupported
unless a later design introduces `bits8_15(...)` or equivalent syntax.

`zextM(x)` means zero-extend `x` to `M` bits.  `sextM(x)` means sign-extend
`x` to `M` bits.

`loN(guest.<family>)` is a physical Guest register-family view.  It is not a
general semantic placeholder and is not alpha-renumbered.  It exists for cases
where the source ISA has an architecturally fixed input location, such as x86
`cl`.

## Host-Only Policy

General semantic expressions are Host-only:

- Host may contain `loN(iM_regK)`.
- Host may contain `zextM(...)` and `sextM(...)`.
- Host may contain `loN(guest.<family>)`.
- Guest should not contain `loN(iM_regK)`, `zextM(...)`, or `sextM(...)` in the
  first phase.

The exception is native Guest assembly that already names a partial physical
register, for example `shl i32_reg1, cl`.  That remains normal Guest match text.
The corresponding Host side may refer to the value as `lo8(guest.rcx)`.

## Read-View Semantics

Read-view support handles source operands such as x86 `dil`, `di`, and `al`
when their register family is already bound to a semantic placeholder.

Example target output:

```text
Guest:
    and i32_reg1, i32_reg2, #0xff
Host:
    movzx i32_reg1, lo8(i32_reg2)
```

Here `movzx` carries the zero-extension operation in the ISA mnemonic, while
`lo8(i32_reg2)` identifies the bit slice being read.  A fully explicit internal
AST may represent the same source as `zext32(lo8(i32_reg2))`, but the text form
can remain native enough for Host code generation as long as the instruction
semantics are unambiguous.

For `movzx eax, di`, the output should be:

```text
Host:
    movzx i32_reg1, lo16(i32_reg2)
```

## Write-View Semantics

Write-view support handles destination operands such as x86 `al`.

Example target output:

```text
Guest:
    cmp i32_reg2, i32_reg3
    cset i32_reg1, eq
Host:
    xor i32_reg1, i32_reg1
    cmp i32_reg2, i32_reg3
    sete lo8(i32_reg1)
```

`sete lo8(i32_reg1)` alone is not enough to define `i32_reg1`.  It is valid only
because the preceding `xor i32_reg1, i32_reg1` defines all bits of the output,
and `sete` then overwrites the low 8 bits.  The generalizer must reject a rule
that maps `al` directly to a full `i32_regN` output without such a full-width
producer.

The same rule applies to other partial writes: a partial write may contribute to
a full output only when a same-side def-use check proves the non-written bits are
already defined by the Host sequence.

## Architecture Capability Requirements

The architecture layer already provides register families and bit ranges.  This
feature needs one additional semantic distinction:

- whether writing a register defines only that bit range or also defines the
  wider family value.

For x86-64:

- Writing `al`, `ax`, or another 8/16-bit sub-register writes only that slice.
- Writing `eax` zero-extends into `rax`.
- Writing `rax` defines the full 64-bit family.

For AArch64:

- Writing `wN` zero-extends into `xN`.
- Writing `xN` defines the full 64-bit family.

These facts should be exposed through architecture capability helpers rather
than embedded in rule generalization.

## Generalizer Changes

The generalizer should replace physical partial-register tokens on the Host
side using the mapped semantic family:

1. Find the physical token's architecture family and bit range.
2. Find a mapped register in the same family.
3. If the physical token is a strict low slice of the mapped placeholder,
   replace it with `loN(<placeholder>)`.
4. For known zero-extension instructions such as `movzx`, allow the source view
   directly.
5. For partial-write destinations, require the full-output coverage check before
   accepting the rewrite.

This should be implemented as a focused module next to the existing
`rules/register_views.py` logic rather than as scattered regex replacement.

## Verifier Changes

Verifier input remains unchanged: it verifies concrete Guest and Host assembly
fragments before rule emission.  The new expressions are rule-output semantics,
not verifier input syntax.

Verifier-related work is still needed in two places:

- The existing register initialization and output comparison must continue to
  model sub-register equality correctly, including x86 `eax` zero-extension and
  AArch64 `wN` zero-extension.
- Generalizer tests should use verifier-passing candidates for end-to-end
  confidence, but the semantic expression syntax itself is validated at the AST
  and rule-generalization layers.

## Testing Plan

Add focused unit tests for:

- AST parse/write roundtrip for `lo8(i32_reg1)`, `lo16(i32_reg1)`,
  `zext32(lo8(i32_reg1))`, and `lo8(guest.rcx)`.
- Alpha-equivalence for semantic expressions: placeholder IDs can be
  canonicalized, but `lo8` and `lo16` are not equivalent, and
  `lo8(guest.rcx)` is not equivalent to `lo8(guest.rdx)`.
- Host read-view rewriting: `movzx eax, dil` becomes
  `movzx i32_reg1, lo8(i32_reg2)`.
- Host write-view rewriting: `sete al` becomes `sete lo8(i32_reg1)` only when a
  prior full-width Host definition exists.
- Rejection of unsafe partial-output rules without a full-width producer.

Add pipeline regressions asserting that stable kernel output now includes rules
for the `and_const` and `icmp` families listed in the goals, without increasing
verifier internal errors.

## Risks and Boundaries

The largest risk is accidentally treating partial writes as full writes.  The
first implementation should reject ambiguous cases aggressively.

Another risk is overloading rule text with expressions the downstream
translator cannot parse.  This is acceptable only because Host-side rule text
is already semantic-enhanced (`save`, `restore`, `reg64(...)`,
`lo8(guest.rcx)`).  The downstream parser must be updated together with the
rule generator before relying on these rules outside the learner.

High-byte x86 registers such as `ah` and `ch` are intentionally excluded from
the first phase because they are not low slices.  If they appear in verified
candidates, they should remain skipped with a clear reason until a separate
bit-range expression is designed.
