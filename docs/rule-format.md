# Rule Format

`angr-rule-learning` emits plain-text translation rules. Each rule maps a
guest (AArch64) code fragment to a host (x86-64) code fragment using typed
placeholders for registers, immediates, branch targets, and temporaries.

## Rule Structure

```
<id>.Guest:
    <guest-line-1>
    <guest-line-2>
.Host:
    <host-line-1>
    <host-line-2>
```

Lines consist of the original assembly mnemonic in the target ISA's native
syntax, with concrete operands replaced by typed placeholders.

## Placeholder Catalogue

### Register Placeholders — `i{bits}_reg{N}`

General-purpose integer registers.

```
Guest: add i32_reg1, i32_reg2, i32_reg1
Host:  add i32_reg1, i32_reg2
```

| Placeholder | Meaning |
|-------------|---------|
| `i8_reg1` | 8-bit integer register |
| `i16_reg1` | 16-bit integer register |
| `i32_reg1` | 32-bit integer register |
| `i64_reg1` | 64-bit integer register |

Guest and host sides share the same placeholder when the registers are paired
as semantically equivalent. The `{N}` suffix is a per-rule counter that
increments globally (not per bit-width) — `i32_reg1` and `i64_reg2` may
appear in the same rule because `reg1` was consumed by the first i32 pair.

### Stack Pointer Placeholder — `sp{bits}`

Stack pointer registers are not typed as `i{bits}_regN`; they receive a
dedicated placeholder that preserves their architectural role.

```
Guest: sub sp64, sp64, #imm1
Host:  sub sp64, imm1
```

| Placeholder | Guest source | Host source |
|-------------|-------------|-------------|
| `sp64` | `sp` (AArch64) | `rsp` (x86-64) |
| `sp32` | `wsp` (AArch64) | `esp` (x86-64) |
| `sp16` | — | `sp` (x86-64) |

### Frame Pointer Placeholder — `fp{bits}`

Frame pointer (base pointer) registers.

```
Guest: ldur i32_reg1, [fp64, #-imm1]
Host:  mov i32_reg1, dword ptr [fp64 - imm1]
```

| Placeholder | Guest source | Host source |
|-------------|-------------|-------------|
| `fp64` | `x29`, `fp` (AArch64) | `rbp` (x86-64) |
| `fp32` | — | `ebp` (x86-64) |
| `fp16` | — | `bp` (x86-64) |

> **Note:** `fp` in AArch64 is the architectural alias for `x29` (the frame
> pointer), not a floating-point register.  AArch64 floating-point registers
> are `v0`–`v31`/`d0`–`d31` and are not supported by the current verifier.

#### Mixed `sp`/`fp` pairs

When a memory binding pairs an AArch64 stack pointer with an x86-64 frame
pointer (e.g. `sp + 12` ↔ `rbp - 4`), the generalizer routes the pair
through the frame-pointer branch and assigns the `fp{bits}` placeholder
(because the operation is frame-relative memory access, not stack-pointer
arithmetic).

### Immediate Placeholders — `imm{N}` / `#imm{N}`

Constant immediate values.  Guest and host share the same `imm{N}` when the
numerical value (including sign) is equal.

```
Guest: mov i32_reg1, #imm1
Host:  mov i32_reg1, imm1
```

- AArch64 prefixes immediates with `#` (`#imm1`, `#-imm1`).
- x86-64 does not use a prefix (`imm1`, `- imm1`).
- Negative values preserve the sign in the placeholder: `#-imm1` (AArch64),
  `- imm1` (x86-64).

Hexadecimal and decimal immediates are canonicalized to signed integers so
that `#-0xc` (AArch64) and `- 0xc` (x86-64) share the same `imm{N}`.

Scale immediates (`lsl #2` in AArch64, `*4` in x86-64) are **not** replaced
— they remain as literal constants.

### Branch Label Placeholders — `label{N}`

Branch targets are replaced with shared `label{N}` placeholders.

```
Guest: tbz i32_reg1, #0, #label1
Host:  je label1
```

AArch64 prefixes labels with `#`; x86-64 does not.

### Temporary Register Placeholders — `tmp{N}`

Rules may introduce `tmp{N}` registers that do **not** correspond to any
physical register in the original candidate.  These appear when:

- One ISA uses a load-store sequence while the other fuses the memory access
  into a single CISC instruction (e.g. `ldr tmp + add` ↔ `add [mem]`).
- One ISA's code pattern internally defines a register that the paired ISA
  does not expose.

```
Guest: ldr tmp1, [i64_reg2, #imm1]
       add i32_reg1, i32_reg1, tmp1
Host:  add i32_reg1, dword ptr [i64_reg2 + imm1]
```

A register is classified as a temporary when it satisfies **all** of:

1. It is written inside the window (has a `write_registers` entry).
2. It does **not** appear in `candidate.output_registers`.
3. It does **not** appear in `candidate.input_registers`.
4. It is not a literal register (sp, xzr, …), a condition-code family, or
   an unsupported register class.

`tmp{N}` numbering is global within a rule — the counter increments for
each new temporary across both guest and host sides.

### Dead-Write Lifespan Annotations — `save` / `restore`

Some instructions write to a register that is **not** live-out of the
window.  Rather than discarding the write, the generalizer wraps the
affected lines with lifespan annotations:

```
Guest: tbz i32_reg1, #0, #label1
Host:  save i32_reg1
       and i32_reg1, imm1
       cmp i32_reg1, 0
       restore i32_reg1
       je label1
```

- `save r` marks the point where the register's old value must be preserved.
- `restore r` marks the point where the old value is restored, after the
  last read of the overwritten register.

Temporary registers (`tmp{N}`) are **not** annotated with `save`/`restore`
— they are introduced specifically to hold transient values and their
lifespan is implicitly bounded by the side that defines them.

## Semantic Contract

A rule describes an equivalence: if the guest and host share the same
concrete values for all placeholders (registers, immediates, labels, temps),
then executing the guest fragment produces the same observable state as
executing the host fragment.

Rule generation guarantees:

- Every register placeholder on the host side corresponds to a register
  placeholder on the guest side (no host-only register placeholders).
- Every immediate placeholder on the host side is a subset of those on the
  guest side for non-branch rules with memory bindings.
- `save`/`restore` annotations are consistent: every `save` has a matching
  `restore` in the same block, and the saved register is never used between
  them.

## Unsupported Patterns

The current generalizer deliberately rejects rule shapes that cannot be
expressed with the available placeholder vocabulary:

| Skip reason | Meaning |
|-------------|---------|
| `register_class_mismatch` | Guest and host registers differ in bit-width or kind (integer vs float). |
| `unsupported_rule_shape` | Register coalescing conflicts — the same guest register maps to different host registers (or vice versa) in a way that cannot be resolved. |
| `unpaired_host_immediate` | A frame-relative memory rule has host-side immediate placeholders with no guest-side counterpart (different frame-layout displacements). |
| `unmapped_register_surface` | The instruction text contains a register that was not classified (should only occur when no `tmp` heuristic applies). |
| `duplicate_rule` | The generated rule text is identical to a previously emitted rule. |
| `mismatched_branch_targets` | Guest and host branch targets use different label sets. |

Future extensions (not in the current design):

- Explicit frame-layout relation (to allow different displacements on each
  side of a frame-relative pair to share an immediate).
- Push/pop ↔ stp/ldp prologue/epilogue modelling.
- Branch-target equivalence rules.
