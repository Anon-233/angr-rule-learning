# Rule Generalization

Rule generalization turns verifier-passing extraction windows into plain text
translation rules. It runs inside `extract --verify` because the pipeline still
has both the verified candidate model and the original disassembled instruction
text.

## Command

```bash
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir runs/samples/smoke_int_o0/work \
  --output runs/samples/smoke_int_o0/candidates.jsonl \
  --diagnostics runs/samples/smoke_int_o0/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output runs/samples/smoke_int_o0/rules.txt \
  --rules-diagnostics runs/samples/smoke_int_o0/rules_diagnostics.json
```

`--rules-output` requires `--verify`. The rule generator emits only windows
whose verifier report has status `pass` and equivalent checks.

## Text Format

```text
1.Guest:
	<guest asm>
.Host:
	<host asm>

```

Multi-instruction rules use one tab-indented assembly line per instruction.
The text file contains only rules. Diagnostics and candidate ids are kept out
of the rule text.

## Register Generalization

Registers are replaced with typed placeholders:

- `i8_regN`, `i16_regN`, `i32_regN`, `i64_regN` for integer registers;
- `f32_regN` and `f64_regN` are reserved for scalar floating-point rules;
- `v128_regN` and wider vector placeholders are reserved for vector rules.

The first implementation emits integer register rules only. It keeps
immediates, offsets, scales, labels, and mnemonics literal.

## Memory Operand Generalization

Memory rules keep each ISA's native memory operand syntax and replace only
the register tokens and shared displacement immediates.  Each memory slot
gets a ``MemoryBinding`` that pairs a guest address expression
(e.g. ``x1 + x2 * 4`` or ``x1 + 8``) with a host address expression
(e.g. ``rcx + rdx * 4`` or ``rcx + 8``).

Address base and index registers use the same typed register placeholders as
the register surface:

```text
1.Guest:
    ldr i32_reg1, [i64_reg2, #imm1]
.Host:
    mov i32_reg1, dword ptr [i64_reg2 + imm1]

2.Guest:
    ldr i32_reg1, [i64_reg2, i64_reg3, lsl #2]
.Host:
    mov i32_reg1, dword ptr [i64_reg2 + i64_reg3*4]
```

Rules for the new design:

- address base/index registers use normal typed register placeholders;
- displacements shared by guest and host use the same ``immN``;
- scale/shift literals remain literal in the current implementation;
- ``[addr64_N]`` is no longer emitted for memory rules.

### Supported Memory Forms

- AArch64: ``ldr``, ``ldur``, ``str``, ``stur`` with base-only ``[base]``,
  base+displacement ``[base, #disp]``, register-offset ``[base, index]``,
  and shifted index ``[base, index, lsl #shift]``.
- x86-64: ``mov`` with ``[reg]``, ``[reg + disp]``, ``[base + index*scale]``,
  and ``[base + index*scale + disp]`` (32-bit and 64-bit).

### Unsupported Memory Forms

These are detected and reported as ``unsupported_memory_surface`` in
diagnostics:

- AArch64: ``ldp``, ``stp``, ``ldnp``, ``stnp``, extension-index addressing
  (``uxtw``/``sxtw``), post/pre-index addressing.
- x86-64: ``push``, ``pop``, RIP-relative addressing, segment overrides,
  no-base indexed addressing (``[index*scale + disp]``), memory-to-memory
  operands, read-modify-write instructions.

``lea`` on x86-64 uses memory-like addressing syntax (e.g. ``lea rcx, [rdx+4]``)
but performs no memory access.  It is not treated as a memory surface and is
instead handled by the register/liveness surface path.  Whether ``lea``-based
rules can be learned depends on the verifier's register arithmetic support.

## Conservative Skips

The generator skips verified windows when it cannot produce a safe generalized
rule:

- `register_class_mismatch`: guest and host mapped registers differ in kind or width;
- `unknown_register_class`: a mapped register cannot be classified;
- `unsupported_register_class`: the register class is known but not enabled;
- `unmapped_register_surface`: a concrete register remains after replacement;
- `unsupported_rule_shape`: the candidate mapping is inconsistent or empty.

AArch64 `xzr` and `wzr` may remain literal because they represent architectural
zero registers.
