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
