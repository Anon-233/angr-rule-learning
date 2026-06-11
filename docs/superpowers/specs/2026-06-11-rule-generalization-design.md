# Rule Generalization Design

Date: 2026-06-11

## Context

The project can now extract verifier candidates from a single C source file,
verify those candidates with angr, and keep only short AArch64-to-x86-64 integer
fragments that pass semantic verification. The next step is to turn verified
candidate windows into the text rule format consumed by downstream rule-table
tooling.

The current `VerificationCandidate` JSON is not enough by itself to produce a
readable assembly rule because it stores code bytes, addresses, and register
relations, but not the disassembled instruction text. Rule generation should
therefore run inside the extraction pipeline while `WindowPair` records are
still available.

## Goals

- Generate text rules from verified passing extraction windows.
- Integrate rule output into `extract --verify` as an optional output.
- Preserve the existing candidate JSONL, verifier report, and diagnostics
  behavior.
- Generalize registers with explicit type and bit width.
- Keep immediates, addressing constants, scale values, and labels as literals in
  the first implementation.
- Skip rules that cannot be generalized safely.

## Non-Goals

- Do not implement a rule database or coverage scoring.
- Do not infer memory rules in this stage; memory windows are still skipped by
  surface inference.
- Do not generalize immediates.
- Do not implement flag-output rule generation. Windows with `nzcv` or `rflags`
  are skipped before candidate emission today.
- Do not regenerate rules from candidate JSONL alone.

## Output Format

Rules are saved as plain text. Each rule uses a consecutive one-based rule id:

```text
1.Guest:
	<guest rule asm codes>
.Host:
	<host rule asm codes>

2.Guest:
	<guest rule asm codes>
.Host:
	<host rule asm codes>

```

The indentation before each assembly line is one literal tab. Multi-instruction
windows emit one tab-indented line per instruction. Each rule ends with one
blank line.

Example:

```text
1.Guest:
	mov i32_reg1, #9
.Host:
	mov i32_reg1, 9

```

The text rule file intentionally contains only rule text. Machine-readable
metadata, diagnostics, and source candidate ids should live in separate files.

## CLI Integration

Add optional arguments to `extract`:

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

`--rules-output` requires `--verify`. If `--rules-output` is supplied without
`--verify`, the command should fail with a clear CLI error. The extractor needs
verifier reports to know which windows are safe to emit as rules.

`--rules-diagnostics` is optional. If omitted, no extra diagnostics file is
written. The existing extraction diagnostics file remains focused on extraction
and mining statistics.

## Pipeline Placement

Rule generation runs after each verification stage has reports for emitted
candidates. The pipeline already holds:

```text
WindowPair + VerificationCandidate + VerificationReport
```

Only reports with `status == "pass"` and `equivalent == true` are eligible. The
same verified passing windows that drive composite-window pruning should feed
rule generation.

The implementation should keep a stable internal association between each
emitted `WindowPair`, its candidate, and its verifier report. It should not try
to recover windows from candidate ids.

## Register Placeholders

Register placeholders use the form:

```text
<kind><bits>_reg<id>
```

Examples:

```text
i32_reg1
i64_reg2
f32_reg1
f64_reg1
v128_reg1
```

`kind` values:

- `i`: integer/general-purpose register;
- `f`: scalar floating-point register;
- `v`: vector register.

The first implementation must support integer registers used by the current
AArch64-to-x86-64 samples. Floating-point and vector classification should be
represented in the API so the text format does not need to change later, but
the initial extractor may skip rules requiring unsupported classes.

## Register Mapping

Register placeholders are shared across guest and host according to
`VerificationCandidate.input_registers` and `output_registers`.

For example:

```json
{
  "inputs": {"registers": [["w0", "eax"]]},
  "outputs": {"registers": [["w8", "ecx"]]}
}
```

maps to:

```text
w8  -> i32_reg1
ecx -> i32_reg1
w0  -> i32_reg2
eax -> i32_reg2
```

Output registers should be assigned first, then input registers, preserving
candidate order. Repeated pairs reuse the existing placeholder. If a register
appears in both input and output pairs, it keeps the first assigned placeholder.

For every cross-ISA pair, both sides must have the same `(kind, bits)`. If they
do not, skip the rule and record `register_class_mismatch`.

## Register Classification

Register type and bit width should be resolved through a dedicated rules module,
not scattered through string replacement code.

Recommended files:

```text
src/angr_rule_learning/rules/registers.py
src/angr_rule_learning/rules/generalize.py
src/angr_rule_learning/rules/writer.py
```

Width source:

- prefer architecture register metadata from angr arch definitions;
- fall back to local register-name tables for known subregisters;
- if neither path succeeds, skip the rule with `unknown_register_class`.

Classification rules for the first implementation:

- AArch64 `w*` registers are `i32`;
- AArch64 `x*`, `sp`, `fp`, and `lr` are `i64`;
- x86-64 byte/word/dword/qword general-purpose subregisters are `i8`, `i16`,
  `i32`, and `i64` respectively;
- AArch64 `s*` and x86 `xmm*` scalar 32-bit float cases may classify as `f32`
  when the instruction semantics are known to be scalar float;
- AArch64 `d*` and x86 `xmm*` scalar 64-bit float cases may classify as `f64`
  when the instruction semantics are known to be scalar float;
- AArch64 `v*`, `q*`, and x86 `xmm/ymm/zmm` vector cases may classify as vector
  widths when scalar float classification is not safe.

The first implementation can conservatively skip ambiguous float/vector
registers with `unsupported_register_class` until floating-point extraction is
explicitly enabled.

## Assembly Text Generalization

Each `ExtractedInstruction` becomes:

```text
<mnemonic> <op_str>
```

If `op_str` is empty, emit only `<mnemonic>`.

Generalization replaces register tokens in that instruction text using the
placeholder map. Replacement requirements:

- replace longer register names before shorter names;
- use token-aware boundaries so `x1` does not rewrite the `x1` part of `x10`;
- replace both guest and host physical register names with their shared
  placeholder;
- do not replace immediates, scale values, offsets, labels, or mnemonics;
- preserve instruction order and one instruction per line.

After replacement, scan the instruction text for remaining ordinary register
tokens. If one remains, skip the rule with `unmapped_register_surface`. This
prevents concrete physical registers from leaking into generalized rules.

Architectural literal registers that represent constants may remain literal:

- AArch64 `xzr`;
- AArch64 `wzr`.

Other special registers such as `sp`, `fp`, and `lr` should only appear if they
are part of a candidate register mapping. If they remain unmapped in assembly
text, skip the rule.

## Diagnostics

Rule diagnostics should be separate from extraction diagnostics:

```json
{
  "rules_considered": 10,
  "rules_emitted": 10,
  "rules_skipped": 0,
  "skip_reasons": {}
}
```

Expected skip reasons:

- `register_class_mismatch`;
- `unknown_register_class`;
- `unsupported_register_class`;
- `unmapped_register_surface`;
- `unsupported_rule_shape`.

The diagnostics should count only windows that passed verification and were
considered for rule output. Extraction/mining skip reasons remain in extraction
diagnostics.

## Metadata

Rule text stays minimal. To support debugging and evaluation, optionally emit a
sidecar index file in a later step. The first implementation may include rule
ids and candidate ids in diagnostics, but the text rule file must preserve the
requested plain format.

## Testing Strategy

Unit tests should cover:

- `w0` and `edi` map to `i32_reg1`;
- `x0` and `rdi` map to `i64_reg1`;
- output registers are numbered before input registers;
- repeated registers reuse the same placeholder;
- `x1` replacement does not corrupt `x10`;
- mismatched width pairs are skipped;
- unknown register names are skipped;
- `xzr` and `wzr` may remain literal;
- unmapped physical registers cause a skipped rule;
- multi-instruction windows emit multiple tab-indented lines.

CLI or pipeline tests should cover:

- `extract --verify --rules-output` writes a non-empty rule file for
  `samples/sources/smoke_int.c`;
- `--rules-output` without `--verify` fails with a clear error;
- not passing `--rules-output` leaves current extraction behavior unchanged;
- rule diagnostics count considered, emitted, skipped, and skip reasons.

End-to-end smoke should verify that generated rules use placeholders such as
`i32_reg1` and do not contain concrete registers such as `w0`, `x0`, `eax`, or
`rdi`, except for explicitly allowed architectural literals.
