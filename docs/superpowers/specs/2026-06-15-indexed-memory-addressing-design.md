# Indexed Memory Addressing Design

## Summary

The memory rule pipeline currently supports only base plus displacement memory
operands and emits opaque address placeholders such as `[addr64_1]`. The next
memory-rule iteration should support indexed addressing on both AArch64 and
x86-64, normalize both ISAs into one address expression model for verification,
and emit rules that preserve each ISA's native assembly memory syntax.

The target is not just to accept more parser forms. The extractor, verifier,
and rule generalizer must agree on the same structured effective-address model:

```text
effective_address = base + index * scale + displacement
```

Rule output must expose the address structure through normal typed register and
immediate placeholders. It must not collapse the entire memory operand to an
opaque `[addr64_N]` placeholder.

## Goals

- Support simple indexed memory operands on both sides of the rule-learning
  pair.
- Normalize AArch64 and x86-64 memory operands into one structured address IR.
- Verify memory bindings using base, index, scale, and displacement semantics.
- Emit rule text using each ISA's original memory-operand syntax with typed
  register placeholders and shared immediate placeholders.
- Keep unsupported addressing forms explicit as `unsupported_memory_surface`.
- Preserve the current conservative behavior for pre/post-index writeback,
  pair loads/stores, RIP-relative addressing, segment overrides, and
  read-modify-write instructions.

## Non-Goals

- Do not support AArch64 pre-index or post-index writeback in this iteration.
- Do not support AArch64 `uxtw` or `sxtw` extension semantics yet.
- Do not support x86-64 RIP-relative or segment-based addressing yet.
- Do not support x86 memory operands with no base register in the first
  implementation.
- Do not introduce full symbolic address-equivalence proof in the first
  implementation. Leave the data model ready for it.
- Do not introduce a new final rule-file syntax beyond native assembly text
  with existing typed placeholders.

## Current State

Current memory extraction is centered on:

- `extraction/memory_operands.py`
  - `MemoryAddress(base, displacement)`
  - `MemoryOperand(kind, width, address, text, value_register)`
- `extraction/memory_surfaces.py`
  - pairs guest and host memory operands into `MemorySpec`
  - rejects unparsed memory access via `unsupported_memory_surface`
- `verification/addressing.py`
  - parses only `register +/- offset`
- `verification/memory.py`
  - initializes a bound register so the effective address reaches the memory
    slot base
- `rules/memory.py`
  - rewrites whole memory operand text to `[addr64_N]`

That shape is too narrow for indexed addressing and loses rule information in
the output.

## Address IR

Introduce a structured address expression that is shared by extraction,
verification, and rule generation:

```python
@dataclass(frozen=True)
class AddressExpr:
    base: str | None
    index: str | None = None
    scale: int = 1
    displacement: int = 0
    width: int = 64
```

The canonical semantics are:

```text
base + index * scale + displacement
```

Rules:

- `base` and `index` are register names in the source ISA before rule
  placeholder rewriting.
- `scale` is a positive integer. For the first implementation, accept x86
  scales `{1, 2, 4, 8}` and AArch64 `lsl #shift` where `scale = 1 << shift`.
- `displacement` is a signed integer.
- `width` is the address width. It is `64` for the current AArch64 to x86-64
  target.
- If `index is None`, `scale` must be `1`.
- If both `base` and `index` are absent, the address is unsupported for the
  first implementation.

`MemoryOperand.address` should use `AddressExpr` instead of the current
`MemoryAddress`. Compatibility helpers may provide a canonical string for JSON
and verifier binding fields, but the structured value should remain the source
of truth.

## Parser Scope

### AArch64

Support:

```text
[base]
[base, #disp]
[base, index]
[base, index, lsl #shift]
```

Examples:

```text
ldr w0, [x1]              -> base=x1
ldr w0, [x1, #8]          -> base=x1, displacement=8
ldr w0, [x1, x2]          -> base=x1, index=x2, scale=1
ldr w0, [x1, x2, lsl #2]  -> base=x1, index=x2, scale=4
```

Continue rejecting:

```text
[base], #disp
[base, #disp]!
[base, index, uxtw #shift]
[base, index, sxtw #shift]
ldp/stp/ldnp/stnp
```

### x86-64

Support:

```text
[base]
[base + disp]
[base + index*scale]
[base + index*scale + disp]
[base + index + disp]
```

Examples:

```text
mov eax, dword ptr [rcx]              -> base=rcx
mov eax, dword ptr [rcx + 8]          -> base=rcx, displacement=8
mov eax, dword ptr [rcx + rdx*4]      -> base=rcx, index=rdx, scale=4
mov eax, dword ptr [rcx + rdx*4 + 8]  -> base=rcx, index=rdx, scale=4, displacement=8
```

Continue rejecting:

```text
[rip + disp]
segment:[...]
push/pop
read-modify-write instructions
memory-to-memory operands
```

## Surface Inference

Address registers must participate in the verifier candidate's input register
mapping. The current opaque-address rule path removes address-register pairs
from the input surface; that is no longer correct because rule output needs
typed placeholders for base and index registers.

For a memory load:

```text
ldr w0, [x1, x2, lsl #2]
mov eax, dword ptr [rcx + rdx*4]
```

the candidate should include:

```text
input_registers:
  x1 <-> rcx
  x2 <-> rdx

output_registers:
  w0 <-> eax

memory:
  mem0 read width=4
  guest address: base=x1, index=x2, scale=4
  host address:  base=rcx, index=rdx, scale=4
```

For stores, the stored value register remains an input as before, and base/index
registers are also inputs.

Surface inference should not require scale or displacement to be equal. Those
are semantic properties and should be checked by the verifier. Surface inference
should skip only when the memory operands cannot be structurally represented or
paired at all, such as unsupported parser forms, memory access count mismatch,
kind mismatch, width mismatch, or unmappable address registers.

## Verifier Behavior

The first implementation can keep the current memory-slot event model and use a
concrete witness for address binding. It must avoid the old pitfall of setting
index to zero, because that can hide scale mistakes.

For each memory binding:

1. Choose a slot base, as today.
2. Choose deterministic non-zero witness values for index registers, for
   example `3`.
3. Compute the required base register value:

```text
base_value = slot_base - index_value * scale - displacement
```

4. Write base and index registers on both guest and host states.
5. Execute the fragments.
6. Check that the recorded memory event address equals the slot base.

This is still a witness-based check, not a full symbolic proof of address
equivalence. It is acceptable for this iteration because it catches base/index,
scale, and displacement mismatches for the supported parser forms. The address
IR should make a future SMT address-equivalence check straightforward.

## Rule Generalization

Rules should keep native ISA memory operand syntax and replace internal tokens.

The old output:

```text
.Guest:
	ldr i32_reg1, [addr64_1]
.Host:
	mov i32_reg1, dword ptr [addr64_1]
```

should become:

```text
.Guest:
	ldr i32_reg1, [i64_reg2]
.Host:
	mov i32_reg1, dword ptr [i64_reg2]
```

Indexed addressing should generalize as:

```text
.Guest:
	ldr i32_reg1, [i64_reg2, i64_reg3, lsl #2]
.Host:
	mov i32_reg1, dword ptr [i64_reg2 + i64_reg3*4]
```

Displacements must be shared across guest and host with normal immediate
placeholders:

```text
.Guest:
	ldr i32_reg1, [i64_reg2, #imm1]
.Host:
	mov i32_reg1, dword ptr [i64_reg2 + imm1]
```

This is required because the host instruction generator must be able to derive
every host-side immediate from the guest rule match. Literal host-only
displacements are not valid generalized rules.

Scale and shift should remain literal in the first implementation, but their
semantic equality must be checked through `AddressExpr.scale`:

```text
lsl #2 <-> *4
```

Future work may introduce derived placeholders for scale or shift, but this is
not required for the first indexed-addressing iteration.

## Diagnostics

Existing diagnostics remain valid:

- `unsupported_memory_surface` for addressing forms outside the supported
  parser and verifier scope.
- `unsupported_address_expression` should disappear for newly supported indexed
  forms and remain for unsupported verifier address expressions.
- `unmapped_register_surface` should catch concrete address registers left in
  rule output.

If useful during implementation, add targeted skip reasons internally, but keep
the public taxonomy stable unless a new reason materially improves debugging.

## Testing Strategy

Add unit tests for parser normalization:

- AArch64 base, base+disp, base+index, base+index+lsl.
- x86-64 base, base+disp, base+index*scale, base+index*scale+disp.
- Explicit rejection for writeback, RIP-relative, segment override, and
  extension forms.

Add surface inference tests:

- indexed load pairs address base/index registers as inputs;
- indexed store pairs address base/index and stored-value registers as inputs;
- mismatched scale or displacement reaches the verifier and fails semantic
  verification instead of being classified as an unsupported surface.

Add verifier tests:

- equivalent indexed load passes;
- wrong host scale fails;
- wrong host displacement fails;
- unsupported expression still reports `unsupported_address_expression`.

Add rule generalization tests:

- base-only memory operand keeps native syntax with register placeholders;
- base+disp shares `immN`;
- indexed AArch64 `lsl #shift` and x86 `*scale` keep literal scale syntax while
  sharing base/index placeholders;
- no `[addr64_N]` appears in new memory rule output.

Add smoke coverage:

- a small source sample that produces load/store with array-style indexing;
- `extract --verify --rules-output` should emit at least one indexed memory
  rule.

## Acceptance Criteria

- Current base+displacement memory rules still pass.
- Supported indexed memory operands are extracted into `AddressExpr`.
- Verifier accepts correct indexed memory bindings and rejects wrong scale or
  displacement bindings.
- Generated memory rules use native ISA memory syntax and typed placeholders.
- Displacements shared between guest and host use the same `immN` placeholder.
- Newly generated memory rules do not use `[addr64_N]`.
- Existing unsupported memory forms remain rejected.
- `uv run ruff format --check`, `uv run ruff check`, and `uv run pytest -q`
  pass.

## Open Extension Points

- Full SMT proof of effective address equivalence.
- AArch64 `uxtw` and `sxtw` index-extension semantics.
- x86 RIP-relative addressing.
- x86 no-base addressing such as `[index*scale + disp]`.
- Pair load/store and multi-memory-operand instructions.
- Read-modify-write memory instructions.
