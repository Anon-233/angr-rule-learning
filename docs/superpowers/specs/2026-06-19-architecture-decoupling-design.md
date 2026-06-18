# Architecture Decoupling Design

## Context

The project currently learns rules from AArch64 guest code and x86-64 host code,
but the verifier, extractor, and rule model are intended to be architecture-neutral.
An audit found several implementation details that treat `guest` as a synonym for
AArch64 and `host` as a synonym for x86-64. Those assumptions prevent the same
pipeline from operating in the reverse direction and make future ISA support
unnecessarily invasive.

This design separates three concepts that must not be conflated:

1. **Pipeline side**: guest or host.
2. **Architecture capability**: register roles, aliases, widths, compiler target,
   and instruction-specific parsing for a named ISA.
3. **Translation-pair policy**: directional knowledge that is meaningful only for
   a particular guest/host pair, such as a proven immediate derivation template.

ISA-specific code is expected and remains necessary. Side-specific ISA assumptions
are the defect addressed by this refactor.

## Audit Findings

The following are accidental side bindings and must be removed:

- Frame-address pairing in extraction accepts only an AArch64 frame register on
  the guest side and an x86-64 frame register on the host side.
- Frame-relative memory initialization in verification uses the same fixed
  AArch64-guest/x86-host pairing.
- Fixed-role register provenance uses x86-64 register families and bit ranges
  without consulting the candidate's host architecture.
- Rule generalization applies host fixed-role policy while processing registers
  from both sides and can use the host architecture while rewriting guest code.
- The extraction CLI exposes no architecture arguments, so the full pipeline is
  effectively locked to its default direction even though `ExtractionConfig`
  carries architecture fields.

The following are architecture-specific but are not side coupling and should stay
architecture-specific:

- Instruction decoding and memory-operand parsing selected by the instruction's
  architecture.
- Branch classification, flag extraction, register aliases, ABI liveness sets,
  and stack-delta semantics selected by architecture.
- Compiler target selection selected by architecture.
- Immediate derivation strategies registered for a directional
  `(guest_arch, host_arch)` pair.

## Goals

- Make architecture capability queries independent of guest/host side.
- Preserve AArch64-to-x86-64 behavior and rule output unless an existing result
  depends on an invalid side assumption.
- Support the complete reverse x86-64-to-AArch64 pipeline: build, extract,
  surface inference, verify, and rule emission.
- Keep legitimate directionality explicit, especially host fixed-role provenance
  and translation-pair immediate derivation.
- Reject unsupported architectures at a single, well-defined boundary.

## Non-Goals

- Building a general plugin protocol for arbitrary third-party ISAs.
- Adding a new ISA beyond the AArch64 and x86-64 implementations already present.
- Inventing reverse immediate-derivation templates without semantic proof.
- Removing all ISA-specific instruction handling.
- Reorganizing unrelated extraction or verification behavior.

## Capability Layer

The `angr_rule_learning.arch` package owns reusable ISA facts. It must not expose
APIs containing `guest` or `host` terminology.

The existing registry will provide canonical architecture names and compiler
targets. Shared register semantics will move behind architecture-aware queries,
with APIs equivalent to:

```python
canonical_arch_name(arch)
clang_target(arch)
register_family(arch, register)
register_bit_range(arch, register)
is_stack_pointer(arch, register)
is_frame_pointer(arch, register)
is_frame_base(arch, register)
frame_base_width(arch, register)
stack_pointer_placeholder(arch, register)
frame_pointer_placeholder(arch, register)
is_fixed_role_register(arch, register)
fixed_role_family(arch, register)
fixed_role_preserve_register(arch, register)
```

The exact internal representation may use immutable capability objects or
module-level tables. Callers depend on query functions, not those tables. Rule
placeholder classification remains in `rules`, while shared architectural facts
must not live in `rules` or `extraction`, because verification also consumes them.

Architecture aliases such as `amd64` and `x86_64` are normalized at this boundary.
Unknown architectures raise a clear `ValueError` rather than silently selecting a
default ISA.

## Cross-Architecture Register Pairing

Frame-base compatibility is symmetric and based on capabilities:

```python
is_compatible_frame_base_pair(
    left_arch,
    left_register,
    right_arch,
    right_register,
)
```

The pair is compatible when both operands are recognized frame bases and their
address widths are compatible. The implementation may preserve currently valid
stack-pointer/frame-pointer combinations, but it must derive them from each
register's own architecture. Swapping both sides must not change the answer.

Extraction and verification use this function instead of maintaining separate
AArch64 and x86-64 side sets.

## Rule Generalization

Guest and host instruction streams are generalized with their own architecture:

- Guest register classification uses `candidate.guest.arch`.
- Host register classification uses `candidate.host.arch`.
- Save/restore spelling and register width use the architecture of the stream being
  rewritten.
- Host fixed-role provenance applies only to host registers. A fixed-role register
  encountered on the guest side is identified with the guest architecture and must
  never be processed using host policy. Until the rule model can bind a guest
  fixed-role literal to a generic host value, that shape is rejected rather than
  emitted with an unbound placeholder.
- Host fixed-role producer tracing uses host register families and host bit ranges,
  not x86-64 tables selected implicitly.
- Host-only literal allowances are never passed into guest generalization.

This remains directionally asymmetric by design: a translator must prove how a
required host fixed-role value is produced from guest-visible inputs. The policy is
host-specific, but the architecture used to implement it is supplied explicitly.

## Directional Translation Knowledge

Immediate derivation remains registered by `(guest_arch, host_arch)`. A derivation
such as an AArch64 bit index becoming an x86-64 mask is not an architecture
capability and is not symmetric. The registry may contain no strategy for the
reverse pair; in that case rules requiring an unproven host immediate are skipped.

This restriction can reduce reverse-direction rule yield, but it is preferable to
emitting an unsound rule. Register-only and memory rules without such a derivation
must still pass through the reverse pipeline.

## CLI and Configuration

The `extract` and `diagnose-skips` commands gain explicit options:

```text
--guest-arch {aarch64,x86-64}
--host-arch {aarch64,x86-64}
```

Defaults remain AArch64 guest and x86-64 host for compatibility. Both values are
normalized through the architecture registry before building or extracting. The
build driver obtains target triples from the same registry rather than owning a
second architecture map.

Core APIs continue to receive architecture values through typed configuration and
candidate objects. They must not read CLI defaults or infer architecture from side.

## Verification Strategy

Implementation follows test-driven development. Regression tests are added before
each behavior change.

Required unit and integration coverage:

1. Architecture aliases, targets, register families, bit ranges, frame roles, and
   fixed roles are queried through the capability layer.
2. Frame-base compatibility is symmetric for AArch64/x86-64 and
   x86-64/AArch64 arguments.
3. Memory surface inference accepts frame-relative pairs in both directions.
4. Memory initialization verifies equivalent frame-relative fragments in both
   directions.
5. Rule generalization processes each side with its own architecture and does not
   leak host fixed-role literals into guest code.
6. CLI configuration reaches build and extraction in both directions.
7. Existing AArch64-to-x86-64 end-to-end smoke remains passing.
8. A new x86-64-to-AArch64 end-to-end smoke compiles one source for both targets,
   extracts candidates, verifies them, and emits at least one rule with the correct
   guest/host architecture order and no verifier internal errors.

The reverse smoke is not required to match forward rule count. It is required to
exercise the full production path rather than constructing candidates directly in
a test.

## Documentation and Compatibility

`docs/architecture.md` will document the capability boundary, legal directional
translation policies, CLI architecture selection, and bidirectional smoke tests.
Existing JSON candidates remain compatible because architecture fields already
exist. Defaults remain unchanged.

The refactor should use temporary forwarding functions only where needed to keep
module boundaries stable during migration. The final production paths must use the
central capability layer; duplicated side-specific architecture tables are not an
acceptable final state.
