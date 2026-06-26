# Architecture

`angr-rule-learning` is a rule-learning pipeline with explicit data boundaries
and independently testable components. The current main path is IR-kernel based
constructive learning: controlled LLVM IR kernels are compiled to Guest and
Host targets, their machine-code snippets are verified with angr/Claripy, and
passing snippets are generalized into text rules. Rule storage and coverage
evaluation remain planned.

## Pipeline Shape

The intended constructive pipeline is:

```text
IR Kernel Corpus
  -> Kernel Compilation
  -> Snippet Extraction
  -> ABI Binding
  -> Semantic Verification
  -> Rule Generalization
  -> Rule Store
  -> Coverage Evaluation
```

The kernel package (`src/angr_rule_learning/kernel/`) implements the first
four stages for the current MVP:

```text
HardcodedKernelSynthesizer
  -> KernelCompiler (clang -x ir)
  -> SnippetExtractor (ObjectExtractor + conservative filtering)
  -> KernelBindingBuilder (scalar ABI register binding)
  -> VerificationCandidate values
  -> verification.BatchVerifier
  -> rules.RuleGeneralizer
  -> text rules + diagnostics
```

This route constructs a clean learning region from each IR kernel instead of
searching a source/debug-info aligned binary region for candidate windows.
One kernel may eventually produce multiple candidates, but the MVP emits one
function-level candidate per scalar kernel.

Guest and Host are pipeline roles, not architecture aliases. The `learn`
command accepts `--guest-arch` and `--host-arch`; the defaults are `aarch64`
and `x86-64`, and the same code path supports the reverse direction.

The CLI still accepts candidate JSON/JSONL through `verify` so verifier work
can proceed independently of the constructive learner.

## Package Structure

```text
src/angr_rule_learning/
  cli.py
  arch/
    registry.py
    registers.py
    flags.py
    memory.py
    aarch64/
      memory.py
    x86_64/
      memory.py
  kernel/
    models.py
    synthesize.py
    compile.py
    extract.py
    bind.py
    pipeline.py
  io/
    readers.py
    schema.py
    writers.py
  smt/
    solver.py
  verification/
    candidate.py
    config.py
    execution.py
    context.py
    relations.py
    checks.py
    memory.py
    memory_checks.py
    flags.py
    branches.py
    report.py
    batch.py
    verifier.py
  extraction/
    config.py
    build.py
    object.py
    blocks.py
    align.py
    windows.py
    surfaces.py
    candidates.py
    register_bindings.py
    register_transfer.py
    register_cegis.py
    memory_surfaces.py
    liveness.py
    diagnostics.py
    emit.py
    pipeline.py
  analysis/
    skip_patterns.py
  rules/
    ast.py
    derivation.py
    registers.py
    generalize.py
    writer.py
```

The package boundaries are:

- `arch`: owns canonical architecture names, angr and clang identifiers,
  register families and bit ranges, stack/frame roles, fixed register roles,
  architecture-specific flag expressions, and instruction-level memory
  recognition. `arch.memory` defines the shared memory-operand contract and
  dispatches to per-ISA packages such as `arch.aarch64.memory` and
  `arch.x86_64.memory`. Capability APIs receive an architecture explicitly and
  contain no guest/host policy.
- `io`: converts strict JSON dictionaries into typed verifier models and writes
  report/summary JSON.
- `kernel`: owns the constructive learning route. It defines IR-kernel models,
  synthesizes the builtin scalar corpus, compiles LLVM IR through clang,
  extracts snippets from target objects, builds ABI-based verifier candidates,
  invokes verification, and emits generalized rules and diagnostics.
- `smt`: holds shared bit-vector width helpers used by relation checks.
- `verification`: owns the verifier data model, execution setup, semantic
  checks, report model, and batch API.
- `extraction`: contains the legacy source/debug-info mining route and reusable
  object/disassembly models. It is no longer the primary learning entry point,
  but `kernel.extract` intentionally reuses `ObjectExtractor`.
- `rules`: defines the structured Rule AST (`ast.py`) as the canonical
  internal rule model; classifies registers; generalizes verified extraction
  windows into typed placeholder rules; derives host-only immediates from
  prescribed instruction-aware templates (`derivation.py`); performs
  relationship-preserving alpha-equivalence deduplication and consolidation;
  and writes plain text rule output with diagnostics.
- `analysis`: read-only diagnostics/observability tools.  Reuses extraction
  components to aggregate skip patterns but never participates in candidate
  extraction, verification, or rule generation decisions.  Exposed via the
  `diagnose-skips` CLI subcommand.
- `cli.py`: provides a thin command-line wrapper over `KernelLearningPipeline`
  and `BatchVerifier`.

## Data Flow

```text
IRKernel
  -> kernel.KernelCompiler
     -> guest object
     -> host object
  -> kernel.SnippetExtractor
     -> guest snippet
     -> host snippet
  -> kernel.KernelBindingBuilder
     -> VerificationCandidate values
  -> verification.BatchVerifier
     -> addressing.parse_address_binding (AddressExpr for memory bindings)
  -> VerificationReport values
  -> rules.RuleGeneralizer
     -> rules.registers (register classification + generalization)
  -> plain text rules + rule diagnostics
```

The legacy source-mining route still exists under `extraction/` and can be
used as a reference for future snippet mining work, but it is intentionally not
the main pipeline described by this document.

### Architecture Capability Boundary

ISA-specific behavior is necessary, but it is selected from the architecture
attached to each fragment or instruction. `arch.registry` normalizes aliases
and supplies toolchain identifiers. `arch.registers` supplies shared register
families, bit ranges, frame roles, and fixed-role information to extraction,
verification, and rule generation. Those packages must not maintain separate
Guest=AArch64 or Host=x86-64 register tables.

Cross-ISA frame pairing is symmetric: both registers must be recognized frame
bases by their respective architectures and have equal address width. A pair
such as AArch64 `sp` and x86-64 `rbp` therefore receives the same treatment
when the pipeline direction is reversed.

Directionality remains valid where it describes translation rather than an
ISA capability. Fixed-role producer provenance is checked on the actual Host
fragment because generated Host code must establish that physical register.
Immediate derivation templates remain registered by
`(guest_arch, host_arch)` because those transformations are not generally
invertible.

### Register Binding Boundary

`extraction.register_bindings` defines the single boundary that converts
independent Guest and Host `WindowSurface` values into paired input and output
registers. `BindingProblem` carries both surfaces, the `WindowPair`, and the
complete `MemorySurface`. `SurfaceInferer` consumes the resulting
`RegisterBindingResult` and does not construct register pairs itself.

Two strategies implement this boundary. `positional` remains the default and
pairs equal-sized surfaces with `zip` for compatibility. The opt-in `cegis`
strategy accepts equal-cardinality surfaces with at most four external inputs
and outputs per side. Zero inputs or outputs are valid when register outputs,
memory events, or branch guards still provide an observable effect.

For CEGIS, `RegisterTransferExtractor` independently symbolically executes the
Guest and Host fragment once and caches their output expressions over distinct
side-local input symbols. Finite Host-to-Guest selector variables then propose
exact-width, all-different input and output bindings under concrete samples.
Each proposal is converted through the same candidate factory used by normal
extraction and passed to `SemanticVerifier`. A failed verifier model contributes
the next Guest input sample; transfer expressions are not re-extracted. The
first verifier-proved mapping is returned, so synthesis filters proposals while
the existing verifier remains the correctness boundary.

Parsed memory and branch windows use bounded verifier-driven selector search
instead of the register transfer summary. Each proposal carries the complete
memory slots, address bindings, aliases, and access expectations. Structurally
inferred memory register pairs constrain selector proposals where those pairs
are already known.

If transfer extraction, selector modelling, or verification is unsupported or
inconclusive, CEGIS invokes positional binding as a compatibility heuristic.
Successful fallbacks are counted in `register_binding_fallbacks` with their
cause, separately from window skips. Exhausting every supported selector
mapping returns `register_binding_unsat` and does not fall back. Register-limit
details identify the side, surface role, observed count, and limit of four.

### Memory Surface Inference

The extractor explicitly distinguishes "no memory access" from "memory access
exists but is unsupported." `arch.memory` dispatches each instruction to its
ISA recognizer. The recognizer parses supported operands into the shared
`MemoryOperand` and `AddressExpr` models, identifies broader unsupported memory
forms through `has_any_memory_access`, and reports implicit stack-pointer
changes through `stack_pointer_delta`. The architecture-neutral surface
inferer emits `unsupported_memory_surface` when memory access is present but
cannot be modelled, preventing unsupported forms from being silently treated
as register-only candidates.

Adding memory recognition for another ISA requires a canonical architecture
entry and an `arch/<canonical_name>/memory.py` module exporting `RECOGNIZER`.
Extraction, diagnostics, and verification code must not import ISA-specific
regular expressions or mnemonic tables directly.

Address base and index registers are included in candidate `input_registers`
so rule generalization can emit typed register placeholders for them.

Extraction diagnostics preserve coarse skip counters in `skip_reasons`. For
broad categories that hide actionable causes, the pipeline also emits
`skip_details`, keyed by the same coarse reason. For example,
`unsupported_memory_surface` may contain `memory_access_count_mismatch`,
`memory_width_mismatch`, or `unparsed_memory_access`; the sum of those detail
counts should match the corresponding coarse reason when every skip path in
that category reports a detail.

Frame-relative stack memory is treated specially. When two architecture-owned
frame bases of equal width align, extraction does not model the base registers
as equal input values. Instead, memory bindings carry the effective address
expressions and the verifier assigns frame base witnesses that make consistent
slots alias across ISAs. This preserves normal equality semantics for ordinary
address registers while allowing common `sp + offset` versus `rbp - offset`
stack-slot rules to verify in either translation direction.

Store-immediate surfaces are rejected at extraction time. Until the verifier
supports explicit immediate value bindings, a store pair where either side
uses an immediate value (e.g. `mov dword ptr [rbp-4], 3`) returns
``store_value_immediate_unsupported`` rather than emitting a bogus register
input.

Sign-extension memory loads (`ldrsw` for AArch64, `movsxd` for x86-64) are
parsed as 32-bit memory reads. The verifier compares output register
expressions after execution, so the memory surface only needs the read address
and width; the sign extension is checked via the output register relation.

``push``/``pop`` (x86-64) and ``stp``/``ldp`` (AArch64, including
non-temporal variants) are parsed as ``MemoryOperand`` records with
stack-pointer-relative addresses.  Full prologue/epilogue *rules* require
the window to contain matching sp/rsp modifications (e.g. ``sub sp`` /
``add rsp`` on both sides) so the translation correctly preserves stack
side-effects.  Windows where only one side modifies the stack pointer
are rejected as ``one_sided_memory_access`` or
``memory_access_count_mismatch``.

Still unsupported: x86 read-modify-write arithmetic memory operands,
x86 ``movaps`` (XMM spill/fill), and AArch64 SIMD memory
(``ldr q0``/``str q0``).

Rule generation consumes `WindowPair + VerificationCandidate + VerificationReport`
and produces text rules with typed register placeholders such as `i32_reg1`
in each ISA's native assembly syntax.  Memory rules keep the original operand
text and generalize only registers and shared displacement immediates.

The CLI is intentionally outside the verifier core. Future pipeline code should
construct `VerificationCandidate` values directly, call `SemanticVerifier` or
`BatchVerifier`, and consume `VerificationReport` values without depending on
subprocess execution.

## Verifier Core

The verifier compares semantic surfaces rather than instruction families. angr
provides lifting and symbolic execution, Claripy provides symbolic expressions
and solver queries, and `RelationChecker` performs equivalence checks by
contradiction:

```text
guest_expr != host_expr is UNSAT  => equivalent for that check
guest_expr != host_expr is SAT    => counterexample found
```

The verifier currently checks:

- register output pairs;
- memory access count, kind, width, address, and value;
- explicit flag output pairs for the stable flag subset;
- terminal conditional branch taken-guard equivalence.

Detailed verifier behavior and support boundaries are documented in
[Verifier](verifier.md).

## Rule AST

The canonical rule model lives in `rules/ast.py`.  Every generated rule is
a dataclass tree of `Rule`, `Instruction`, and typed `Operand` nodes (RegOp,
ImmOp, TmpOp, LabelOp, LitOp, RegTextOp, RegViewOp).  The AST supports:

- **Structured comparison**: relationship-preserving alpha-equivalence
  (`build_rule_fingerprint` / `rule_alpha_equal`) that recognizes two rules
  as equal when they differ only by consistent renumbering of placeholders,
  but distinguishes rules where the same placeholder maps to different
  operand positions.  The fingerprint is a nested tuple-of-tuples with
  explicit Guest/Host boundary markers and per-namespace canonical-ID maps
  that preserve alias relationships across both sides.
- **Substitution**: `substitute_imm` replaces an immediate placeholder with a
  literal value for consolidation (subsumed-rule detection).
- **Pre/post metadata ordering**: `Instruction.meta` holds pre-instruction
  annotations (e.g. `save`), `Instruction.post_meta` holds post-instruction
  annotations (e.g. `restore`).  This preserves the correct execution order:
  `save -> instruction -> restore`.

Consolidation (`consolidate_rules`) uses these AST primitives: a rule is
subsumed when substituting one of its `immN` placeholders with a reserved
literal (`0`, `00`, `000`) produces a structure alpha-equivalent to another
rule.

### Supported Memory Forms for Rules

- AArch64: `ldr`, `ldur`, `str`, `stur` with base-only, base+displacement,
  register-offset, and shifted-index (`lsl #N`) addressing.
- AArch64: `stp`, `ldp`, `stnp`, `ldnp` with offset, pre-index (`!`),
  and post-index forms.  Non-temporal variants (``ldnp``/``stnp``) do not
  support writeback (rejected per ISA rules).
- x86-64: `mov` with base-only, base+displacement, indexed
  (`base + index*scale`), and indexed+displacement addressing.
- x86-64: `push` and `pop` as implicit rsp-relative memory operands.
  64-bit registers (``rNN``, ``rax``, …) and 16-bit operand-size override
  forms (``rNNw``, ``ax``, …) are supported.  32-bit and 8-bit register
  names are rejected as not encodable in 64-bit mode.
- x86-64 memory-source arithmetic: `add`, `sub`, `and`, `or`, `xor`, `imul`
  with a memory source operand are parsed and verified.
- x86-64 memory-destination read-modify-write (RMW) remains unsupported.

Memory operands from stack-based instructions (``push``/``pop``,
``stp``/``ldp``) are matched by effective address displacement rather than
instruction order when both sides are homogeneous (all reads / all writes)
and non-overlapping.  This correctly pairs ``stp x0, x1, [sp, #-0x10]!``
with ``push rsi; push rdi`` by ascending address.  Overlapping or mixed
read/write stack accesses are rejected as
``memory_address_order_conflict``.

### Immediate Derivation

Host-only immediates are derived from guest placeholders through
instruction-aware templates registered per ``(guest_arch, host_arch)`` pair
in ``derivation._STRATEGIES``.  The derivation framework itself is
ISA-agnostic.

Immediate token syntax is selected independently for each side from its actual
architecture. Reversing the pipeline therefore emits x86-64 `immN` operands
on the Guest side and AArch64 `#immN` operands on the Host side; syntax is not
inferred from the Guest/Host role.

Current templates for ``("aarch64", "x86-64")``:

- **tbz/tbnz mask**: host mask derived as `(1 << immN)` from the guest
  bit-position immediate.
- **mov/movk constant**: host 64-bit constant derived as
  `(imm_high << imm_shift) | imm_low` from a guest `mov` + `movk` pair.
- **Indexed-address scale**: host x86 multiplier derived as `(1 << immN)`
  from the guest `lsl #immN` shift amount.  The ``*`` adjacency check uses
  the precise span of each ``immN`` occurrence, so the same immediate
  appearing as both scale and displacement in one operand is handled
  correctly.

Current templates for ``("x86-64", "aarch64")``:

- **Reverse indexed-address scale**: host AArch64 shift `lsl #immN` derived
  as `log2(guest_scale)` from the guest x86-64 ``*immN`` scale factor.
  The derivation validates that the guest occurrence is a scale factor
  (``*`` before the immediate in the operand text) and that the host
  occurrence is adjacent to ``lsl``.

Any host immediate that cannot be expressed through these templates causes
the rule to be skipped with `unpaired_host_immediate` (a universal rejection
condition, not limited to frame-relative memory rules).

### Fixed-role Registers

Some ISA-specific registers serve architecturally fixed roles (e.g. ``cl``
is the only valid shift-count register on x86-64).  Such registers are
classified via ``is_fixed_role_register()`` in ``arch/registers.py`` and are
emitted as literals in rule output.

For correctness, every fixed-role register *read* must have a visible
reaching definition earlier on the same side of the window. Surface inference
rejects an unbound read before candidate verification, and fixed-role registers
cannot appear in cross-ISA `input_registers` pairs. The producer target register
(e.g. ``ecx`` feeding into ``cl``) is preserved as a literal rather than
generalised to a ``tmpN`` placeholder, so the family relationship
(``ecx`` → ``cl``) is explicit in the emitted rule.  Rules lacking a
producer are rejected with ``unbound_fixed_role_register``.

**Provenance tracing** resolves the full backward slice of a fixed-role
consumer to its external inputs.  A producer's target must have a
covering bit range (``ecx`` covers ``cl``; ``ch`` does not) and belong to
the same register family.  All read dependencies of the producer are
recursively traced until every chain reaches a non-fixed-family mapped
input; any untraceable dependency causes rejection.

**Save/restore** annotations for fixed-role producer targets use the
widest family register (e.g. ``save rcx`` / ``restore rcx``) to
correctly preserve the full physical register, even when the instruction
text writes a sub-register (``ecx``, ``cx``, ``cl``).

The family and covering bit range are queried using the architecture of the
fragment being inspected. This policy is symmetric: neither Guest nor Host may
use a fixed-role register as an unexplained boundary value. Learning rules for
fixed-role values supplied directly at fragment entry remains unsupported.

### Register View / Cast Semantics

Some ISA patterns require a semantic input to appear at a different bit
width at a specific use point.  For example, when an i32 addition is
lowered to ``lea eax, [rdi + rsi]`` on x86-64, the 32‑bit semantic inputs
(``edi``, ``esi``) are accessed through their 64‑bit family registers
(``rdi``, ``rsi``) in the address expression.

The AST represents this with ``RegViewOp`` — a use‑site width view:

* ``reg64(i32_reg1)`` means: *low 32 bits bind to ``i32_reg1``, high 32
  bits are unspecified (fresh).*
* ``reg32(i64_reg1)`` means: *low 32 bits bind to ``i64_reg1``.*

``reg64(i32_regN)`` is **not** zero‑extension.  ``zext64``, ``sext64``,
and ``lo32`` are reserved for future use.

The view is resolved at rule‑generalization time by
``rules/register_views.py``, which detects when a physical register in the
instruction text belongs to the same family as a mapped placeholder but
has a wider bit range.  On the verifier side,
``verification/register_views.py`` widens input‑register initialization
so that the full family register is set to ``Concat(fresh_hi, semantic)``,
explicitly modelling the partial‑equality contract.

**Current scope** (first phase):

* Integer GPR only.
* x86‑64 ``lea`` address operands trigger the view resolver.
* Output verification compares only low bits (e.g. ``eax`` ↔ ``w0``).
* Guest‑side ``wN``/``xN`` widening is handled generically through the
  same ``register_family`` / ``register_bit_range`` queries — neither
  side is hard‑coded.

**Why not directly map ``rdi`` → ``i32_regN``?**  Mapping a 64‑bit
register to an ``i32`` placeholder would lose the information that only
the low 32 bits are constrained.  The ``reg64(i32_regN)`` notation makes
this explicit: a rule consumer knows that the upper 32 bits are free.

### Pointer Register Placeholders

Some kernel inputs have type ``ptr`` rather than an integer type.  Rule
generalization preserves this semantic role through ``RegisterBindingRole``
hints attached to ``VerificationCandidate.register_roles``.  When a
register pair has ``value_type == "ptr"``, the generalizer emits
``ptr64_regN`` instead of ``i64_regN``.

``ptr64_regN`` is semantically a 64-bit pointer — equal in width to
``i64_regN`` but distinguished in the rule format so that memory
operands explicitly reference pointer base registers rather than
general integer values.  The verifier initialises ``ptr64_regN`` as a
normal 64‑bit symbolic value; the distinction matters for rule matching
and is enforced only at the rule‑generalization stage.

### Kernel‑Declared Memory Semantics

The IR‑kernel model now supports explicit memory declarations that
bypass the older assembly‑window‑based memory surface inference.
Each memory kernel declares:

* **memory objects**: named regions (e.g. ``slot0``) with a base pointer
  name and element width (e.g. 32 bits for ``i32``).
* **memory accesses**: load or store operations referencing a memory
  object, with an address specification (base ± index × scale) and
  the kernel‐level value name for the loaded/stored value.

``KernelBindingBuilder.build_candidate()`` converts these declarations
into a ``MemorySpec`` with one slot, one binding, and one access
expectation per kernel memory access.  The address expressions use
machine register names resolved from the kernel’s ABI binding, so both
AArch64 and x86‑64 sides get the correct syntax spontaneously.

**Supported kernel forms (first stage):**

* Single‑slot memory — exactly one base pointer argument
* Must‑alias only (no ``may_alias``)
* No stack/frame‑local memory
* No memory‑to‑memory or read‑modify‑write
* Pointer arguments are 64‑bit ABI register arguments
* Indexed access with ``i64`` index and scale 4 (for ``i32``) or 8
  (for ``i64``)
* Both directions: AArch64 → x86‑64 and x86‑64 → AArch64

## Candidate Boundary

The request boundary is JSON-shaped and intentionally strict. All top-level
fields are required, unknown fields are rejected, and parsed payloads become
frozen dataclass models under `verification.candidate`.

This gives later pipeline stages a stable contract:

- candidate extraction emits structured candidates;
- verification emits structured reports;
- rule generalization consumes successful reports;
- coverage evaluation can aggregate report summaries and rejected features.

The current JSON fields and report shape are documented in
[Candidate Format](candidate-format.md).

## Status And Diagnostics

Every verification report has one of four top-level statuses:

- `pass`: all requested checks passed;
- `fail`: the verifier found a semantic counterexample;
- `unsupported`: the candidate requires a known but unsupported verifier
  capability;
- `error`: the verifier itself failed unexpectedly.

`unsupported` is an expected pipeline outcome and should be tracked as coverage
loss. `error` indicates a verifier bug, environment issue, or uncategorized
failure that should be investigated.

### Skip Pattern Analysis

The `diagnose-skips` CLI is a read-only observability tool for large skip
categories. It reuses extraction alignment and window enumeration, classifies
selected memory skip details, and writes pattern reports for
`unparsed_memory_access` and `one_sided_memory_access`. These reports are used
to decide whether the next improvement should extend memory operand parsing,
refine window pairing, or add a stack/frame abstraction. The analyzer must not
change candidate emission, verification, or rule generation behavior.

## Extension Points

Near-term extensions should preserve the existing verifier API and add new
semantic surfaces behind focused modules:

- precondition parsing and SMT constraint injection;
- direct branch target mapping checks;
- indirect branch target expression equivalence;
- richer memory alias constraints (may_alias, multi-slot memory surfaces);
- richer extraction beyond single-source smoke inputs;
- generalized memory rules for complex addressing (push/pop, ldp/stp, writeback);
- generalized branch-target rule output;
- rule store and coverage reporting against an external rule table.

When adding a new capability, prefer a typed model change in
`verification.candidate`, a small checker module, schema updates in `io`, and
focused tests that exercise both Python API and JSON/CLI behavior.
