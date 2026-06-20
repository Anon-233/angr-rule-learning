# CEGIS Register Binding Prototype Design

## Context

The extraction pipeline independently infers Guest and Host register surfaces,
then converts those surfaces into `VerificationCandidate.input_registers` and
`output_registers`. The current `RegisterBindingSolver` is intentionally a
placeholder: it checks counts and surface kinds, then pairs registers by their
position with `zip`.

Positional pairing is not semantically valid across architectures. For example,
the equivalent fragments

```asm
Guest: lsl w0, w0, w1

Host:  mov ecx, esi
       mov eax, edi
       shl eax, cl
```

have boundary inputs `(w0, w1)` and `(esi, edi)` in first-read order. Positional
pairing produces `(w0, esi), (w1, edi)`, while the valid binding is
`(w0, edi), (w1, esi)`.

This design adds an opt-in counterexample-guided inductive synthesis (CEGIS)
prototype. It synthesizes finite register-binding selectors from concrete
samples and uses the existing `SemanticVerifier` to prove each proposed binding
over all symbolic inputs. The positional implementation remains the default
until the prototype's coverage and cost are understood.

## Goals

- Isolate CEGIS behind the existing register-binding boundary.
- Infer both input and output register bindings without relying on register
  order.
- Use finite-domain selector constraints rather than Python permutation loops.
- Accept a binding only after the existing verifier proves it equivalent.
- Feed verifier counterexamples back into selector synthesis.
- Expose the prototype through typed Python configuration and the `extract` CLI.
- Preserve default positional behavior and current pipeline results.

## Non-Goals

- Replacing the default binding strategy in this iteration.
- Supporting memory, branch, flag, vector, floating-point, or fixed-role live-in
  surfaces in the CEGIS prototype.
- Proving that a valid binding is unique.
- Building a general architecture-neutral instruction IR.
- Adding provenance or source-variable matching.
- Falling back to positional pairing when CEGIS cannot prove a result.

## Configuration and Selection

`ExtractionConfig` gains a validated binding strategy:

```python
register_binding: Literal["positional", "cegis"] = "positional"
```

The `extract` CLI gains:

```text
--register-binding {positional,cegis}
```

The default remains `positional`. Pipeline construction selects either the
existing positional `RegisterBindingSolver` or a new
`CegisRegisterBindingSolver` and injects it into `SurfaceInferer`. The core
pipeline does not inspect CLI arguments directly.

## Prototype Eligibility

CEGIS accepts a binding problem only when all of the following hold:

- both surfaces have kind `register`;
- the window has no modeled or detected memory access;
- neither fragment branches and each fragment produces exactly one successor;
- neither surface contains flag outputs or an external condition-code input;
- each side has between one and four integer inputs;
- each side has between one and four integer outputs;
- Guest and Host input counts match;
- Guest and Host output counts match;
- every input and output has at least one exact-width compatible register on the
  other side;
- no fixed-role register is an unexplained boundary input.

Ineligible problems return `unsupported_register_binding_surface`. CEGIS never
delegates such a problem to the positional solver.

## Data Model

The binding module owns the prototype-specific models:

```python
@dataclass(frozen=True)
class BindingProblem:
    pair: WindowPair
    guest_surface: WindowSurface
    host_surface: WindowSurface
    has_memory: bool


@dataclass(frozen=True)
class SymbolicRegisterTransfer:
    input_registers: tuple[str, ...]
    input_symbols: tuple[claripy.ast.BV, ...]
    input_widths: tuple[int, ...]
    output_registers: tuple[str, ...]
    output_expressions: tuple[claripy.ast.BV, ...]


@dataclass(frozen=True)
class BindingSample:
    guest_input_values: tuple[int, ...]
```

`RegisterBindingResult` gains an optional machine-readable `skip_detail` in
addition to its existing `skip_reason`. `SurfaceInferer` records both through
`MiningDiagnostics`.

This keeps memory eligibility decisions at the existing structured-memory
boundary rather than rediscovering memory access from instruction text.

## Symbolic Transfer Extraction

The CEGIS solver creates independent blank states for Guest and Host through
`FragmentExecutor`. Every declared boundary input receives a distinct BVS with
the physical register's exact width. Each fragment is executed for its declared
instruction count, and the declared outputs are read from the sole successor.

The resulting output expressions form side-local transfer functions. Guest and
Host symbols are deliberately independent at this stage.

Every output expression must depend only on the declared input symbols and
architecture-owned constants. If angr introduces an unconstrained register
variable that is not one of the surface inputs, the solver returns
`unmodeled_input`. This prevents synthesis from hiding an incomplete liveness
surface.

## Selector Synthesis

For each Host input, synthesis creates a finite-domain selector whose domain is
the exact-width compatible Guest inputs. Input selectors are constrained to be
all-different. Host output selectors similarly choose exact-width compatible
Guest outputs and are all-different.

Selectors are oriented Host-to-Guest because each Host symbolic input must be
replaced by one Guest semantic value. A successful model is inverted into the
existing Guest-to-Host pair representation.

For each `BindingSample`:

1. Replace Guest input BVS leaves with the sample's concrete bit vectors.
2. Replace each Host input BVS with a Claripy `If` expression selected from the
   same Guest sample values.
3. Evaluate Guest and Host output expressions under those replacements.
4. Constrain each Host output to equal the Guest output chosen by its output
   selector.

Claripy `replace_dict` performs expression substitution. Selector variables and
all accumulated sample constraints share one solver instance for a synthesis
round. The implementation must not construct or iterate all register
permutations in Python.

## CEGIS Loop

The prototype starts with one all-zero Guest input sample and uses a maximum of
16 iterations:

```text
samples = deterministic_initial_samples()

repeat up to 16 times:
    selectors = synthesize(samples)
    if no selector model exists:
        return register_binding_unsat

    candidate = build_register_only_candidate(selectors)
    report = SemanticVerifier.verify(candidate)

    if report passes:
        return selectors

    if report is unsupported or error:
        return register_binding_inconclusive

    counterexample = extract_guest_inputs(report)
    if counterexample is missing or already present:
        return register_binding_inconclusive

    samples.add(counterexample)

return register_binding_inconclusive
```

The first binding that passes full symbolic verification is returned
immediately. The prototype does not search for a second solution or require
uniqueness. This is sound because the returned mapping itself has been proved;
it also avoids penalizing symmetric operations such as addition.

## Verification Oracle

Selector synthesis does not decide correctness. A decoded binding is converted
to a temporary register-only `VerificationCandidate` and passed to the existing
`SemanticVerifier`.

Candidate fragment construction is extracted into a focused helper shared by
`SurfaceInferer` and the CEGIS verification oracle. This avoids duplicating code
hex, address, instruction-count, and candidate-id construction.

On a failed register check, the verifier already reports a concrete model. The
prototype reads values by Guest input name, truncates them to the declared Guest
width, and stores them in Guest surface order. Unsupported reports, internal
errors, absent counterexamples, and repeated counterexamples are inconclusive;
none may be treated as a valid binding.

## Failure Semantics

The solver uses three stable coarse reasons:

- `unsupported_register_binding_surface`: outside the prototype's declared
  semantic boundary;
- `register_binding_unsat`: selector constraints have no model for accumulated
  counterexamples;
- `register_binding_inconclusive`: execution, verification, or convergence did
  not establish a result.

Detailed diagnostics include:

```text
memory_surface
branch_surface
flag_surface
non_integer_register
register_limit_exceeded
width_domain_empty
unmodeled_input
execution_shape
verification_unsupported
verification_error
counterexample_missing
counterexample_repeated
iteration_limit
```

No failure path falls back to positional binding when `cegis` was requested.

## Testing and Acceptance

Implementation follows test-driven development. Required coverage includes:

1. Configuration validation and CLI strategy selection.
2. Positional binding remains the default and preserves existing output.
3. Selector domains enforce exact width and bijection constraints.
4. Symbolic transfer extraction rejects undeclared symbolic dependencies.
5. The incorrect shift binding produces a verifier counterexample.
6. Adding that counterexample causes synthesis to select
   `(w0, edi), (w1, esi)`.
7. The first fully verified binding terminates the loop without uniqueness
   search.
8. Missing or repeated counterexamples and the iteration limit return
   inconclusive results.
9. Memory, branch, flags, non-integer registers, and excessive register counts
   are rejected without positional fallback.
10. An end-to-end `rich_int.c` extraction with `--register-binding cegis`
    verifies the full `mov ecx, esi; mov eax, edi; shl eax, cl` window and emits
    a shift rule containing an explicit `mov ecx, i32_regN` producer.
11. No CEGIS output reintroduces a direct Guest-register-to-`cl` input binding.
12. The normal positional end-to-end smoke retains its current diagnostics and
    rule counts.

## Documentation

`docs/architecture.md` will describe both strategies, the opt-in boundary, and
the fact that the positional solver remains a known placeholder. CLI examples
will document how to run comparable positional and CEGIS extractions. Prototype
limitations and diagnostic reasons must remain explicit until the strategy is
expanded or made the default.
