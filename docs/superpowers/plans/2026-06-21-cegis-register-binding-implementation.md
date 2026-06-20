# CEGIS Register Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Keep the checklist current and follow TDD for every behavior change.

**Goal:** Add an opt-in CEGIS register-binding strategy that discovers Guest/Host input and output register mappings without relying on traversal order, then accepts the first mapping proved by the existing semantic verifier.

**Architecture:** Each eligible window is independently symbolically executed once per side to obtain cached register transfer expressions. A selector-based synthesizer uses concrete Guest samples to propose width-compatible bijective bindings. Every proposal is converted to a normal `VerificationCandidate` and passed to `SemanticVerifier`; a failing verifier counterexample becomes the next synthesis sample. Positional binding remains the default and CEGIS never silently falls back to it.

**Tech Stack:** Python 3.14, angr, claripy, pytest, Ruff, uv.

---

## Behavioral Boundary

- CEGIS supports straight-line, register-only integer windows with one successor.
- Each side must expose 1-4 inputs and 1-4 outputs with equal side counts.
- Domains require exact register-width compatibility and all-different selectors.
- Memory, branch, flag, vector/float, unexplained fixed-role live-ins, incomplete liveness, unsupported execution, and iteration exhaustion are explicit skips.
- Guest and Host transfer expressions are extracted once and reused across all synthesis rounds.
- The first binding that passes full symbolic verification terminates the search.
- Synthesis samples filter proposals; only the existing verifier establishes correctness.

## Planned Files

- Modify `src/angr_rule_learning/extraction/config.py`
- Modify `src/angr_rule_learning/extraction/register_bindings.py`
- Create `src/angr_rule_learning/extraction/candidates.py`
- Create `src/angr_rule_learning/extraction/register_transfer.py`
- Create `src/angr_rule_learning/extraction/register_cegis.py`
- Modify `src/angr_rule_learning/extraction/surfaces.py`
- Modify `src/angr_rule_learning/extraction/pipeline.py`
- Modify `src/angr_rule_learning/analysis/skip_patterns.py`
- Modify `src/angr_rule_learning/cli.py`
- Modify `scripts/run_all_tests.sh`
- Modify `README.md`
- Modify `docs/architecture.md`
- Modify focused tests under `tests/`

### Task 1: Typed Binding Problem and Shared Candidate Construction

**Files:**
- Modify: `src/angr_rule_learning/extraction/register_bindings.py`
- Create: `src/angr_rule_learning/extraction/candidates.py`
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Modify: `tests/test_extraction_register_bindings.py`
- Modify: `tests/test_extraction_surfaces.py`

- [ ] Add failing tests for a `BindingProblem` carrying the pair, both liveness surfaces, and structured memory presence.
- [ ] Add a `skip_detail` field to `RegisterBindingResult` and test that `SurfaceInferer` forwards it to `MiningDiagnostics`.
- [ ] Change the solver protocol to `solve(problem: BindingProblem)` while preserving positional behavior exactly.
- [ ] Extract `build_verification_candidate(pair, bindings, memory_spec, memory_inputs)` and candidate-id construction into `extraction/candidates.py`.
- [ ] Use the shared factory from `SurfaceInferer`; assert candidate JSON and existing surface behavior remain unchanged.
- [ ] Run:

```bash
uv run pytest -q tests/test_extraction_register_bindings.py tests/test_extraction_surfaces.py
uv run ruff format src tests
uv run ruff check src tests
```

- [ ] Commit: `Prepare semantic register binding boundary`.

### Task 2: One-Time Symbolic Register Transfer Extraction

**Files:**
- Create: `src/angr_rule_learning/extraction/register_transfer.py`
- Create: `tests/test_extraction_register_transfer.py`

- [ ] Write machine-code tests for AArch64 and x86-64 register-only fragments. Assert exact-width independent input BVS values and expected output dependencies.
- [ ] Add a test where an output depends on an undeclared input register and require `unmodeled_input`.
- [ ] Add zero/multiple-successor tests requiring `execution_shape`.
- [ ] Implement immutable `SymbolicRegisterTransfer` with ordered input names, input symbols, widths, output names, and output expressions.
- [ ] Implement `RegisterTransferExtractor` using `FragmentExecutor.make_state`, exact-width symbolic initialization, one execution, one successor, and output reads.
- [ ] Reject any symbolic leaf in an output expression that is not one of the declared side-local input symbols.
- [ ] Ensure extraction is side-local: Guest and Host symbols must never share names or identities.
- [ ] Run:

```bash
uv run pytest -q tests/test_extraction_register_transfer.py
uv run ruff format src/angr_rule_learning/extraction/register_transfer.py tests/test_extraction_register_transfer.py
uv run ruff check src/angr_rule_learning/extraction/register_transfer.py tests/test_extraction_register_transfer.py
```

- [ ] Commit: `Extract symbolic register transfer functions`.

### Task 3: Finite Selector Synthesis

**Files:**
- Create: `src/angr_rule_learning/extraction/register_cegis.py`
- Create: `tests/test_extraction_register_cegis.py`

- [ ] Build synthetic transfer-expression tests before integrating machine code.
- [ ] Test exact-width input/output selector domains and all-different constraints.
- [ ] Test that a swapped two-input shift transfer selects the semantic mapping rather than positional order.
- [ ] Test that inconsistent samples produce `register_binding_unsat`.
- [ ] Define `BindingSample(guest_input_values)` and a decoded selector mapping model.
- [ ] Implement Host-to-Guest finite selector variables using Claripy bitvectors, range/domain constraints, and pairwise inequality.
- [ ] For every sample, substitute Guest inputs with concrete BVVs and Host inputs with selector-controlled `If` expressions; constrain selected Guest outputs to equal Host outputs.
- [ ] Use `claripy.replace_dict` for cached transfer-expression substitution. Do not enumerate permutations in Python.
- [ ] Decode one satisfying model to the existing Guest-to-Host register-pair representation.
- [ ] Run:

```bash
uv run pytest -q tests/test_extraction_register_cegis.py -k selector
uv run ruff format src tests
uv run ruff check src tests
```

- [ ] Commit: `Synthesize register bindings with finite selectors`.

### Task 4: CEGIS Loop and Verifier Oracle

**Files:**
- Modify: `src/angr_rule_learning/extraction/register_cegis.py`
- Modify: `tests/test_extraction_register_cegis.py`

- [ ] Add eligibility tests for memory, branch, flags, non-integer registers, fixed-role live-ins, register limits, count mismatch, and empty width domains.
- [ ] Add fake transfer-extractor/synthesizer/verifier tests proving transfer extraction occurs once per side while multiple verifier rounds may occur.
- [ ] Test all-zero initialization, failed proposal counterexample feedback, repeated/missing counterexamples, verifier unsupported/error handling, and the 16-round cap.
- [ ] Test that the first verifier pass returns immediately without searching for uniqueness.
- [ ] Implement `CegisRegisterBindingSolver` with injected transfer extractor, selector synthesizer, candidate factory, and `SemanticVerifier` for focused tests.
- [ ] Decode a proposal through the shared candidate factory and invoke `SemanticVerifier.verify` as the sole acceptance oracle.
- [ ] Extract counterexample values only by Guest input register name, mask them to the declared width, preserve Guest surface order, and reject missing/repeated samples.
- [ ] Return stable coarse reasons and detailed reasons exactly as specified; never delegate to positional binding.
- [ ] Add a real machine-code regression for:

```asm
Guest: lsl w0, w0, w1
Host:  mov ecx, esi
       mov eax, edi
       shl eax, cl
```

  The accepted mapping must include `w0 <-> edi` and `w1 <-> esi`, not a direct `w1 <-> cl` binding.
- [ ] Run:

```bash
uv run pytest -q tests/test_extraction_register_cegis.py
uv run ruff format src tests
uv run ruff check src tests
```

- [ ] Commit: `Prove synthesized register bindings with CEGIS`.

### Task 5: Configuration, Pipeline, and CLI Integration

**Files:**
- Modify: `src/angr_rule_learning/extraction/config.py`
- Modify: `src/angr_rule_learning/extraction/pipeline.py`
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Modify: `src/angr_rule_learning/analysis/skip_patterns.py`
- Modify: `src/angr_rule_learning/cli.py`
- Modify: `tests/test_extraction_models.py`
- Modify: `tests/test_extraction_pipeline.py`
- Modify: `tests/test_analysis_skip_patterns.py`
- Modify: `tests/test_batch_cli.py`

- [ ] Add tests for `ExtractionConfig(register_binding="positional" | "cegis")`, default positional selection, and invalid strategy rejection.
- [ ] Add CLI parser/propagation tests for `--register-binding {positional,cegis}`.
- [ ] Add a solver factory that receives the existing `SemanticVerifier`; keep solver construction out of `SurfaceInferer`.
- [ ] Inject the selected solver from `ExtractionPipeline` and diagnostic analysis paths.
- [ ] Ensure fake batch verifiers used by tests do not need a semantic verifier unless CEGIS is selected; fail clearly if CEGIS lacks an oracle.
- [ ] Record `skip_reason` and `skip_detail` without changing positional diagnostics.
- [ ] Run:

```bash
uv run pytest -q tests/test_extraction_models.py tests/test_extraction_pipeline.py tests/test_analysis_skip_patterns.py tests/test_batch_cli.py
uv run ruff format src tests
uv run ruff check src tests
```

- [ ] Commit: `Expose opt-in CEGIS register binding`.

### Task 6: End-to-End Acceptance and Yield Evidence

**Files:**
- Modify: `tests/test_extraction_pipeline.py`
- Modify: `scripts/run_all_tests.sh`
- Modify: `README.md`
- Modify: `docs/architecture.md`

- [ ] Add an end-to-end test using the existing rich integer source and sufficient window limits to include the complete x86 fixed-role producer sequence.
- [ ] Assert CEGIS verifies the shift candidate and emitted rule contains an explicit `mov ecx, i32_regN` before `shl ..., cl`.
- [ ] Assert no candidate or rule contains a direct Guest-register-to-`cl` input binding.
- [ ] Extend `scripts/run_all_tests.sh` with an optional binding-strategy argument defaulting to positional.
- [ ] Run comparable positional and CEGIS extraction commands into ignored `runs/` directories and record diagnostics in the final report.
- [ ] Document configuration, one-time transfer extraction, selector synthesis, verifier feedback, supported boundary, diagnostics, and lack of positional fallback.
- [ ] Run:

```bash
uv run pytest -q tests/test_extraction_pipeline.py
./scripts/run_all_tests.sh samples/sources/rich_int.c runs/cegis-rich 1 cegis
./scripts/run_all_tests.sh samples/sources/smoke_int.c runs/positional-smoke 0 positional
```

- [ ] Commit: `Validate CEGIS register binding end to end`.

### Task 7: Full Verification, Review, and Main Integration

- [ ] Run the complete quality gate:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
git diff --check
git status --short
```

- [ ] Review for architecture direction assumptions, especially any binding of Guest to AArch64 or Host to x86-64.
- [ ] Review that transfer extraction occurs exactly once per side per `solve()` and that CEGIS rounds only reuse expressions.
- [ ] Review that synthesis never decides correctness and every returned mapping was accepted by `SemanticVerifier`.
- [ ] Review that unsupported CEGIS cases never fall back to positional pairing.
- [ ] Review diagnostics and public documentation against actual behavior.
- [ ] Fix findings with focused regression tests and commits.
- [ ] Merge the feature branch into `main`, rerun the complete quality gate on `main`, and report commit hashes plus positional/CEGIS acceptance results.

## Execution Status

Implemented on `feature/cegis-register-binding`:

- Tasks 1-6, including typed binding problems, shared candidate construction,
  one-time symbolic transfer extraction, finite selector synthesis, the CEGIS
  verifier loop, CLI/config integration, documentation, and end-to-end tests.
- Architecture-direction regression coverage for the fixed-role shift mapping.
- A control-flow classifier correction so AArch64 `bic`/`bfi` are not treated
  as branches while x86 jump, call, return, and interrupt variants remain
  recognized.

Acceptance evidence:

- full pytest suite: 467 tests passed;
- CEGIS `rich_int.c -O1`: 51 candidates emitted, 51 verifier passes, 18 rules;
- emitted shift rules contain an explicit `mov ecx, i32_regN` producer;
- positional `smoke_int.c -O0`: 210 candidates, 120 verifier passes, 13 rules.

Review fixes completed before integration:

- ordinary `ecx`/`rcx` inputs are no longer rejected as fixed-role live-ins;
  only the actual fixed-role `cl` boundary remains unsupported;
- expected angr execution exceptions map to `execution_shape`, while unexpected
  implementation exceptions are no longer hidden by a broad catch.

The remaining action is Task 7 Git commit/merge and the final post-merge quality
gate.
