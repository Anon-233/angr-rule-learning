# IR Kernel Learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the source/DWARF mining entry point with an IR-kernel based constructive learning pipeline that can compile builtin LLVM IR kernels, extract Guest/Host snippets, verify them, and emit rules.

**Architecture:** Add a new `angr_rule_learning.kernel` package as the main pipeline. It owns kernel models, hardcoded kernel synthesis, clang-based IR compilation, snippet extraction, ABI binding, diagnostics, and orchestration; it reuses existing `verification`, `rules`, `arch`, and JSON/rule writers.

**Tech Stack:** Python 3.14, clang, pyelftools/Capstone through existing `ObjectExtractor`, angr verifier, existing rule AST/generalizer/writer.

---

## File Structure

- Create `src/angr_rule_learning/kernel/models.py`: dataclasses for IR kernels, signatures, compiled kernels, snippets, binding specs, and pipeline diagnostics.
- Create `src/angr_rule_learning/kernel/synthesize.py`: builtin hardcoded scalar integer kernels.
- Create `src/angr_rule_learning/kernel/compile.py`: clang `-x ir -c` compiler driver.
- Create `src/angr_rule_learning/kernel/extract.py`: object-to-snippet extraction with conservative return/nop filtering.
- Create `src/angr_rule_learning/kernel/bind.py`: ABI-based register binding and candidate/window construction for scalar integer kernels.
- Create `src/angr_rule_learning/kernel/pipeline.py`: end-to-end constructive learning orchestration.
- Create `src/angr_rule_learning/kernel/__init__.py`: public package marker.
- Modify `src/angr_rule_learning/cli.py`: make `learn` the main constructive learning command; keep `verify` as a low-level utility.
- Add tests under `tests/test_kernel_*.py` and update CLI tests for the new `learn` command.
- Update `README.md` and `docs/architecture.md` after the MVP behavior is working.

## Task 1: Kernel Models

**Files:**
- Create: `src/angr_rule_learning/kernel/models.py`
- Create: `src/angr_rule_learning/kernel/__init__.py`
- Test: `tests/test_kernel_models.py`

- [ ] **Step 1: Write failing tests**

```python
from pathlib import Path

import pytest

from angr_rule_learning.kernel.models import (
    KernelConfig,
    KernelSignature,
    KernelValue,
)


def test_kernel_value_accepts_scalar_integer_types() -> None:
    value = KernelValue("a", "i32")
    assert value.name == "a"
    assert value.bit_width == 32


def test_kernel_value_rejects_unknown_types() -> None:
    with pytest.raises(ValueError, match="unsupported kernel value type"):
        KernelValue("a", "ptr")


def test_kernel_config_canonicalizes_architectures(tmp_path: Path) -> None:
    config = KernelConfig(work_dir=tmp_path, guest_arch="arm64", host_arch="amd64")
    assert config.guest_arch == "aarch64"
    assert config.host_arch == "x86-64"


def test_signature_rejects_missing_output() -> None:
    with pytest.raises(ValueError, match="at least one output"):
        KernelSignature(inputs=(KernelValue("a", "i32"),), outputs=())
```

- [ ] **Step 2: Run red test**

Run: `uv run pytest tests/test_kernel_models.py -q`

Expected: import failure because `angr_rule_learning.kernel` does not exist.

- [ ] **Step 3: Implement dataclasses**

Define immutable dataclasses:

- `KernelValue(name: str, type: str)` with `bit_width` property for `i8/i16/i32/i64`.
- `KernelSignature(inputs, outputs)` requiring at least one output for MVP.
- `KernelMetadata(op_kind, bit_width, has_memory=False, has_branch=False, has_immediate=False, notes=None)`.
- `IRKernel(id, name, llvm_ir, signature, metadata)`.
- `KernelConfig(work_dir, guest_arch="aarch64", host_arch="x86-64", clang="clang", optimization="1")`.
- `CompiledKernel`, `Snippet`, `BindingSpec`, `KernelRunRecord`, `KernelPipelineResult`.

- [ ] **Step 4: Run green test**

Run: `uv run pytest tests/test_kernel_models.py -q`

Expected: all tests pass.

## Task 2: Builtin Kernel Synthesizer

**Files:**
- Create: `src/angr_rule_learning/kernel/synthesize.py`
- Test: `tests/test_kernel_synthesize.py`

- [ ] **Step 1: Write failing tests**

```python
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


def test_builtin_synthesizer_emits_scalar_integer_kernels() -> None:
    kernels = HardcodedKernelSynthesizer().generate()
    names = {kernel.name for kernel in kernels}
    assert {"kernel_add_i32", "kernel_and_i32", "kernel_xor_i32"} <= names


def test_builtin_kernel_ir_is_single_function() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )
    assert "define i32 @kernel_add_i32(i32 %a, i32 %b)" in kernel.llvm_ir
    assert "ret i32 %r" in kernel.llvm_ir
    assert [value.name for value in kernel.signature.inputs] == ["a", "b"]
    assert [value.name for value in kernel.signature.outputs] == ["r"]
```

- [ ] **Step 2: Run red test**

Run: `uv run pytest tests/test_kernel_synthesize.py -q`

Expected: module import failure.

- [ ] **Step 3: Implement synthesizer**

Implement `HardcodedKernelSynthesizer.generate()` returning tuple of `IRKernel` for `add/sub/and/or/xor i32`. Leave variable shifts for a later task because LLVM shift poison semantics need constraints.

- [ ] **Step 4: Run green test**

Run: `uv run pytest tests/test_kernel_synthesize.py -q`

Expected: pass.

## Task 3: Clang IR Compiler and Snippet Extractor

**Files:**
- Create: `src/angr_rule_learning/kernel/compile.py`
- Create: `src/angr_rule_learning/kernel/extract.py`
- Test: `tests/test_kernel_compile_extract.py`

- [ ] **Step 1: Write failing tests**

```python
import shutil
import pytest

from angr_rule_learning.kernel.compile import KernelCompiler
from angr_rule_learning.kernel.extract import SnippetExtractor
from angr_rule_learning.kernel.models import KernelConfig
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_compile_and_extract_add_kernel_for_both_architectures(tmp_path) -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )
    config = KernelConfig(work_dir=tmp_path, optimization="1")
    compiled = KernelCompiler().compile_pair(kernel, config)
    snippets = SnippetExtractor().extract_pair(compiled, config)

    assert snippets.guest.instructions
    assert snippets.host.instructions
    assert all(inst.mnemonic != "ret" for inst in snippets.guest.instructions)
    assert all(inst.mnemonic != "ret" for inst in snippets.host.instructions)
    assert snippets.guest.instructions[0].arch == "aarch64"
    assert snippets.host.instructions[0].arch == "x86-64"
```

- [ ] **Step 2: Run red test**

Run: `uv run pytest tests/test_kernel_compile_extract.py -q`

Expected: module import failure.

- [ ] **Step 3: Implement compiler**

Write each kernel to `<work_dir>/<kernel_id>/<arch>.ll` and run:

```bash
clang -target <triple> -x ir -O<level> -c <input.ll> -o <output.o>
```

Use `arch.registry.clang_target()` for triples. Raise `RuntimeError` with stderr/stdout on compile failure.

- [ ] **Step 4: Implement extractor**

Reuse `ObjectExtractor.extract(object_path, arch)`, select the function by `kernel.name`, and remove only `ret`, `nop`, and `endbr64` in MVP. Return `SnippetPair`.

- [ ] **Step 5: Run green test**

Run: `uv run pytest tests/test_kernel_compile_extract.py -q`

Expected: pass or skip if clang is unavailable.

## Task 4: ABI Binding and Candidate Construction

**Files:**
- Create: `src/angr_rule_learning/kernel/bind.py`
- Test: `tests/test_kernel_bind.py`

- [ ] **Step 1: Write failing tests**

```python
from angr_rule_learning.kernel.bind import KernelBindingBuilder
from angr_rule_learning.kernel.models import BindingSpec
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


def test_scalar_i32_abi_binding_for_aarch64_to_x86_64() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )
    spec = KernelBindingBuilder().build_spec(kernel, "aarch64", "x86-64")
    assert spec.inputs == (("a", "w0", "edi"), ("b", "w1", "esi"))
    assert spec.outputs == (("r", "w0", "eax"),)


def test_scalar_i32_abi_binding_for_reverse_direction() -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )
    spec = KernelBindingBuilder().build_spec(kernel, "x86-64", "aarch64")
    assert spec.inputs == (("a", "edi", "w0"), ("b", "esi", "w1"))
    assert spec.outputs == (("r", "eax", "w0"),)
```

- [ ] **Step 2: Run red test**

Run: `uv run pytest tests/test_kernel_bind.py -q`

Expected: module import failure.

- [ ] **Step 3: Implement ABI binding**

Support scalar integer `i32/i64`, first four parameter registers, and one register return. Add `build_candidate(kernel, snippets, spec)` returning `(WindowPair, VerificationCandidate)`.

- [ ] **Step 4: Run green test**

Run: `uv run pytest tests/test_kernel_bind.py -q`

Expected: pass.

## Task 5: Constructive Pipeline and CLI

**Files:**
- Create: `src/angr_rule_learning/kernel/pipeline.py`
- Modify: `src/angr_rule_learning/cli.py`
- Test: `tests/test_kernel_pipeline.py`
- Test: `tests/test_batch_cli.py`

- [ ] **Step 1: Write failing tests**

```python
import shutil
import pytest

from angr_rule_learning.kernel.models import KernelConfig
from angr_rule_learning.kernel.pipeline import KernelLearningPipeline


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_kernel_pipeline_emits_verified_rules(tmp_path) -> None:
    result = KernelLearningPipeline().run(
        KernelConfig(work_dir=tmp_path / "work", optimization="1"),
        rules_output=tmp_path / "rules.txt",
        diagnostics_output=tmp_path / "diagnostics.json",
    )

    assert result.rules
    assert (tmp_path / "rules.txt").read_text(encoding="utf-8")
    assert result.diagnostics["kernels_total"] >= 1
    assert result.diagnostics["verified_pass"] >= 1
```

Add a CLI test invoking:

```python
main([
    "learn",
    "--work-dir", str(tmp_path / "work"),
    "--rules-output", str(tmp_path / "rules.txt"),
    "--diagnostics", str(tmp_path / "diagnostics.json"),
])
```

- [ ] **Step 2: Run red tests**

Run: `uv run pytest tests/test_kernel_pipeline.py tests/test_batch_cli.py -q`

Expected: `KernelLearningPipeline` or `learn` command missing.

- [ ] **Step 3: Implement pipeline**

For each builtin kernel:

1. Compile Guest/Host objects.
2. Extract snippets.
3. Build ABI binding and `VerificationCandidate`.
4. Verify with `BatchVerifier`.
5. If pass, generalize with `RuleGeneralizer`.
6. Write rules, diagnostics JSON, and optional candidates/reports JSONL.

- [ ] **Step 4: Replace CLI main route**

Expose:

```text
angr-rule-learning learn
  --work-dir PATH
  --rules-output PATH
  --diagnostics PATH
  --guest-arch aarch64
  --host-arch x86-64
  --clang clang
  --optimization 1
  --candidates-output PATH optional
  --reports-output PATH optional
  --rules-diagnostics PATH optional
  --rules-debug-diagnostics PATH optional
```

Keep `verify` as a low-level utility. Remove `extract` and `diagnose-skips` from the CLI parser.

- [ ] **Step 5: Run green tests**

Run:

```bash
uv run pytest tests/test_kernel_pipeline.py tests/test_batch_cli.py -q
```

Expected: pass.

## Task 6: Documentation and Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`

- [ ] **Step 1: Update docs**

Document the new constructive route as the primary architecture and remove old source-mining CLI examples from README.

- [ ] **Step 2: Format and lint**

Run:

```bash
uv run ruff format src tests
uv run ruff check
```

Expected: all clean.

- [ ] **Step 3: Full test suite**

Run:

```bash
uv run pytest -q
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

Commit all changes on `refactor/ir-kernel-learning` with co-author markers.

## Self-Review

- Spec coverage: this plan implements the constructive MVP, not memory kernels, branch kernels, immediate derivation redesign, or large kernel corpus synthesis.
- Placeholder scan: no TBD/TODO placeholders are used as implementation requirements.
- Type consistency: model names used in later tasks are introduced in Task 1.
