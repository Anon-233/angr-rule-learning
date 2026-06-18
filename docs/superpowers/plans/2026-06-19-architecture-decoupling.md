# Architecture Decoupling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove implicit Guest=AArch64 and Host=x86-64 assumptions while preserving the current default pipeline and adding a complete x86-64 Guest to AArch64 Host smoke path.

**Architecture:** Introduce a central architecture capability layer for canonical names, compiler targets, register families, bit ranges, frame roles, and fixed roles. Extraction, verification, and rule generalization will query capabilities using each fragment's actual architecture; only genuinely directional translation knowledge remains keyed by `(guest_arch, host_arch)`.

**Tech Stack:** Python 3.14, angr/claripy, archinfo, Capstone, pyelftools, pytest, Ruff, uv, clang.

---

## File Structure

- Modify `src/angr_rule_learning/arch/registry.py`: canonical architecture names, angr names, and clang targets.
- Create `src/angr_rule_learning/arch/registers.py`: shared register families, bit ranges, frame roles, fixed roles, and cross-architecture frame compatibility.
- Modify `src/angr_rule_learning/extraction/config.py`: normalize configured architecture aliases.
- Modify `src/angr_rule_learning/extraction/build.py`: obtain target triples from the architecture registry.
- Modify `src/angr_rule_learning/extraction/liveness.py`: delegate shared family normalization to `arch.registers` while retaining liveness and ABI policy.
- Modify `src/angr_rule_learning/extraction/memory_surfaces.py`: replace directional frame-register sets with symmetric capability queries.
- Modify `src/angr_rule_learning/verification/memory.py`: use candidate fragment architectures for frame grouping and initialization.
- Modify `src/angr_rule_learning/rules/registers.py`: delegate canonical names and register-role data to `arch` while retaining rule classification.
- Modify `src/angr_rule_learning/rules/generalize.py`: make fixed-role provenance and dead-write rewriting architecture-aware per side.
- Modify `src/angr_rule_learning/cli.py`: expose guest and host architecture options for extraction and diagnostics.
- Create `tests/test_arch_capabilities.py`: focused capability-layer tests.
- Modify `tests/test_extraction_build.py`: canonical target and reverse-direction build tests.
- Modify `tests/test_extraction_memory_surfaces.py`: reverse frame-surface test.
- Modify `tests/test_verifier_memory.py`: reverse frame-verification test.
- Modify `tests/test_rules_generalize.py`: side-isolation and host-capability regression tests.
- Modify `tests/test_batch_cli.py`: CLI argument propagation tests.
- Modify `tests/test_extraction_pipeline.py`: full reverse-direction source-to-rule smoke.
- Modify `docs/architecture.md`: architecture capability boundary and legal directionality.

### Task 1: Central Architecture Registry

**Files:**
- Modify: `src/angr_rule_learning/arch/registry.py`
- Test: `tests/test_arch_capabilities.py`

- [ ] **Step 1: Write failing canonical-name and target tests**

```python
import pytest

from angr_rule_learning.arch.registry import (
    canonical_arch_name,
    clang_target,
)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("AARCH64", "aarch64"),
        ("arm64", "aarch64"),
        ("AMD64", "x86-64"),
        ("x86_64", "x86-64"),
    ],
)
def test_canonical_arch_name_normalizes_supported_aliases(name, expected):
    assert canonical_arch_name(name) == expected


def test_clang_target_is_selected_by_architecture():
    assert clang_target("aarch64") == "aarch64-linux-gnu"
    assert clang_target("amd64") == "x86_64-linux-gnu"


def test_unknown_architecture_is_rejected():
    with pytest.raises(ValueError, match="unsupported architecture"):
        canonical_arch_name("made-up-isa")
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `uv run pytest -q tests/test_arch_capabilities.py`

Expected: collection or import failure because `canonical_arch_name` and `clang_target` are not exported by `arch.registry`.

- [ ] **Step 3: Add immutable architecture records and public queries**

Implement a private record and alias map in `arch/registry.py`:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class _Architecture:
    name: str
    angr_name: str
    clang_target: str | None = None


_ARCHITECTURES = {
    "arm": _Architecture("arm", "ARMEL"),
    "x86": _Architecture("x86", "X86"),
    "aarch64": _Architecture("aarch64", "AARCH64", "aarch64-linux-gnu"),
    "x86-64": _Architecture("x86-64", "AMD64", "x86_64-linux-gnu"),
}

_ALIASES = {
    "arm": "arm",
    "armel": "arm",
    "x86": "x86",
    "i386": "x86",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "amd64": "x86-64",
    "x86_64": "x86-64",
    "x86-64": "x86-64",
}


def canonical_arch_name(arch: str) -> str:
    try:
        return _ALIASES[arch.strip().lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {arch}") from exc


def angr_arch_name(arch: str) -> str:
    return _ARCHITECTURES[canonical_arch_name(arch)].angr_name


def clang_target(arch: str) -> str:
    canonical = canonical_arch_name(arch)
    target = _ARCHITECTURES[canonical].clang_target
    if target is None:
        raise ValueError(f"unsupported extraction target: {arch}")
    return target
```

- [ ] **Step 4: Run focused and existing registry users**

Run: `uv run pytest -q tests/test_arch_capabilities.py tests/test_schema.py tests/test_extraction_build.py`

Expected: all tests pass.

- [ ] **Step 5: Format and commit**

Run: `uv run ruff format src/angr_rule_learning/arch/registry.py tests/test_arch_capabilities.py && uv run ruff check src/angr_rule_learning/arch/registry.py tests/test_arch_capabilities.py`

Commit:

```bash
git add src/angr_rule_learning/arch/registry.py tests/test_arch_capabilities.py
git commit -m "Centralize architecture identity and targets" -m "Co-authored-by: Codex <codex@openai.com>"
```

### Task 2: Shared Register Capabilities

**Files:**
- Create: `src/angr_rule_learning/arch/registers.py`
- Modify: `src/angr_rule_learning/extraction/liveness.py`
- Modify: `src/angr_rule_learning/rules/registers.py`
- Modify: `tests/test_arch_capabilities.py`
- Modify: `tests/test_rules_registers.py`

- [ ] **Step 1: Add failing tests for families, ranges, roles, and symmetry**

```python
from angr_rule_learning.arch.registers import (
    fixed_role_preserve_register,
    is_compatible_frame_base_pair,
    is_fixed_role_register,
    register_bit_range,
    register_family,
)


def test_register_capabilities_are_selected_by_explicit_architecture():
    assert register_family("aarch64", "w8") == "x8"
    assert register_family("x86-64", "eax") == "rax"
    assert register_bit_range("aarch64", "w8") == (0, 31)
    assert register_bit_range("x86-64", "ch") == (8, 15)
    assert is_fixed_role_register("x86-64", "cl")
    assert not is_fixed_role_register("aarch64", "w1")
    assert fixed_role_preserve_register("x86-64", "ecx") == "rcx"


def test_frame_base_compatibility_is_symmetric():
    forward = is_compatible_frame_base_pair("aarch64", "sp", "x86-64", "rbp")
    reverse = is_compatible_frame_base_pair("x86-64", "rbp", "aarch64", "sp")
    assert forward
    assert reverse
```

- [ ] **Step 2: Run the focused tests and verify import failure**

Run: `uv run pytest -q tests/test_arch_capabilities.py`

Expected: FAIL because `arch.registers` does not exist.

- [ ] **Step 3: Implement architecture-owned register capabilities**

Create `arch/registers.py` with architecture-keyed immutable tables and these APIs:

```python
def normalize_register_name(register: str) -> str:
    return register.strip().lower()


def register_family(arch: str, register: str) -> str:
    canonical = canonical_arch_name(arch)
    register = normalize_register_name(register)
    if canonical == "aarch64":
        return _aarch64_family(register)
    if canonical == "x86-64":
        return _x86_64_family(register)
    return register


def register_bit_range(arch: str, register: str) -> tuple[int, int] | None:
    canonical = canonical_arch_name(arch)
    register = normalize_register_name(register)
    if canonical == "aarch64":
        return _aarch64_bit_range(register)
    if canonical == "x86-64":
        return _X86_64_BIT_RANGES.get(register)
    return None


def is_compatible_frame_base_pair(
    left_arch: str,
    left_register: str | None,
    right_arch: str,
    right_register: str | None,
) -> bool:
    if left_register is None or right_register is None:
        return False
    left_width = frame_base_width(left_arch, left_register)
    right_width = frame_base_width(right_arch, right_register)
    return left_width is not None and left_width == right_width
```

Move the AArch64 and x86-64 family aliases, stack/frame widths, fixed-role set, and x86 bit ranges into this module. `fixed_role_preserve_register()` returns the canonical full-width family head only when the register belongs to a configured fixed-role family.

- [ ] **Step 4: Delegate existing public functions without changing callers yet**

In `extraction/liveness.py`, import `register_family` and retain compatibility:

```python
def family_for_register(arch: str, register: str) -> str:
    return register_family(arch, register)
```

In `rules/registers.py`, import and re-export `canonical_arch_name`, `normalize_register_name`, stack/frame placeholder functions, and `is_fixed_role_register` from `arch`. Remove duplicated role tables while retaining `RegisterClass`, `classify_register`, allowed literal policy, and known-token construction.

- [ ] **Step 5: Run register and liveness tests**

Run: `uv run pytest -q tests/test_arch_capabilities.py tests/test_rules_registers.py tests/test_extraction_liveness.py`

Expected: all tests pass with existing classification and liveness behavior unchanged.

- [ ] **Step 6: Format and commit**

Run: `uv run ruff format src/angr_rule_learning/arch/registers.py src/angr_rule_learning/extraction/liveness.py src/angr_rule_learning/rules/registers.py tests/test_arch_capabilities.py tests/test_rules_registers.py && uv run ruff check src tests`

Commit:

```bash
git add src/angr_rule_learning/arch/registers.py src/angr_rule_learning/extraction/liveness.py src/angr_rule_learning/rules/registers.py tests/test_arch_capabilities.py tests/test_rules_registers.py
git commit -m "Centralize register architecture capabilities" -m "Co-authored-by: Codex <codex@openai.com>"
```

### Task 3: Architecture-Aware Build and CLI Configuration

**Files:**
- Modify: `src/angr_rule_learning/extraction/build.py`
- Modify: `src/angr_rule_learning/cli.py`
- Modify: `tests/test_extraction_build.py`
- Modify: `tests/test_batch_cli.py`

- [ ] **Step 1: Add failing reverse build and CLI propagation tests**

Add to `tests/test_extraction_build.py`:

```python
def test_build_driver_supports_reverse_architecture_direction(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    runner = RecordingRunner()
    config = ExtractionConfig(
        source=source,
        work_dir=tmp_path / "out",
        guest_arch="x86_64",
        host_arch="arm64",
    )

    artifacts = ClangBuildDriver(runner=runner).build(config)

    assert artifacts.guest_object.name == "guest-x86-64.o"
    assert artifacts.host_object.name == "host-aarch64.o"
    assert runner.commands[0][:3] == ["clang", "-target", "x86_64-linux-gnu"]
    assert runner.commands[1][:3] == ["clang", "-target", "aarch64-linux-gnu"]
```

Add CLI tests that capture the constructed configuration without invoking clang:

```python
def test_extract_cli_propagates_architecture_direction(tmp_path, monkeypatch):
    captured = {}

    def fake_run(self, config, **kwargs):
        captured["config"] = config

    monkeypatch.setattr(
        "angr_rule_learning.cli.ExtractionPipeline.run", fake_run
    )
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")

    main(
        [
            "extract",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(tmp_path / "candidates.jsonl"),
            "--diagnostics",
            str(tmp_path / "diagnostics.json"),
            "--guest-arch",
            "x86_64",
            "--host-arch",
            "arm64",
        ]
    )

    assert captured["config"].guest_arch == "x86-64"
    assert captured["config"].host_arch == "aarch64"


def test_diagnose_cli_propagates_architecture_direction(tmp_path, monkeypatch):
    captured = {}

    def fake_analyze(self, config):
        captured["config"] = config
        return {}

    monkeypatch.setattr(
        "angr_rule_learning.cli.SkipPatternAnalyzer.analyze", fake_analyze
    )
    source = tmp_path / "sample.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")

    main(
        [
            "diagnose-skips",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
            "--output",
            str(tmp_path / "patterns.json"),
            "--guest-arch",
            "x86-64",
            "--host-arch",
            "aarch64",
        ]
    )

    assert captured["config"].guest_arch == "x86-64"
    assert captured["config"].host_arch == "aarch64"
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest -q tests/test_extraction_build.py tests/test_batch_cli.py`

Expected: reverse build uses unnormalized filenames or CLI rejects the new arguments.

- [ ] **Step 3: Normalize configuration and delegate compiler targets**

Add `ExtractionConfig.__post_init__()` using `object.__setattr__` because the dataclass is frozen:

```python
def __post_init__(self) -> None:
    object.__setattr__(self, "guest_arch", canonical_arch_name(self.guest_arch))
    object.__setattr__(self, "host_arch", canonical_arch_name(self.host_arch))
```

Delete `TARGETS` from `extraction/build.py` and replace its lookup with:

```python
target = clang_target(arch)
```

- [ ] **Step 4: Add architecture options to both commands**

Define one helper in `cli.py`:

```python
def _add_architecture_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--guest-arch", default="aarch64")
    parser.add_argument("--host-arch", default="x86-64")
```

Call it for `extract_parser` and `diagnose_parser`, then pass
`guest_arch=args.guest_arch` and `host_arch=args.host_arch` to both `ExtractionConfig`
constructors.

- [ ] **Step 5: Run focused tests**

Run: `uv run pytest -q tests/test_extraction_build.py tests/test_batch_cli.py tests/test_analysis_cli.py`

Expected: all tests pass, including aliases normalized before object naming.

- [ ] **Step 6: Format and commit**

Run: `uv run ruff format src/angr_rule_learning/extraction/config.py src/angr_rule_learning/extraction/build.py src/angr_rule_learning/cli.py tests/test_extraction_build.py tests/test_batch_cli.py && uv run ruff check src tests`

Commit:

```bash
git add src/angr_rule_learning/extraction/config.py src/angr_rule_learning/extraction/build.py src/angr_rule_learning/cli.py tests/test_extraction_build.py tests/test_batch_cli.py
git commit -m "Expose architecture direction in extraction CLI" -m "Co-authored-by: Codex <codex@openai.com>"
```

### Task 4: Symmetric Frame Memory Surfaces

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Modify: `tests/test_extraction_memory_surfaces.py`

- [ ] **Step 1: Add a failing reverse frame-pair test**

```python
def test_reverse_frame_address_pairs_are_not_shared_input_registers():
    surface = infer_memory_surface(
        _pair(
            (_inst("x86-64", 0x1000, "mov", "dword ptr [rbp - 4], eax"),),
            (_inst("aarch64", 0x2000, "str", "w0, [sp, #12]"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "rbp - 4"
    assert surface.spec.bindings[0].host_addr == "sp + 12"
    assert ("rbp", "sp") not in surface.input_registers
    assert ("eax", "w0") in surface.input_registers
```

- [ ] **Step 2: Run the test and confirm the directional defect**

Run: `uv run pytest -q tests/test_extraction_memory_surfaces.py::test_reverse_frame_address_pairs_are_not_shared_input_registers`

Expected: FAIL because `rbp`/`sp` is treated as an ordinary shared input pair.

- [ ] **Step 3: Replace side-specific sets with capability lookup**

Delete `_AARCH64_FRAME_REGS`, `_X86_64_FRAME_REGS`, and the fixed-direction predicate.
Use the actual operand architectures:

```python
def _is_frame_address_pair(
    guest_arch: str,
    guest_reg: str | None,
    host_arch: str,
    host_reg: str | None,
) -> bool:
    return is_compatible_frame_base_pair(
        guest_arch, guest_reg, host_arch, host_reg
    )
```

Update every call to pass the architecture from the corresponding
`ExtractedInstruction` or window fragment. Do not infer architecture from the side.

- [ ] **Step 4: Run all memory-surface tests**

Run: `uv run pytest -q tests/test_extraction_memory_operands.py tests/test_extraction_memory_surfaces.py`

Expected: all tests pass in both directions.

- [ ] **Step 5: Format and commit**

Run: `uv run ruff format src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_surfaces.py && uv run ruff check src tests`

Commit:

```bash
git add src/angr_rule_learning/extraction/memory_surfaces.py tests/test_extraction_memory_surfaces.py
git commit -m "Make frame memory surface pairing symmetric" -m "Co-authored-by: Codex <codex@openai.com>"
```

### Task 5: Symmetric Frame Memory Verification

**Files:**
- Modify: `src/angr_rule_learning/verification/memory.py`
- Modify: `tests/test_verifier_memory.py`

- [ ] **Step 1: Add a failing reverse machine-code verification test**

Reuse the existing frame-store bytes with sides reversed:

```python
def test_verifier_accepts_reverse_frame_relative_store():
    candidate = VerificationCandidate(
        candidate_id="reverse-frame-store32",
        guest=CodeFragment("x86-64", 0x8048000, X86_64_MOV_RBP_MINUS4_EDI, 1),
        host=CodeFragment("aarch64", 0x10000, AARCH64_STR_W0_SP12, 1),
        input_registers=(("edi", "w0"),),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "rbp - 4", "sp + 12", "write"),),
            accesses=(MemoryAccessExpectation("mem0", "write", 4),),
        ),
    )

    report = SemanticVerifier().verify(candidate)

    assert report.status == "pass", report
```

- [ ] **Step 2: Run the test and verify failure**

Run: `uv run pytest -q tests/test_verifier_memory.py::test_verifier_accepts_reverse_frame_relative_store`

Expected: FAIL because reverse frame bases are allocated as unrelated ordinary bases.

- [ ] **Step 3: Pass candidate architectures into frame grouping**

Replace `_is_frame_register_pair(guest_reg, host_reg)` with:

```python
def _is_frame_register_pair(
    candidate: VerificationCandidate,
    guest_reg: str | None,
    host_reg: str | None,
) -> bool:
    return is_compatible_frame_base_pair(
        candidate.guest.arch,
        guest_reg,
        candidate.host.arch,
        host_reg,
    )
```

Use this function in `_initialize_memory_registers()` and `_collect_frame_groups()`.
Delete the direction-specific frame-register sets. Preserve all existing offset
consistency and multi-slot allocation checks.

- [ ] **Step 4: Run verifier memory regressions**

Run: `uv run pytest -q tests/test_verifier_memory.py tests/test_memory_correctness.py tests/test_memory_events.py`

Expected: forward, reverse, multi-slot, and slot-order tests all pass.

- [ ] **Step 5: Format and commit**

Run: `uv run ruff format src/angr_rule_learning/verification/memory.py tests/test_verifier_memory.py && uv run ruff check src tests`

Commit:

```bash
git add src/angr_rule_learning/verification/memory.py tests/test_verifier_memory.py
git commit -m "Make frame memory verification direction independent" -m "Co-authored-by: Codex <codex@openai.com>"
```

### Task 6: Isolate Host Fixed-Role Policy

**Files:**
- Modify: `src/angr_rule_learning/rules/generalize.py`
- Modify: `tests/test_rules_generalize.py`

- [ ] **Step 1: Add failing architecture and side-isolation regressions**

Add focused tests proving:

Add direct capability-use tests:

```python
def test_writer_coverage_uses_explicit_architecture():
    assert _writer_covers_consumer("x86-64", "ecx", "cl")
    assert not _writer_covers_consumer("x86-64", "ch", "cl")
    assert _writer_covers_consumer("aarch64", "x1", "w1")


def test_guest_fixed_role_is_detected_with_guest_architecture():
    candidate = VerificationCandidate(
        candidate_id="reverse-fixed-role",
        guest=CodeFragment("x86-64", 0x1000, "0102", 1),
        host=CodeFragment("aarch64", 0x2000, "01020304", 1),
        input_registers=(("cl", "w1"),),
    )

    with pytest.raises(_RuleSkip) as excinfo:
        _build_placeholder_map(candidate, "x86-64", "aarch64")

    assert excinfo.value.reason == "unsupported_rule_shape"
```

Add a dead-write regression using the existing `_inst` and `_window_pair` helpers:

```python
def test_dead_write_save_restore_uses_guest_architecture():
    window = _window_pair(
        (
            _inst(
                "x86-64",
                0x1000,
                "mov",
                "ecx, edi",
                write_registers=("ecx",),
                read_registers=("edi",),
            ),
        ),
        (
            _inst(
                "aarch64",
                0x2000,
                "mov",
                "w8, w0",
                write_registers=("w8",),
                read_registers=("w0",),
            ),
        ),
    )
    candidate = VerificationCandidate(
        candidate_id="reverse-dead-write",
        guest=CodeFragment("x86-64", 0x1000, "0102", 1),
        host=CodeFragment("aarch64", 0x2000, "01020304", 1),
        input_registers=(("edi", "w0"), ("ecx", "w8")),
    )
    guest, _host = _annotate_dead_writes(
        _instructions_to_ast(window.guest.instructions),
        _instructions_to_ast(window.host.instructions),
        candidate,
        window,
        {"edi": "i32_reg1", "w0": "i32_reg1", "ecx": "ecx", "w8": "i32_reg2"},
        "x86-64",
        "aarch64",
    )

    assert "save rcx" in guest[0].to_text()
    assert "restore rcx" in guest[0].to_text()
```

Import `_annotate_dead_writes`, `_build_placeholder_map`, and
`_writer_covers_consumer` in the test module.

- [ ] **Step 2: Run the focused tests and verify failures**

Run: `uv run pytest -q tests/test_rules_generalize.py -k 'writer_covers or fixed_role or dead_write_arch'`

Expected: at least the AArch64 coverage and side-isolation cases fail under the
hardcoded x86/Host behavior.

- [ ] **Step 3: Replace hardcoded bit-range and family logic**

Change the helper to require architecture explicitly:

```python
def _writer_covers_consumer(arch: str, writer: str, consumer: str) -> bool:
    writer_range = register_bit_range(arch, writer)
    consumer_range = register_bit_range(arch, consumer)
    if writer_range is None or consumer_range is None:
        return False
    if register_family(arch, writer) != register_family(arch, consumer):
        return False
    return (
        writer_range[0] <= consumer_range[0]
        and writer_range[1] >= consumer_range[1]
    )
```

Pass `host_arch` from `_collect_fixed_role_sources()` and
`_require_fixed_role_producers()`. Replace `_fixed_family_for_arch()` and
`_save_restore_form()` table logic with `arch.registers` capability queries.

- [ ] **Step 4: Correct placeholder mapping and literal ownership**

In `_build_placeholder_map()`, determine fixed-role status independently:

```python
guest_fixed = is_fixed_role_register(guest_arch, guest_reg)
host_fixed = is_fixed_role_register(host_arch, host_reg)
if guest_fixed:
    raise _RuleSkip("unsupported_rule_shape")
mapping[guest_reg] = existing
if not host_fixed:
    mapping[host_reg] = existing
```

This preserves the supported generic-Guest to fixed-role-Host path while safely
rejecting a fixed-role Guest value that the current rule model cannot bind to a
generic Host placeholder. Retain conflict checks before assignment. In
`RuleGeneralizer.generate()`, call:

```python
guest_insts = _generalize_instructions_with_roles(
    guest_insts,
    window.guest.instructions,
    mapping,
    role_split,
    guest_arch,
)
host_insts = _generalize_instructions_with_roles(
    host_insts,
    window.host.instructions,
    mapping,
    role_split,
    host_arch,
    allowed_literals=fixed_producers,
)
```

- [ ] **Step 5: Make dead-write AST conversion side-aware**

Change `_text_to_regop` to accept `arch`, validate physical tokens only against
`known_register_tokens(arch)`, and normalize save/restore with that architecture.
Change `_apply` to accept `arch` and invoke:

```python
return (
    _apply(guest_insts, window.guest.instructions, guest_arch),
    _apply(host_insts, window.host.instructions, host_arch),
)
```

- [ ] **Step 6: Run all rule tests**

Run: `uv run pytest -q tests/test_rules_registers.py tests/test_rules_generalize.py tests/test_rules_memory_generalize.py tests/test_rules_writer.py`

Expected: all rule tests pass; existing x86-64 `cl` provenance behavior is unchanged.

- [ ] **Step 7: Format and commit**

Run: `uv run ruff format src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py && uv run ruff check src tests`

Commit:

```bash
git add src/angr_rule_learning/rules/generalize.py tests/test_rules_generalize.py
git commit -m "Decouple rule generalization from host ISA assumptions" -m "Co-authored-by: Codex <codex@openai.com>"
```

### Task 7: Bidirectional End-to-End Acceptance

**Files:**
- Modify: `tests/test_extraction_pipeline.py`
- Modify: `docs/architecture.md`

- [ ] **Step 1: Add a reverse full-pipeline smoke test**

Add a test using `ExtractionPipeline` directly so the full report set can be
inspected, while Task 3 separately covers CLI argument propagation:

```python
result = ExtractionPipeline().run(
    ExtractionConfig(
        source=source,
        work_dir=tmp_path / "work",
        guest_arch="x86-64",
        host_arch="aarch64",
    ),
    candidates_output=candidates_output,
    diagnostics_output=diagnostics_output,
    verify=True,
    rules_output=rules_output,
    rules_diagnostics_output=rules_diagnostics_output,
)
```

Assert:

```python
candidates = list(read_candidates(candidates_output))
assert candidates
assert all(candidate.guest.arch == "x86-64" for candidate in candidates)
assert all(candidate.host.arch == "aarch64" for candidate in candidates)

diagnostics = json.loads(diagnostics_output.read_text(encoding="utf-8"))
assert result.diagnostics.windows_verified_pass > 0
assert result.rules
assert all(report.status != "error" for report in result.reports)

rules = rules_output.read_text(encoding="utf-8")
assert ".Guest:\n" in rules
assert ".Host:\n" in rules
rule_diagnostics = json.loads(
    rules_diagnostics_output.read_text(encoding="utf-8")
)
assert rule_diagnostics["rules_emitted"] > 0
```

Use the existing clang-unavailable skip behavior. If the current diagnostics JSON
cannot be produced because the local clang lacks a target, return using the same
strict error checks as the existing smoke tests.

- [ ] **Step 2: Run the reverse smoke and fix only discovered direction leaks**

Run: `uv run pytest -q tests/test_extraction_pipeline.py -k reverse`

Expected after Tasks 1-6: PASS. Any failure caused by a remaining side-to-ISA binding
must be fixed at the capability boundary and covered by a focused regression test;
do not add pair-specific reverse exceptions.

- [ ] **Step 3: Run both production directions through the CLI**

Run:

```bash
uv run angr-rule-learning extract samples/sources/smoke_int.c --work-dir /tmp/arl-forward --output /tmp/arl-forward/candidates.jsonl --diagnostics /tmp/arl-forward/diagnostics.json --verify --rules-output /tmp/arl-forward/rules.txt --rules-diagnostics /tmp/arl-forward/rules-diagnostics.json
uv run angr-rule-learning extract samples/sources/smoke_int.c --work-dir /tmp/arl-reverse --output /tmp/arl-reverse/candidates.jsonl --diagnostics /tmp/arl-reverse/diagnostics.json --guest-arch x86-64 --host-arch aarch64 --verify --rules-output /tmp/arl-reverse/rules.txt --rules-diagnostics /tmp/arl-reverse/rules-diagnostics.json
```

Expected: both exit zero, emit candidates and at least one rule, and report no
`verifier_internal_error`. Reverse rule count may be lower because no unproven
reverse immediate derivations are added.

- [ ] **Step 4: Update architecture documentation**

Document in `docs/architecture.md`:

- the `arch` capability boundary;
- the distinction between ISA-specific adapters and side coupling;
- symmetric frame-base compatibility;
- Host-only fixed-role provenance with explicit Host architecture;
- directional immediate derivation registration;
- `--guest-arch` and `--host-arch` CLI options;
- forward and reverse smoke coverage and the reverse immediate-derivation limit.

- [ ] **Step 5: Run complete verification**

Run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
git diff --check
git status --short
```

Expected: all formatting, lint, and tests pass; no whitespace errors; only intended
documentation/test/source changes are present.

- [ ] **Step 6: Commit documentation and acceptance coverage**

```bash
git add tests/test_extraction_pipeline.py docs/architecture.md
git commit -m "Verify bidirectional rule learning pipeline" -m "Co-authored-by: Codex <codex@openai.com>"
```

## Completion Criteria

- No production predicate identifies a frame pair as AArch64 guest plus x86-64 host.
- No rule helper hardcodes x86-64 while receiving an architecture argument.
- Guest rewriting never uses Host fixed-role literal policy.
- Both architecture choices are explicit CLI inputs and normalized centrally.
- Forward and reverse source-to-rule smoke tests pass without verifier internal errors.
- Existing forward rules remain sound; reverse rules requiring unavailable immediate
  derivations are skipped rather than guessed.
- Full Ruff and pytest suites pass on a clean worktree.
