# Detailed Skip Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add detailed memory and control-flow skip diagnostics so `unsupported_memory_surface` and `unsupported_control_flow_surface` can be broken down into actionable causes without changing candidate filtering behavior.

**Architecture:** Keep the existing coarse `skip_reasons` counters for compatibility, and add nested `skip_details` counters keyed by the existing coarse reason. `SurfaceInferer` remains the single place that records skipped windows; lower-level memory/control-flow helpers should return a coarse reason plus a stable detail string.

**Tech Stack:** Python 3.14, dataclasses, pytest, ruff, existing `uv run` workflow.

---

## File Structure

- Modify `src/angr_rule_learning/extraction/diagnostics.py`
  - Add optional detailed skip counters while preserving existing `skip_reasons`.
- Modify `src/angr_rule_learning/extraction/memory_surfaces.py`
  - Add `MemorySurface.skip_detail`.
  - Return stable memory detail strings for each existing `unsupported_memory_surface` path.
- Modify `src/angr_rule_learning/extraction/surfaces.py`
  - Record memory details.
  - Replace boolean control-flow check with detail-returning helper.
- Modify `tests/test_extraction_memory_surfaces.py`
  - Assert memory detail strings at the surface level.
- Modify `tests/test_extraction_surfaces.py`
  - Assert diagnostics record memory and control-flow details.
- Modify `tests/test_extraction_pipeline.py`
  - Assert smoke diagnostics include `skip_details` and preserve existing high-level behavior.
- Modify `docs/architecture.md`
  - Document coarse vs detailed extraction diagnostics.

---

### Task 1: Add Nested Skip Detail Counters

**Files:**
- Modify: `src/angr_rule_learning/extraction/diagnostics.py`
- Test: `tests/test_extraction_diagnostics.py`

- [ ] **Step 1: Write failing diagnostics tests**

Create `tests/test_extraction_diagnostics.py` if it does not exist. Add:

```python
from angr_rule_learning.extraction.diagnostics import MiningDiagnostics


def test_records_skip_details_without_losing_coarse_reason() -> None:
    diagnostics = MiningDiagnostics()

    diagnostics.record_window_skipped(
        "unsupported_memory_surface",
        detail="memory_access_count_mismatch",
    )
    diagnostics.record_window_skipped(
        "unsupported_memory_surface",
        detail="memory_access_count_mismatch",
    )
    diagnostics.record_window_skipped(
        "unsupported_memory_surface",
        detail="memory_width_mismatch",
    )
    diagnostics.record_window_skipped("no_verifiable_surface")

    payload = diagnostics.to_json()

    assert payload["skip_reasons"] == {
        "no_verifiable_surface": 1,
        "unsupported_memory_surface": 3,
    }
    assert payload["skip_details"] == {
        "unsupported_memory_surface": {
            "memory_access_count_mismatch": 2,
            "memory_width_mismatch": 1,
        }
    }


def test_omits_skip_details_when_no_detail_was_recorded() -> None:
    diagnostics = MiningDiagnostics()

    diagnostics.record_window_skipped("no_verifiable_surface")

    payload = diagnostics.to_json()

    assert payload["skip_reasons"] == {"no_verifiable_surface": 1}
    assert "skip_details" not in payload
```

- [ ] **Step 2: Run the failing diagnostics tests**

Run:

```bash
uv run pytest tests/test_extraction_diagnostics.py -q
```

Expected: failure because `record_window_skipped()` does not accept `detail` and `to_json()` does not emit `skip_details`.

- [ ] **Step 3: Implement detailed counters**

Update `src/angr_rule_learning/extraction/diagnostics.py`:

```python
from collections import Counter, defaultdict
from collections.abc import DefaultDict
```

Add this field to `MiningDiagnostics`:

```python
    skip_details: DefaultDict[str, Counter[str]] = field(
        default_factory=lambda: defaultdict(Counter)
    )
```

Change `record_window_skipped()` to:

```python
    def record_window_skipped(self, reason: str, detail: str | None = None) -> None:
        self.skip_reasons[reason] += 1
        if detail is not None:
            self.skip_details[reason][detail] += 1
```

Change `to_json()` so it builds the existing payload first, then conditionally adds details:

```python
        payload: dict[str, object] = {
            "functions": self.functions,
            "regions": self.regions,
            "regions_skipped": self.regions_skipped,
            "windows_enumerated": self.windows_enumerated,
            "windows_emitted": self.windows_emitted,
            "windows_verified": self.windows_verified,
            "windows_verified_pass": self.windows_verified_pass,
            "mean_guest_window_size": (
                mean(self._guest_sizes) if self._guest_sizes else 0
            ),
            "mean_host_window_size": (
                mean(self._host_sizes) if self._host_sizes else 0
            ),
            "p95_guest_window_size": _p95(self._guest_sizes),
            "p95_host_window_size": _p95(self._host_sizes),
            "max_guest_window_size": max(self._guest_sizes, default=0),
            "max_host_window_size": max(self._host_sizes, default=0),
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
            "surface_kinds": dict(sorted(self.surface_kinds.items())),
        }
        if self.skip_details:
            payload["skip_details"] = {
                reason: dict(sorted(counter.items()))
                for reason, counter in sorted(self.skip_details.items())
                if counter
            }
        return payload
```

- [ ] **Step 4: Verify diagnostics tests pass**

Run:

```bash
uv run pytest tests/test_extraction_diagnostics.py -q
```

Expected: pass.

- [ ] **Step 5: Run formatting**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/diagnostics.py tests/test_extraction_diagnostics.py
uv run ruff check src/angr_rule_learning/extraction/diagnostics.py tests/test_extraction_diagnostics.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/diagnostics.py tests/test_extraction_diagnostics.py
git commit -m "Add detailed extraction skip counters"
```

---

### Task 2: Split Memory Surface Skip Details

**Files:**
- Modify: `src/angr_rule_learning/extraction/memory_surfaces.py`
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Test: `tests/test_extraction_memory_surfaces.py`
- Test: `tests/test_extraction_surfaces.py`

- [ ] **Step 1: Add failing memory surface tests**

Append to `tests/test_extraction_memory_surfaces.py`:

```python
def test_memory_surface_reports_one_sided_memory_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, ecx"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "one_sided_memory_access"


def test_memory_surface_reports_access_count_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (
                _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),
                _inst("x86-64", 0x2004, "mov", "edx, dword ptr [rbx]"),
            ),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "memory_access_count_mismatch"


def test_memory_surface_reports_kind_and_width_details() -> None:
    kind = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx], eax"),),
        )
    )
    width = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "rax, qword ptr [rcx]"),),
        )
    )

    assert kind.skip_detail == "memory_kind_mismatch"
    assert width.skip_detail == "memory_width_mismatch"


def test_memory_surface_reports_unparsed_access_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldp", "x0, x1, [x2]"),),
            (_inst("x86-64", 0x2000, "mov", "rax, qword ptr [rcx]"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "unparsed_memory_access"
```

- [ ] **Step 2: Add failing surface diagnostics test**

Append to `tests/test_extraction_surfaces.py`:

```python
def test_surface_inferer_records_memory_skip_detail() -> None:
    diagnostics = MiningDiagnostics()
    inferer = SurfaceInferer(diagnostics, LivenessIndex.empty())
    pair = _pair(
        (
            _inst("aarch64", 0x1000, "ldp", "x0, x1, [x2]"),
        ),
        (
            _inst("x86-64", 0x2000, "mov", "rax, qword ptr [rcx]"),
        ),
    )

    assert inferer.infer(pair) is None
    payload = diagnostics.to_json()

    assert payload["skip_reasons"] == {"unsupported_memory_surface": 1}
    assert payload["skip_details"] == {
        "unsupported_memory_surface": {"unparsed_memory_access": 1}
    }
```

If the helper names in `tests/test_extraction_surfaces.py` differ from `_pair` or `_inst`, use the existing helper names in that file and keep the assertions identical.

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py -q
```

Expected: failure because `MemorySurface` has no `skip_detail`.

- [ ] **Step 4: Add `skip_detail` to `MemorySurface`**

In `src/angr_rule_learning/extraction/memory_surfaces.py`, add the field:

```python
    skip_detail: str | None = None
```

Update every `MemorySurface(..., skip_reason="unsupported_memory_surface")` return to include one of these stable details:

```python
"unparsed_memory_access"
"one_sided_memory_access"
"memory_access_count_mismatch"
"memory_kind_mismatch"
"memory_width_mismatch"
"memory_address_register_count_mismatch"
"store_value_internality_mismatch"
"store_producer_source_count_mismatch"
```

Use this split:

```python
        if guest.kind != host.kind:
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
                skip_detail="memory_kind_mismatch",
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
        if guest.width != host.width:
            return MemorySurface(
                MemorySpec(),
                skip_reason="unsupported_memory_surface",
                skip_detail="memory_width_mismatch",
                guest_operands=guest_operands,
                host_operands=host_operands,
            )
```

For the existing `_has_unparsed_memory()` path, use:

```python
skip_detail="unparsed_memory_access"
```

For `not guest_operands or not host_operands`, use:

```python
skip_detail="one_sided_memory_access"
```

For `len(guest_operands) != len(host_operands)`, use:

```python
skip_detail="memory_access_count_mismatch"
```

For address register arity mismatch, use:

```python
skip_detail="memory_address_register_count_mismatch"
```

For `guest_value_internal != host_value_internal`, use:

```python
skip_detail="store_value_internality_mismatch"
```

For producer source count mismatch, use:

```python
skip_detail="store_producer_source_count_mismatch"
```

- [ ] **Step 5: Record memory details in `SurfaceInferer`**

In `src/angr_rule_learning/extraction/surfaces.py`, change:

```python
            self._diagnostics.record_window_skipped(memory_surface.skip_reason)
```

to:

```python
            self._diagnostics.record_window_skipped(
                memory_surface.skip_reason,
                detail=memory_surface.skip_detail,
            )
```

- [ ] **Step 6: Verify memory tests pass**

Run:

```bash
uv run pytest tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py -q
```

Expected: pass.

- [ ] **Step 7: Run formatting**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py
uv run ruff check src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py
```

Expected: both pass.

- [ ] **Step 8: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/memory_surfaces.py src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_memory_surfaces.py tests/test_extraction_surfaces.py
git commit -m "Split memory surface skip diagnostics"
```

---

### Task 3: Split Control-Flow Skip Details

**Files:**
- Modify: `src/angr_rule_learning/extraction/surfaces.py`
- Test: `tests/test_extraction_surfaces.py`

- [ ] **Step 1: Add failing control-flow diagnostics tests**

Append to `tests/test_extraction_surfaces.py`:

```python
def test_surface_inferer_records_x86_call_control_flow_detail() -> None:
    diagnostics = MiningDiagnostics()
    inferer = SurfaceInferer(diagnostics, LivenessIndex.empty())
    pair = _pair(
        (_inst("aarch64", 0x1000, "mov", "w0, w1"),),
        (_inst("x86-64", 0x2000, "call", "0x2010"),),
    )

    assert inferer.infer(pair) is None
    payload = diagnostics.to_json()

    assert payload["skip_reasons"] == {"unsupported_control_flow_surface": 1}
    assert payload["skip_details"] == {
        "unsupported_control_flow_surface": {"x86_64_call": 1}
    }


def test_surface_inferer_records_aarch64_return_control_flow_detail() -> None:
    diagnostics = MiningDiagnostics()
    inferer = SurfaceInferer(diagnostics, LivenessIndex.empty())
    pair = _pair(
        (_inst("aarch64", 0x1000, "ret", ""),),
        (_inst("x86-64", 0x2000, "mov", "eax, edi"),),
    )

    assert inferer.infer(pair) is None
    payload = diagnostics.to_json()

    assert payload["skip_reasons"] == {"unsupported_control_flow_surface": 1}
    assert payload["skip_details"] == {
        "unsupported_control_flow_surface": {"aarch64_return": 1}
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
uv run pytest tests/test_extraction_surfaces.py -q
```

Expected: failure because control-flow details are not recorded.

- [ ] **Step 3: Replace boolean helper with detail helper**

In `src/angr_rule_learning/extraction/surfaces.py`, replace `_has_unsupported_control_flow()` with:

```python
def _unsupported_control_flow_detail(window: InstructionWindow) -> str | None:
    for inst in window.instructions:
        mnemonic = inst.mnemonic.lower()
        arch = inst.arch
        if arch == "aarch64":
            if mnemonic == "b":
                return "aarch64_unconditional_branch"
            if mnemonic in {"bl", "blr"}:
                return "aarch64_call"
            if mnemonic == "br":
                return "aarch64_indirect_branch"
            if mnemonic == "ret":
                return "aarch64_return"
        if arch == "x86-64":
            if mnemonic == "jmp":
                return "x86_64_unconditional_jump"
            if mnemonic == "call":
                return "x86_64_call"
            if mnemonic == "ret":
                return "x86_64_return"
    return None
```

Then change the top of `SurfaceInferer.infer()` from:

```python
        if _has_unsupported_control_flow(pair.guest) or _has_unsupported_control_flow(
            pair.host
        ):
            self._diagnostics.record_window_skipped("unsupported_control_flow_surface")
            return None
```

to:

```python
        control_flow_detail = _unsupported_control_flow_detail(pair.guest)
        if control_flow_detail is None:
            control_flow_detail = _unsupported_control_flow_detail(pair.host)
        if control_flow_detail is not None:
            self._diagnostics.record_window_skipped(
                "unsupported_control_flow_surface",
                detail=control_flow_detail,
            )
            return None
```

Leave `_UNSUPPORTED_CONTROL_FLOW` in place only if other code still uses it. If no references remain, delete `_UNSUPPORTED_CONTROL_FLOW`.

- [ ] **Step 4: Verify control-flow tests pass**

Run:

```bash
uv run pytest tests/test_extraction_surfaces.py -q
```

Expected: pass.

- [ ] **Step 5: Run formatting**

Run:

```bash
uv run ruff format src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_surfaces.py
uv run ruff check src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_surfaces.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add src/angr_rule_learning/extraction/surfaces.py tests/test_extraction_surfaces.py
git commit -m "Split control-flow surface skip diagnostics"
```

---

### Task 4: Add End-to-End Diagnostics Coverage

**Files:**
- Modify: `tests/test_extraction_pipeline.py`
- Modify: `docs/architecture.md`

- [ ] **Step 1: Add pipeline smoke assertions for `skip_details`**

Find the existing pipeline smoke test that runs extraction on a sample source. Add assertions after reading the diagnostics JSON:

```python
    skip_details = diagnostics_payload.get("skip_details", {})

    assert "unsupported_memory_surface" in skip_details
    assert sum(skip_details["unsupported_memory_surface"].values()) == diagnostics_payload[
        "skip_reasons"
    ]["unsupported_memory_surface"]
```

If the smoke source does not produce control-flow skips, do not force the assertion in that test. Instead add a focused unit test in `tests/test_extraction_surfaces.py`, as done in Task 3.

- [ ] **Step 2: Run the pipeline test**

Run the specific pipeline test first:

```bash
uv run pytest tests/test_extraction_pipeline.py -q
```

Expected: pass.

- [ ] **Step 3: Update architecture docs**

In `docs/architecture.md`, update the extraction diagnostics section to include:

```markdown
Extraction diagnostics preserve coarse skip counters in `skip_reasons`.
For broad categories that hide actionable causes, the pipeline also emits
`skip_details`, keyed by the same coarse reason. For example,
`unsupported_memory_surface` may contain `memory_access_count_mismatch`,
`memory_width_mismatch`, or `unparsed_memory_access`; the sum of those detail
counts should match the corresponding coarse reason when every skip path in
that category reports a detail.
```

- [ ] **Step 4: Run formatting and docs-neutral checks**

Run:

```bash
uv run ruff format tests/test_extraction_pipeline.py
uv run ruff check tests/test_extraction_pipeline.py
```

Expected: both pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add tests/test_extraction_pipeline.py docs/architecture.md
git commit -m "Document detailed extraction skip diagnostics"
```

---

### Task 5: Final Verification and Smoke Report

**Files:**
- No source files should be changed in this task unless verification exposes a bug.

- [ ] **Step 1: Run full checks**

Run:

```bash
uv run ruff format --check
uv run ruff check
uv run pytest -q
```

Expected: all pass.

- [ ] **Step 2: Run smoke extraction with detailed diagnostics**

Run:

```bash
uv run angr-rule-learning extract samples/sources/smoke_int.c \
  --work-dir /private/tmp/arl-detailed-diagnostics/work \
  --output /private/tmp/arl-detailed-diagnostics/candidates.jsonl \
  --diagnostics /private/tmp/arl-detailed-diagnostics/diagnostics.json \
  --optimization 0 \
  --verify \
  --rules-output /private/tmp/arl-detailed-diagnostics/rules.txt \
  --rules-diagnostics /private/tmp/arl-detailed-diagnostics/rules_diagnostics.json \
  --rules-debug-diagnostics /private/tmp/arl-detailed-diagnostics/rules_debug_diagnostics.json
```

Expected: command exits 0.

- [ ] **Step 3: Inspect diagnostic breakdown**

Run:

```bash
python3 -m json.tool /private/tmp/arl-detailed-diagnostics/diagnostics.json
```

Expected:

- `skip_reasons` still contains `unsupported_memory_surface` and `unsupported_control_flow_surface`.
- `skip_details.unsupported_memory_surface` exists.
- `skip_details.unsupported_control_flow_surface` exists if `smoke_int.c` produces control-flow skips.
- `windows_emitted` should remain in the same range as before; this feature is diagnostic-only and should not be judged by increased rule count.

- [ ] **Step 4: Commit any verification-only fixes**

If no source changes were needed, do not create a commit. If a verification bug was fixed, commit with:

```bash
git add <changed files>
git commit -m "Fix detailed skip diagnostics verification"
```

- [ ] **Step 5: Final report**

Report:

- full check results,
- smoke `windows_enumerated`, `windows_emitted`, `windows_verified_pass`,
- `skip_details.unsupported_memory_surface` top entries,
- `skip_details.unsupported_control_flow_surface` top entries,
- confirmation that candidate filtering behavior was not intentionally changed.

---

## Self-Review

- Spec coverage: The plan covers memory detail counters, control-flow detail counters, serialization, tests, docs, and smoke verification.
- Placeholder scan: No unresolved placeholders are present. The only angle-bracket command in Task 4 is a standard git placeholder for changed files after verification and is not required when no changes occur.
- Type consistency: `record_window_skipped(reason, detail=None)` is introduced in Task 1 and used in Tasks 2 and 3. `MemorySurface.skip_detail` is introduced before `SurfaceInferer` consumes it.
- Scope check: The plan intentionally does not alter candidate acceptance, verifier behavior, rule generalization, or rule yield.
