from collections import Counter

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


def test_omits_skip_details_when_only_empty_detail_counters_exist() -> None:
    diagnostics = MiningDiagnostics()
    diagnostics.skip_details["unsupported_memory_surface"] = Counter()

    payload = diagnostics.to_json()

    assert "skip_details" not in payload


def test_records_register_binding_fallbacks_separately_from_skips() -> None:
    diagnostics = MiningDiagnostics()

    diagnostics.record_register_binding_fallback(
        "register_limit_exceeded:guest_inputs:5>4"
    )
    diagnostics.record_register_binding_fallback(
        "register_limit_exceeded:guest_inputs:5>4"
    )

    payload = diagnostics.to_json()

    assert payload["register_binding_fallbacks"] == {
        "register_limit_exceeded:guest_inputs:5>4": 2
    }
    assert payload["skip_reasons"] == {}
