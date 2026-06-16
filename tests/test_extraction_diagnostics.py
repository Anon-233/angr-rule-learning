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
