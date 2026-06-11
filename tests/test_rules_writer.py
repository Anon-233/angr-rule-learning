import json
from pathlib import Path

from angr_rule_learning.rules.generalize import GeneratedRule, RuleDiagnostics
from angr_rule_learning.rules.writer import (
    format_rule,
    write_rule_diagnostics_json,
    write_rules_text,
)


def test_format_rule_uses_requested_plain_text_shape() -> None:
    rule = GeneratedRule(
        rule_id=1,
        candidate_id="candidate0",
        guest_lines=("add i32_reg1, i32_reg2, i32_reg3",),
        host_lines=("lea i32_reg1, [i32_reg2 + i32_reg3]",),
    )

    assert format_rule(rule) == (
        "1.Guest:\n"
        "\tadd i32_reg1, i32_reg2, i32_reg3\n"
        ".Host:\n"
        "\tlea i32_reg1, [i32_reg2 + i32_reg3]\n"
        "\n"
    )


def test_format_rule_preserves_multi_instruction_lines() -> None:
    rule = GeneratedRule(
        rule_id=7,
        candidate_id="candidate7",
        guest_lines=("mov i32_reg1, i32_reg2", "add i32_reg1, i32_reg1, #1"),
        host_lines=("mov i32_reg1, i32_reg2", "add i32_reg1, 1"),
    )

    assert format_rule(rule) == (
        "7.Guest:\n"
        "\tmov i32_reg1, i32_reg2\n"
        "\tadd i32_reg1, i32_reg1, #1\n"
        ".Host:\n"
        "\tmov i32_reg1, i32_reg2\n"
        "\tadd i32_reg1, 1\n"
        "\n"
    )


def test_write_rules_text_creates_parent_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "rules.txt"
    rule = GeneratedRule(
        rule_id=1,
        candidate_id="candidate0",
        guest_lines=("mov i32_reg1, i32_reg2",),
        host_lines=("mov i32_reg1, i32_reg2",),
    )

    write_rules_text(path, (rule,))

    assert path.read_text(encoding="utf-8") == (
        "1.Guest:\n\tmov i32_reg1, i32_reg2\n.Host:\n\tmov i32_reg1, i32_reg2\n\n"
    )


def test_write_rule_diagnostics_json(tmp_path: Path) -> None:
    diagnostics = RuleDiagnostics()
    diagnostics.record_considered()
    diagnostics.record_skipped("unmapped_register_surface")
    path = tmp_path / "nested" / "rules_diagnostics.json"

    write_rule_diagnostics_json(path, diagnostics)

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "rules_considered": 1,
        "rules_emitted": 0,
        "rules_skipped": 1,
        "skip_reasons": {"unmapped_register_surface": 1},
    }
