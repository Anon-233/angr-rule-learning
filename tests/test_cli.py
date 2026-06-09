from angr_rule_learning.cli import run_verify_payload


def test_run_verify_payload_returns_json_serializable_result() -> None:
    payload = {
        "guest": {
            "arch": "aarch64",
            "address": 0x10000,
            "code_hex": "20 00 02 8b",
            "instruction_count": 1,
            "def_regs": ["x0"],
        },
        "host": {
            "arch": "x86-64",
            "address": 0x8048000,
            "code_hex": "48 8d 04 11",
            "instruction_count": 1,
            "def_regs": ["rax"],
        },
        "init_map": [["x1", "rcx"], ["x2", "rdx"]],
    }

    result = run_verify_payload(payload)

    assert result["equivalent"] is True
    assert result["register_checks"] == [
        {"guest_reg": "x0", "host_reg": "rax", "status": "pass"}
    ]
    assert result["counterexample"] == {}
