from angr_rule_learning.models import CodeFragment, VerificationRequest


def test_verification_request_normalizes_hex_and_register_names() -> None:
    request = VerificationRequest(
        guest=CodeFragment(
            arch="aarch64",
            address=0x10000,
            code_hex="20 00 02 8b",
            instruction_count=1,
            def_regs=("X0",),
        ),
        host=CodeFragment(
            arch="x86-64",
            address=0x8048000,
            code_hex="48 8d 04 11",
            instruction_count=1,
            def_regs=("RAX",),
        ),
        init_map=(("X1", "RCX"), ("X2", "RDX")),
    )

    assert request.guest.code_bytes == bytes.fromhex("2000028b")
    assert request.host.code_bytes == bytes.fromhex("488d0411")
    assert request.guest.def_regs == ("x0",)
    assert request.host.def_regs == ("rax",)
    assert request.init_map == (("x1", "rcx"), ("x2", "rdx"))
