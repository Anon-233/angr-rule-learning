from __future__ import annotations


from angr_rule_learning.arch.registers import normalize_register_name
from angr_rule_learning.extraction.models import ExtractedInstruction
from angr_rule_learning.rules.register_views import (
    resolve_register_views,
)


def _make_inst(
    mnemonic: str,
    op_str: str,
    arch: str = "x86-64",
    read_registers: tuple[str, ...] = (),
    write_registers: tuple[str, ...] = (),
) -> ExtractedInstruction:
    """Minimal ExtractedInstruction factory for view-resolver tests."""
    return ExtractedInstruction(
        address=0x1000,
        size=4,
        code_bytes=b"\x00\x00\x00\x00",
        mnemonic=mnemonic,
        op_str=op_str,
        function="test_func",
        arch=arch,
        read_registers=read_registers,
        write_registers=write_registers,
        source=None,
    )


class TestResolveRegisterViews:
    @staticmethod
    def test_lea_edi_mapped_rdi_needs_view():
        """edi→i32_reg2 in mapping, lea uses rdi → reg64(i32_reg2)."""
        mapping = {
            "eax": "i32_reg1",
            "edi": "i32_reg2",
            "esi": "i32_reg3",
        }
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "lea",
            "eax, [rdi + rsi]",
            read_registers=("rdi", "rsi"),
            write_registers=("eax",),
        )
        views = resolve_register_views("x86-64", inst, mapping)
        assert len(views) == 2

        phys = {rv.physical_register for rv in views}
        assert "rdi" in phys
        assert "rsi" in phys

        for rv in views:
            assert rv.reason == "lea_address_operand_same_family_widen"
            if rv.physical_register == "rdi":
                assert rv.placeholder == "i32_reg2"
                assert rv.replacement_text == "reg64(i32_reg2)"
            elif rv.physical_register == "rsi":
                assert rv.placeholder == "i32_reg3"
                assert rv.replacement_text == "reg64(i32_reg3)"

    @staticmethod
    def test_lea_destination_not_replaced():
        """lea rdi, [rsi + rdx] with edi->i32_reg1 mapping: destination rdi
        must NOT get a reg64(...) replacement."""
        mapping = {"edi": "i32_reg1"}
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "lea",
            "rdi, [rsi + rdx]",
            read_registers=("rsi", "rdx"),
            write_registers=("rdi",),
        )
        views = resolve_register_views("x86-64", inst, mapping)
        # rdi is the destination — it's NOT in the bracket text and
        # shouldn't appear as a replacement.  Only bracket tokens are
        # inspected.
        phys = {rv.physical_register for rv in views}
        assert "rdi" not in phys, f"destination rdi must not get a view: {views}"

    @staticmethod
    def test_non_lea_returns_no_views():
        """add instruction should not trigger view resolution."""
        mapping = {"edi": "i32_reg2"}
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "add",
            "eax, edi",
            read_registers=("eax", "edi"),
            write_registers=("eax",),
        )
        views = resolve_register_views("x86-64", inst, mapping)
        assert views == []

    @staticmethod
    def test_exact_width_no_view():
        """When both mapped and physical regs are same width, no view."""
        mapping = {"rdi": "i64_reg2"}
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "lea",
            "rax, [rdi + rsi]",
            read_registers=("rdi", "rsi"),
            write_registers=("rax",),
        )
        views = resolve_register_views("x86-64", inst, mapping)
        phys = {rv.physical_register for rv in views}
        assert "rdi" not in phys

    @staticmethod
    def test_aarch64_returns_no_views():
        """AArch64 instructions are not eligible."""
        mapping = {"w1": "i32_reg2"}
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "add",
            "w0, w1, w2",
            arch="aarch64",
            read_registers=("w1", "w2"),
            write_registers=("w0",),
        )
        views = resolve_register_views("aarch64", inst, mapping)
        assert views == []

    @staticmethod
    def test_mapped_register_not_in_op_text_no_view():
        """If the wider register isn't in the operand text, no view."""
        mapping = {"edi": "i32_reg2"}
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "lea",
            "eax, [r8d + r9d]",
            read_registers=("r8d", "r9d"),
            write_registers=("eax",),
        )
        views = resolve_register_views("x86-64", inst, mapping)
        assert views == []

    @staticmethod
    def test_narrower_physical_no_view():
        """Wider mapped register does not cause a view for narrower physical.
        e.g., rdi mapped to i64, edi appears → no view (32 < 64)."""
        mapping = {"rdi": "i64_reg2"}
        mapping = {normalize_register_name(k): v for k, v in mapping.items()}
        inst = _make_inst(
            "lea",
            "eax, [edi]",
            read_registers=("edi",),
            write_registers=("eax",),
        )
        views = resolve_register_views("x86-64", inst, mapping)
        assert views == []
