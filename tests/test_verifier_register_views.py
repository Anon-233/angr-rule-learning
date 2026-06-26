"""Tests for partial register equality / register view widening in the verifier."""

from __future__ import annotations

import claripy
import angr

from angr_rule_learning.verification.register_views import (
    widen_input_register_view,
)


class TestWidenInputRegisterView:
    """Unit tests for the side-neutral widening helper."""

    @staticmethod
    def _make_amd64_state():
        """Create a minimal blank AMD64 state."""
        project = angr.load_shellcode(b"\x90", arch="AMD64", load_address=0x1000)
        return project.factory.blank_state(addr=0x1000)

    @staticmethod
    def _make_aarch64_state():
        """Create a minimal blank AArch64 state."""
        project = angr.load_shellcode(
            b"\x00\x00\x00\x00", arch="AARCH64", load_address=0x1000
        )
        return project.factory.blank_state(addr=0x1000)

    @staticmethod
    def test_widen_edi_to_rdi():
        """edi (32-bit) should trigger a write to rdi with fresh high bits."""
        state = TestWidenInputRegisterView._make_amd64_state()
        sym = claripy.BVS("test_sym", 32)

        fresh = widen_input_register_view(state, "edi", "x86-64", sym)
        assert fresh is not None

        rdi_val = state.regs.rdi
        assert rdi_val.symbolic
        assert rdi_val.size() == 64
        assert rdi_val.op == "Concat"
        args = rdi_val.args
        assert len(args) == 2
        assert args[1].args == sym.args
        assert "_view_hi" in args[0].args[0]

    @staticmethod
    def test_widen_w1_to_x1():
        """w1 (32-bit AArch64) should trigger a write to x1 with fresh high bits."""
        state = TestWidenInputRegisterView._make_aarch64_state()
        sym = claripy.BVS("test_sym", 32)

        fresh = widen_input_register_view(state, "w1", "aarch64", sym)
        assert fresh is not None

        x1_val = state.regs.x1
        assert x1_val.symbolic
        assert x1_val.size() == 64
        assert x1_val.op == "Concat"
        args = x1_val.args
        assert args[1].args == sym.args

    @staticmethod
    def test_rdi_already_full_width_noop():
        """rdi is already the widest family register — no widening needed."""
        state = TestWidenInputRegisterView._make_amd64_state()
        sym = claripy.BVS("test_sym", 64)

        from angr_rule_learning.verification.execution import write_reg

        write_reg(state, "rdi", sym)
        fresh = widen_input_register_view(state, "rdi", "x86-64", sym)
        assert fresh is None

        rdi_val = state.regs.rdi
        assert rdi_val.op == "BVS"
        assert rdi_val.args[0].startswith("test_sym")

    @staticmethod
    def test_x1_already_full_width_noop():
        """x1 is already the widest family register — no widening needed."""
        state = TestWidenInputRegisterView._make_aarch64_state()
        sym = claripy.BVS("test_sym", 64)

        from angr_rule_learning.verification.execution import write_reg

        write_reg(state, "x1", sym)
        fresh = widen_input_register_view(state, "x1", "aarch64", sym)
        assert fresh is None

        x1_val = state.regs.x1
        assert x1_val.op == "BVS"

    @staticmethod
    def test_widen_ax_to_rax():
        """ax (16-bit) should trigger a write to rax with fresh high bits."""
        state = TestWidenInputRegisterView._make_amd64_state()
        sym = claripy.BVS("test_sym", 16)

        fresh = widen_input_register_view(state, "ax", "x86-64", sym)
        assert fresh is not None

        rax_val = state.regs.rax
        assert rax_val.symbolic
        assert rax_val.size() == 64
        assert rax_val.op == "Concat"
        args = rax_val.args
        assert args[1].args == sym.args

    @staticmethod
    def test_widen_unknown_register_noop():
        """Non-existent register should not crash and return None."""
        state = TestWidenInputRegisterView._make_amd64_state()
        sym = claripy.BVS("test_sym", 32)
        fresh = widen_input_register_view(state, "nonexistent", "x86-64", sym)
        assert fresh is None
