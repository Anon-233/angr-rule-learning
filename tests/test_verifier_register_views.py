"""Tests for partial register equality / register view widening in the verifier."""

from __future__ import annotations

import claripy
import angr

from angr_rule_learning.verification.register_views import (
    widen_host_input_register,
)


class TestWidenHostInputRegister:
    """Unit tests for the widening helper."""

    @staticmethod
    def _make_amd64_state():
        """Create a minimal blank AMD64 state."""
        project = angr.load_shellcode(b"\x90", arch="AMD64", load_address=0x1000)
        return project.factory.blank_state(addr=0x1000)

    @staticmethod
    def test_widen_edi_to_rdi():
        """edi (32-bit) should trigger a write to rdi with fresh high bits."""
        state = TestWidenHostInputRegister._make_amd64_state()
        sym = claripy.BVS("test_sym", 32)

        widen_host_input_register(state, "edi", "x86-64", sym)

        # rdi should now be defined as Concat(fresh_hi_32, sym).
        rdi_val = state.regs.rdi
        assert rdi_val.symbolic
        assert rdi_val.size() == 64
        # The rdi value should be a Concat operation.
        assert rdi_val.op == "Concat"
        # One argument is fresh (symbolic, has no name referencing sym).
        args = rdi_val.args
        assert len(args) == 2
        # The low 32 bits (args[1]) should be structurally equivalent to sym.
        # args[0] is the high bits (a BVS named "..._hi").
        assert args[1].args == sym.args
        assert "_hi" in args[0].args[0]

    @staticmethod
    def test_rdi_already_full_width_noop():
        """rdi is already the widest family register — no widening needed."""
        state = TestWidenHostInputRegister._make_amd64_state()
        sym = claripy.BVS("test_sym", 64)

        from angr_rule_learning.verification.execution import write_reg

        write_reg(state, "rdi", sym)
        widen_host_input_register(state, "rdi", "x86-64", sym)

        # rdi should still be sym — the widen function detected full width
        # and did not wrap it in another Concat.
        rdi_val = state.regs.rdi
        assert rdi_val.op == "BVS"
        assert rdi_val.args[0].startswith("test_sym")

    @staticmethod
    def test_widen_ax_to_rax():
        """ax (16-bit) should trigger a write to rax with fresh high bits."""
        state = TestWidenHostInputRegister._make_amd64_state()
        sym = claripy.BVS("test_sym", 16)

        widen_host_input_register(state, "ax", "x86-64", sym)

        rax_val = state.regs.rax
        assert rax_val.symbolic
        assert rax_val.size() == 64
        assert rax_val.op == "Concat"
        args = rax_val.args
        # Low 16 bits (args[1]) should match sym.
        assert args[1].args == sym.args

    @staticmethod
    def test_widen_unknown_register_noop():
        """Non-existent register should not crash."""
        state = TestWidenHostInputRegister._make_amd64_state()
        sym = claripy.BVS("test_sym", 32)
        widen_host_input_register(state, "nonexistent", "x86-64", sym)
