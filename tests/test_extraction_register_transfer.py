from __future__ import annotations

import angr
import pytest

from angr_rule_learning.extraction.liveness import WindowSurface
from angr_rule_learning.extraction.memory_surfaces import MemorySurface
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.extraction.register_bindings import BindingProblem
from angr_rule_learning.extraction.register_cegis import CegisRegisterBindingSolver
from angr_rule_learning.extraction.register_transfer import (
    RegisterTransferError,
    RegisterTransferExtractor,
)
from angr_rule_learning.verification.execution import FragmentSuccessors
from angr_rule_learning.verification.verifier import SemanticVerifier
from angr_rule_learning.verification.candidate import MemorySpec


def _window(
    arch: str,
    code: bytes,
    mnemonic: str,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
) -> InstructionWindow:
    instruction = ExtractedInstruction(
        arch=arch,
        address=0x1000,
        size=len(code),
        code_bytes=code,
        mnemonic=mnemonic,
        op_str="",
        function="f",
        source=None,
        read_registers=reads,
        write_registers=writes,
    )
    return InstructionWindow("r0", "guest", (instruction,))


def test_extracts_aarch64_transfer_with_exact_independent_inputs() -> None:
    transfer = RegisterTransferExtractor().extract(
        _window(
            "aarch64",
            bytes.fromhex("20 00 02 0b"),
            "add",
            ("w1", "w2"),
            ("w0",),
        ),
        WindowSurface(inputs=("w1", "w2"), outputs=("w0",)),
        side="guest",
    )

    assert transfer.input_registers == ("w1", "w2")
    assert transfer.input_widths == (32, 32)
    assert transfer.output_registers == ("w0",)
    assert transfer.input_symbols[0] is not transfer.input_symbols[1]
    assert transfer.output_expressions[0].variables == {
        "cegis_guest_w1",
        "cegis_guest_w2",
    }


def test_extracts_x86_transfer_in_separate_symbol_namespace() -> None:
    transfer = RegisterTransferExtractor().extract(
        _window(
            "x86-64",
            bytes.fromhex("8d 04 37"),
            "lea",
            ("edi", "esi"),
            ("eax",),
        ),
        WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
        side="host",
    )

    assert transfer.input_widths == (32, 32)
    assert transfer.output_expressions[0].variables == {
        "cegis_host_edi",
        "cegis_host_esi",
    }


def test_rejects_output_dependency_missing_from_surface_inputs() -> None:
    with pytest.raises(RegisterTransferError, match="unmodeled_input"):
        RegisterTransferExtractor().extract(
            _window(
                "x86-64",
                bytes.fromhex("01 f0"),
                "add",
                ("eax", "esi"),
                ("eax",),
            ),
            WindowSurface(inputs=("eax",), outputs=("eax",)),
            side="host",
        )


def test_rejects_non_single_successor_execution_shape() -> None:
    class EmptyExecutor:
        def make_state(self, fragment):
            return object()

        def successors(self, fragment, state):
            return FragmentSuccessors(())

    with pytest.raises(RegisterTransferError, match="execution_shape"):
        RegisterTransferExtractor(EmptyExecutor()).extract(
            _window("x86-64", bytes.fromhex("90"), "nop", (), ()),
            WindowSurface(outputs=("eax",)),
            side="host",
        )


def test_converts_angr_execution_error_to_execution_shape() -> None:
    class FailingExecutor:
        def make_state(self, fragment):
            raise angr.errors.SimError("unsupported execution")

    with pytest.raises(RegisterTransferError, match="execution_shape"):
        RegisterTransferExtractor(FailingExecutor()).extract(
            _window("x86-64", bytes.fromhex("90"), "nop", (), ()),
            WindowSurface(outputs=("eax",)),
            side="host",
        )


def test_does_not_hide_unexpected_transfer_extractor_errors() -> None:
    class BrokenExtractor:
        def extract(self, window, surface, *, side):
            raise TypeError("implementation defect")

    guest = _window(
        "aarch64",
        bytes.fromhex("e0 03 01 2a"),
        "mov",
        ("w1",),
        ("w0",),
    )
    host = _window(
        "x86-64",
        bytes.fromhex("89 f8"),
        "mov",
        ("edi",),
        ("eax",),
    )
    problem = BindingProblem(
        WindowPair("r0", (1, 1), guest, host),
        WindowSurface(inputs=("w1",), outputs=("w0",)),
        WindowSurface(inputs=("edi",), outputs=("eax",)),
        MemorySurface(MemorySpec()),
    )

    with pytest.raises(TypeError, match="implementation defect"):
        CegisRegisterBindingSolver(
            SemanticVerifier(),
            transfer_extractor=BrokenExtractor(),
        ).solve(problem)
