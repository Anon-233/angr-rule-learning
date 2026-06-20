from __future__ import annotations

import claripy
import pytest

from angr_rule_learning.extraction.liveness import WindowSurface
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.extraction.register_cegis import (
    BindingSample,
    CegisRegisterBindingSolver,
    SelectorSynthesizer,
)
from angr_rule_learning.extraction.register_bindings import (
    BindingProblem,
    RegisterBindingResult,
)
from angr_rule_learning.extraction.register_transfer import SymbolicRegisterTransfer
from angr_rule_learning.verification.report import CheckResult, VerificationReport
from angr_rule_learning.verification.verifier import SemanticVerifier


def _transfer(
    inputs: tuple[str, ...],
    symbols: tuple[claripy.ast.BV, ...],
    widths: tuple[int, ...],
    outputs: tuple[str, ...],
    expressions: tuple[claripy.ast.BV, ...],
) -> SymbolicRegisterTransfer:
    return SymbolicRegisterTransfer(
        input_registers=inputs,
        input_symbols=symbols,
        input_widths=widths,
        output_registers=outputs,
        output_expressions=expressions,
        output_widths=tuple(expression.size() for expression in expressions),
    )


def _symbol(name: str, width: int = 32) -> claripy.ast.BV:
    return claripy.BVS(name, width, explicit_name=True)


def test_selector_synthesizer_finds_swapped_shift_inputs() -> None:
    g_value, g_shift = _symbol("g_value"), _symbol("g_shift")
    h_shift, h_value = _symbol("h_shift"), _symbol("h_value")
    guest = _transfer(
        ("w0", "w1"),
        (g_value, g_shift),
        (32, 32),
        ("w0",),
        (g_value << g_shift,),
    )
    host = _transfer(
        ("esi", "edi"),
        (h_shift, h_value),
        (32, 32),
        ("eax",),
        (h_value << h_shift,),
    )

    result = SelectorSynthesizer().synthesize(
        guest,
        host,
        (BindingSample((3, 1)),),
    )

    assert result is not None
    assert result.input_registers == (("w1", "esi"), ("w0", "edi"))
    assert result.output_registers == (("w0", "eax"),)


def test_selector_domains_require_exact_width() -> None:
    g32, g64 = _symbol("g32", 32), _symbol("g64", 64)
    h64, h32 = _symbol("h64", 64), _symbol("h32", 32)
    guest = _transfer(
        ("w0", "x1"),
        (g32, g64),
        (32, 64),
        ("w0", "x1"),
        (g32, g64),
    )
    host = _transfer(
        ("rax", "edi"),
        (h64, h32),
        (64, 32),
        ("rax", "edi"),
        (h64, h32),
    )

    result = SelectorSynthesizer().synthesize(
        guest,
        host,
        (BindingSample((7, 11)),),
    )

    assert result is not None
    assert result.input_registers == (("x1", "rax"), ("w0", "edi"))
    assert result.output_registers == (("x1", "rax"), ("w0", "edi"))


def test_all_different_output_selectors_can_make_samples_unsatisfiable() -> None:
    g0, g1 = _symbol("g0"), _symbol("g1")
    h0, h1 = _symbol("h0"), _symbol("h1")
    guest = _transfer(
        ("w0", "w1"),
        (g0, g1),
        (32, 32),
        ("w0", "w1"),
        (g0, g1),
    )
    host = _transfer(
        ("edi", "esi"),
        (h0, h1),
        (32, 32),
        ("eax", "edx"),
        (h0, h0),
    )

    result = SelectorSynthesizer().synthesize(
        guest,
        host,
        (BindingSample((1, 2)),),
    )

    assert result is None


def _instruction(
    arch: str,
    address: int,
    code: str,
    mnemonic: str,
    reads: tuple[str, ...],
    writes: tuple[str, ...],
) -> ExtractedInstruction:
    code_bytes = bytes.fromhex(code)
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=len(code_bytes),
        code_bytes=code_bytes,
        mnemonic=mnemonic,
        op_str="",
        function="f",
        source=None,
        read_registers=reads,
        write_registers=writes,
    )


def _problem(
    guest_surface: WindowSurface,
    host_surface: WindowSurface,
    *,
    guest_instructions: tuple[ExtractedInstruction, ...] | None = None,
    host_instructions: tuple[ExtractedInstruction, ...] | None = None,
    has_memory: bool = False,
) -> BindingProblem:
    guest_instructions = guest_instructions or (
        _instruction("aarch64", 0x1000, "1f 20 03 d5", "nop", (), ()),
    )
    host_instructions = host_instructions or (
        _instruction("x86-64", 0x2000, "90", "nop", (), ()),
    )
    pair = WindowPair(
        "r0",
        (len(guest_instructions), len(host_instructions)),
        InstructionWindow("r0", "guest", guest_instructions),
        InstructionWindow("r0", "host", host_instructions),
    )
    return BindingProblem(pair, guest_surface, host_surface, has_memory)


def _identity_transfers() -> tuple[
    SymbolicRegisterTransfer,
    SymbolicRegisterTransfer,
]:
    g0, g1 = _symbol("loop_g0"), _symbol("loop_g1")
    h0, h1 = _symbol("loop_h0"), _symbol("loop_h1")
    return (
        _transfer(("w0", "w1"), (g0, g1), (32, 32), ("w0",), (g0 + g1,)),
        _transfer(
            ("edi", "esi"),
            (h0, h1),
            (32, 32),
            ("eax",),
            (h0 + h1,),
        ),
    )


def test_cegis_extracts_each_transfer_once_and_feeds_back_counterexample() -> None:
    guest_transfer, host_transfer = _identity_transfers()

    class CountingExtractor:
        def __init__(self):
            self.calls = []

        def extract(self, window, surface, *, side):
            self.calls.append(side)
            return guest_transfer if side == "guest" else host_transfer

    class RecordingSynthesizer:
        def __init__(self):
            self.samples = []

        def synthesize(self, guest, host, samples):
            self.samples.append(samples)
            return RegisterBindingResult(
                input_registers=(("w0", "edi"), ("w1", "esi")),
                output_registers=(("w0", "eax"),),
            )

    class CounterexampleVerifier:
        def __init__(self):
            self.calls = 0

        def verify(self, candidate):
            self.calls += 1
            if self.calls == 1:
                return VerificationReport(
                    candidate.candidate_id,
                    "fail",
                    checks=(
                        CheckResult(
                            "register",
                            "fail",
                            "w0",
                            "eax",
                            counterexample={"w0": 3, "w1": 1},
                        ),
                    ),
                )
            return VerificationReport(candidate.candidate_id, "pass")

    extractor = CountingExtractor()
    synthesizer = RecordingSynthesizer()
    verifier = CounterexampleVerifier()
    solver = CegisRegisterBindingSolver(
        verifier,
        transfer_extractor=extractor,
        synthesizer=synthesizer,
    )
    problem = _problem(
        WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
        WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
    )

    result = solver.solve(problem)

    assert result.skip_reason is None
    assert extractor.calls == ["guest", "host"]
    assert verifier.calls == 2
    assert synthesizer.samples == [
        (BindingSample((0, 0)),),
        (BindingSample((0, 0)), BindingSample((3, 1))),
    ]


@pytest.mark.parametrize(
    ("guest_surface", "host_surface", "has_memory", "detail"),
    [
        (
            WindowSurface(inputs=("w0",), outputs=("w0",)),
            WindowSurface(inputs=("edi",), outputs=("eax",)),
            True,
            "memory_surface",
        ),
        (
            WindowSurface(inputs=("w0",), outputs=("w0",), kind="branch"),
            WindowSurface(inputs=("edi",), outputs=("eax",)),
            False,
            "branch_surface",
        ),
        (
            WindowSurface(inputs=("v0",), outputs=("v0",)),
            WindowSurface(inputs=("xmm0",), outputs=("xmm0",)),
            False,
            "non_integer_register",
        ),
        (
            WindowSurface(inputs=("w0",), outputs=("w0",)),
            WindowSurface(inputs=("rax",), outputs=("rax",)),
            False,
            "width_domain_empty",
        ),
        (
            WindowSurface(inputs=("w0",), outputs=("w0",)),
            WindowSurface(inputs=("cl",), outputs=("eax",)),
            False,
            "unmodeled_input",
        ),
    ],
)
def test_cegis_rejects_unsupported_surface_without_fallback(
    guest_surface,
    host_surface,
    has_memory,
    detail,
) -> None:
    class UnusedVerifier:
        def verify(self, candidate):
            raise AssertionError("unsupported surface reached verifier")

    result = CegisRegisterBindingSolver(UnusedVerifier()).solve(
        _problem(guest_surface, host_surface, has_memory=has_memory)
    )

    assert result.skip_reason == "unsupported_register_binding_surface"
    assert result.skip_detail == detail
    assert result.input_registers == ()


def test_cegis_returns_inconclusive_for_repeated_counterexample() -> None:
    guest_transfer, host_transfer = _identity_transfers()

    class Extractor:
        def extract(self, window, surface, *, side):
            return guest_transfer if side == "guest" else host_transfer

    class Synthesizer:
        def synthesize(self, guest, host, samples):
            return RegisterBindingResult(
                input_registers=(("w0", "edi"), ("w1", "esi")),
                output_registers=(("w0", "eax"),),
            )

    class Verifier:
        def verify(self, candidate):
            return VerificationReport(
                candidate.candidate_id,
                "fail",
                checks=(
                    CheckResult(
                        "register",
                        "fail",
                        "w0",
                        "eax",
                        counterexample={"w0": 0, "w1": 0},
                    ),
                ),
            )

    result = CegisRegisterBindingSolver(
        Verifier(),
        transfer_extractor=Extractor(),
        synthesizer=Synthesizer(),
    ).solve(
        _problem(
            WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
            WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
        )
    )

    assert result.skip_reason == "register_binding_inconclusive"
    assert result.skip_detail == "counterexample_repeated"


def test_cegis_stops_after_first_fully_verified_binding() -> None:
    guest_transfer, host_transfer = _identity_transfers()

    class Extractor:
        def extract(self, window, surface, *, side):
            return guest_transfer if side == "guest" else host_transfer

    class Synthesizer:
        def __init__(self):
            self.calls = 0

        def synthesize(self, guest, host, samples):
            self.calls += 1
            return RegisterBindingResult(
                input_registers=(("w0", "edi"), ("w1", "esi")),
                output_registers=(("w0", "eax"),),
            )

    class Verifier:
        def __init__(self):
            self.calls = 0

        def verify(self, candidate):
            self.calls += 1
            return VerificationReport(candidate.candidate_id, "pass")

    synthesizer = Synthesizer()
    verifier = Verifier()
    result = CegisRegisterBindingSolver(
        verifier,
        transfer_extractor=Extractor(),
        synthesizer=synthesizer,
    ).solve(
        _problem(
            WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
            WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
        )
    )

    assert result.skip_reason is None
    assert synthesizer.calls == 1
    assert verifier.calls == 1


def test_cegis_reports_iteration_limit_after_distinct_counterexamples() -> None:
    guest_transfer, host_transfer = _identity_transfers()

    class Extractor:
        def extract(self, window, surface, *, side):
            return guest_transfer if side == "guest" else host_transfer

    class Synthesizer:
        def synthesize(self, guest, host, samples):
            return RegisterBindingResult(
                input_registers=(("w0", "edi"), ("w1", "esi")),
                output_registers=(("w0", "eax"),),
            )

    class Verifier:
        def __init__(self):
            self.calls = 0

        def verify(self, candidate):
            self.calls += 1
            return VerificationReport(
                candidate.candidate_id,
                "fail",
                checks=(
                    CheckResult(
                        "register",
                        "fail",
                        "w0",
                        "eax",
                        counterexample={"w0": self.calls, "w1": 0},
                    ),
                ),
            )

    verifier = Verifier()
    result = CegisRegisterBindingSolver(
        verifier,
        transfer_extractor=Extractor(),
        synthesizer=Synthesizer(),
        max_iterations=2,
    ).solve(
        _problem(
            WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
            WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
        )
    )

    assert result.skip_reason == "register_binding_inconclusive"
    assert result.skip_detail == "iteration_limit"
    assert verifier.calls == 2


def test_cegis_proves_real_fixed_role_shift_mapping() -> None:
    guest_instructions = (
        _instruction(
            "aarch64",
            0x1000,
            "00 20 c1 1a",
            "lsl",
            ("w0", "w1"),
            ("w0",),
        ),
    )
    host_instructions = (
        _instruction("x86-64", 0x2000, "89 f1", "mov", ("esi",), ("ecx",)),
        _instruction("x86-64", 0x2002, "89 f8", "mov", ("edi",), ("eax",)),
        _instruction(
            "x86-64",
            0x2004,
            "d3 e0",
            "shl",
            ("eax", "cl"),
            ("eax", "rflags"),
        ),
    )
    problem = _problem(
        WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
        WindowSurface(inputs=("esi", "edi"), outputs=("eax",)),
        guest_instructions=guest_instructions,
        host_instructions=host_instructions,
    )

    result = CegisRegisterBindingSolver(SemanticVerifier()).solve(problem)

    assert result.skip_reason is None
    assert result.input_registers == (("w1", "esi"), ("w0", "edi"))
    assert result.output_registers == (("w0", "eax"),)
    assert all(host != "cl" for _guest, host in result.input_registers)


def test_cegis_allows_rcx_family_as_an_ordinary_register_input() -> None:
    problem = _problem(
        WindowSurface(inputs=("w1",), outputs=("w0",)),
        WindowSurface(inputs=("ecx",), outputs=("eax",)),
        guest_instructions=(
            _instruction(
                "aarch64",
                0x1000,
                "e0 03 01 2a",
                "mov",
                ("w1",),
                ("w0",),
            ),
        ),
        host_instructions=(
            _instruction(
                "x86-64",
                0x2000,
                "89 c8",
                "mov",
                ("ecx",),
                ("eax",),
            ),
        ),
    )

    result = CegisRegisterBindingSolver(SemanticVerifier()).solve(problem)

    assert result.skip_reason is None
    assert result.input_registers == (("w1", "ecx"),)
    assert result.output_registers == (("w0", "eax"),)


def test_cegis_shift_mapping_is_architecture_direction_independent() -> None:
    x86_instructions = (
        _instruction("x86-64", 0x2000, "89 f1", "mov", ("esi",), ("ecx",)),
        _instruction("x86-64", 0x2002, "89 f8", "mov", ("edi",), ("eax",)),
        _instruction(
            "x86-64",
            0x2004,
            "d3 e0",
            "shl",
            ("eax", "cl"),
            ("eax", "rflags"),
        ),
    )
    aarch64_instructions = (
        _instruction(
            "aarch64",
            0x1000,
            "00 20 c1 1a",
            "lsl",
            ("w0", "w1"),
            ("w0",),
        ),
    )
    forward = _problem(
        WindowSurface(inputs=("esi", "edi"), outputs=("eax",)),
        WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
        guest_instructions=x86_instructions,
        host_instructions=aarch64_instructions,
    )

    result = CegisRegisterBindingSolver(SemanticVerifier()).solve(forward)

    assert result.skip_reason is None
    assert result.input_registers == (("edi", "w0"), ("esi", "w1"))
    assert result.output_registers == (("eax", "w0"),)
    assert all(guest != "cl" for guest, _host in result.input_registers)
