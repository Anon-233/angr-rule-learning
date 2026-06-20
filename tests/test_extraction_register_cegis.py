from __future__ import annotations

import claripy
import pytest

from angr_rule_learning.extraction.liveness import WindowSurface
from angr_rule_learning.extraction.memory_surfaces import MemorySurface
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
from angr_rule_learning.extraction.register_transfer import RegisterTransferError
from angr_rule_learning.verification.candidate import (
    MemoryAccessExpectation,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
)
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
    memory_surface = MemorySurface(
        MemorySpec(),
        guest_operands=((object(),) if has_memory else ()),
    )
    return BindingProblem(pair, guest_surface, host_surface, memory_surface)


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


def test_cegis_accepts_zero_input_constant_transfer() -> None:
    guest = _transfer((), (), (), ("w0",), (claripy.BVV(9, 32),))
    host = _transfer((), (), (), ("eax",), (claripy.BVV(9, 32),))

    class Extractor:
        def extract(self, window, surface, *, side):
            return guest if side == "guest" else host

    class PassingVerifier:
        def verify(self, candidate):
            return VerificationReport(candidate.candidate_id, "pass")

    result = CegisRegisterBindingSolver(
        PassingVerifier(), transfer_extractor=Extractor()
    ).solve(
        _problem(
            WindowSurface(outputs=("w0",)),
            WindowSurface(outputs=("eax",)),
        )
    )

    assert result.skip_reason is None
    assert result.input_registers == ()
    assert result.output_registers == (("w0", "eax"),)


def test_cegis_memory_search_uses_complete_memory_candidate() -> None:
    memory_spec = MemorySpec(
        slots=(MemorySlot("mem0", 4),),
        bindings=(MemoryBinding("mem0", "x0", "rdi", "read"),),
        accesses=(MemoryAccessExpectation("mem0", "read", 4),),
    )
    memory_surface = MemorySurface(
        memory_spec,
        guest_operands=(object(),),
        host_operands=(object(),),
    )
    problem = _problem(
        WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
        WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
    )
    problem = BindingProblem(
        problem.pair,
        problem.guest_surface,
        problem.host_surface,
        memory_surface,
    )

    class MappingVerifier:
        def __init__(self):
            self.candidates = []

        def verify(self, candidate):
            self.candidates.append(candidate)
            status = (
                "pass"
                if candidate.input_registers == (("w1", "edi"), ("w0", "esi"))
                else "fail"
            )
            return VerificationReport(candidate.candidate_id, status)

    verifier = MappingVerifier()
    result = CegisRegisterBindingSolver(verifier).solve(problem)

    assert result.skip_reason is None
    assert result.input_registers == (("w1", "edi"), ("w0", "esi"))
    assert len(verifier.candidates) == 2
    assert all(candidate.memory is memory_spec for candidate in verifier.candidates)


def test_cegis_branch_search_stops_at_first_verified_mapping() -> None:
    problem = _problem(
        WindowSurface(inputs=("w0", "w1"), kind="branch"),
        WindowSurface(inputs=("edi", "esi"), kind="branch"),
    )

    class MappingVerifier:
        def __init__(self):
            self.calls = 0

        def verify(self, candidate):
            self.calls += 1
            status = (
                "pass"
                if candidate.input_registers == (("w0", "edi"), ("w1", "esi"))
                else "fail"
            )
            return VerificationReport(candidate.candidate_id, status)

    verifier = MappingVerifier()
    result = CegisRegisterBindingSolver(verifier).solve(problem)

    assert result.skip_reason is None
    assert result.input_registers == (("w0", "edi"), ("w1", "esi"))
    assert result.output_registers == ()
    assert verifier.calls == 1


def test_cegis_branch_search_proves_real_terminal_guards() -> None:
    guest_instructions = (
        _instruction(
            "aarch64",
            0x1000,
            "1f 00 01 eb",
            "cmp",
            ("x0", "x1"),
            ("nzcv",),
        ),
        _instruction(
            "aarch64",
            0x1004,
            "40 00 00 54",
            "b.eq",
            ("nzcv",),
            (),
        ),
    )
    host_instructions = (
        _instruction(
            "x86-64",
            0x2000,
            "48 39 c8",
            "cmp",
            ("rax", "rcx"),
            ("rflags",),
        ),
        _instruction(
            "x86-64",
            0x2003,
            "74 02",
            "je",
            ("rflags",),
            (),
        ),
    )
    problem = _problem(
        WindowSurface(inputs=("x0", "x1"), kind="branch"),
        WindowSurface(inputs=("rax", "rcx"), kind="branch"),
        guest_instructions=guest_instructions,
        host_instructions=host_instructions,
    )

    result = CegisRegisterBindingSolver(SemanticVerifier()).solve(problem)

    assert result.skip_reason is None
    assert result.input_registers == (("x0", "rax"), ("x1", "rcx"))


def test_cegis_over_limit_uses_positional_fallback_with_explicit_reason() -> None:
    registers = tuple(f"w{index}" for index in range(5))
    host_registers = ("eax", "ebx", "ecx", "edx", "esi")

    class Fallback:
        def __init__(self):
            self.calls = 0

        def solve(self, problem):
            self.calls += 1
            return RegisterBindingResult(
                input_registers=tuple(zip(registers, host_registers, strict=True)),
                output_registers=(("w0", "eax"),),
            )

    fallback = Fallback()
    result = CegisRegisterBindingSolver(
        SemanticVerifier(), fallback_solver=fallback
    ).solve(
        _problem(
            WindowSurface(inputs=registers, outputs=("w0",)),
            WindowSurface(inputs=host_registers, outputs=("eax",)),
        )
    )

    assert result.skip_reason is None
    assert result.fallback_detail == "register_limit_exceeded:guest_inputs:5>4"
    assert fallback.calls == 1


def test_cegis_transfer_inconclusive_uses_positional_fallback() -> None:
    class FailingExtractor:
        def extract(self, window, surface, *, side):
            raise RegisterTransferError("execution_shape")

    class Fallback:
        def solve(self, problem):
            return RegisterBindingResult(
                input_registers=(("w0", "edi"),),
                output_registers=(("w0", "eax"),),
            )

    result = CegisRegisterBindingSolver(
        SemanticVerifier(),
        transfer_extractor=FailingExtractor(),
        fallback_solver=Fallback(),
    ).solve(
        _problem(
            WindowSurface(inputs=("w0",), outputs=("w0",)),
            WindowSurface(inputs=("edi",), outputs=("eax",)),
        )
    )

    assert result.skip_reason is None
    assert result.fallback_detail == "execution_shape"


def test_cegis_unsat_does_not_use_positional_fallback() -> None:
    guest, host = _identity_transfers()

    class Extractor:
        def extract(self, window, surface, *, side):
            return guest if side == "guest" else host

    class UnsatSynthesizer:
        def synthesize(self, guest, host, samples):
            return None

    class ForbiddenFallback:
        def solve(self, problem):
            raise AssertionError("unsat must not use positional fallback")

    result = CegisRegisterBindingSolver(
        SemanticVerifier(),
        transfer_extractor=Extractor(),
        synthesizer=UnsatSynthesizer(),
        fallback_solver=ForbiddenFallback(),
    ).solve(
        _problem(
            WindowSurface(inputs=("w0", "w1"), outputs=("w0",)),
            WindowSurface(inputs=("edi", "esi"), outputs=("eax",)),
        )
    )

    assert result.skip_reason == "register_binding_unsat"


@pytest.mark.parametrize(
    ("guest_surface", "host_surface", "detail"),
    [
        (
            WindowSurface(inputs=("v0",), outputs=("v0",)),
            WindowSurface(inputs=("xmm0",), outputs=("xmm0",)),
            "non_integer_register",
        ),
        (
            WindowSurface(inputs=("w0",), outputs=("w0",)),
            WindowSurface(inputs=("rax",), outputs=("rax",)),
            "width_domain_empty",
        ),
        (
            WindowSurface(inputs=("w0",), outputs=("w0",)),
            WindowSurface(inputs=("cl",), outputs=("eax",)),
            "unmodeled_input",
        ),
    ],
)
def test_cegis_unsupported_surface_uses_positional_fallback(
    guest_surface,
    host_surface,
    detail,
) -> None:
    class UnusedVerifier:
        def verify(self, candidate):
            raise AssertionError("unsupported surface reached verifier")

    result = CegisRegisterBindingSolver(UnusedVerifier()).solve(
        _problem(guest_surface, host_surface)
    )

    assert result.skip_reason is None
    assert result.fallback_detail == detail
    assert result.input_registers == tuple(
        zip(guest_surface.inputs, host_surface.inputs, strict=True)
    )


def test_cegis_repeated_counterexample_uses_positional_fallback() -> None:
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

    assert result.skip_reason is None
    assert result.fallback_detail == "counterexample_repeated"


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


def test_cegis_iteration_limit_uses_positional_fallback() -> None:
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

    assert result.skip_reason is None
    assert result.fallback_detail == "iteration_limit"
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
