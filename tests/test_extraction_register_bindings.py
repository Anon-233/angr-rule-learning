from angr_rule_learning.extraction.liveness import WindowSurface
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)
from angr_rule_learning.extraction.register_bindings import (
    BindingProblem,
    RegisterBindingSolver,
)


def _pair() -> WindowPair:
    guest = ExtractedInstruction(
        arch="aarch64",
        address=0x1000,
        size=4,
        code_bytes=b"\x00" * 4,
        mnemonic="add",
        op_str="w0, w1, w2",
        function="f",
        source=None,
    )
    host = ExtractedInstruction(
        arch="x86-64",
        address=0x2000,
        size=2,
        code_bytes=b"\x00" * 2,
        mnemonic="add",
        op_str="eax, esi",
        function="f",
        source=None,
    )
    return WindowPair(
        region_id="r0",
        stage=(1, 1),
        guest=InstructionWindow("r0", "guest", (guest,)),
        host=InstructionWindow("r0", "host", (host,)),
    )


def test_register_binding_solver_uses_positional_placeholder_binding() -> None:
    guest = WindowSurface(inputs=("w0", "w1"), outputs=("w2",))
    host = WindowSurface(inputs=("edi", "esi"), outputs=("eax",))

    problem = BindingProblem(_pair(), guest, host, has_memory=False)
    result = RegisterBindingSolver().solve(problem)

    assert result.skip_reason is None
    assert result.input_registers == (("w0", "edi"), ("w1", "esi"))
    assert result.output_registers == (("w2", "eax"),)


def test_register_binding_solver_rejects_incompatible_surfaces() -> None:
    guest = WindowSurface(inputs=("w0", "w1"), outputs=("w2",))
    host = WindowSurface(inputs=("edi",), outputs=("eax",))

    problem = BindingProblem(_pair(), guest, host, has_memory=False)
    result = RegisterBindingSolver().solve(problem)

    assert result.skip_reason == "ambiguous_register_surface"
    assert result.input_registers == ()
    assert result.output_registers == ()


def test_binding_problem_preserves_semantic_context() -> None:
    pair = _pair()
    guest = WindowSurface(inputs=("w0",), outputs=("w1",))
    host = WindowSurface(inputs=("edi",), outputs=("eax",))

    problem = BindingProblem(pair, guest, host, has_memory=True)

    assert problem.pair is pair
    assert problem.guest_surface is guest
    assert problem.host_surface is host
    assert problem.has_memory
