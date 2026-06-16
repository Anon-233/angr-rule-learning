from angr_rule_learning.extraction.memory_surfaces import infer_memory_surface
from angr_rule_learning.extraction.models import (
    ExtractedInstruction,
    InstructionWindow,
    WindowPair,
)


def _inst(
    arch: str,
    address: int,
    mnemonic: str,
    op_str: str,
    *,
    reads: tuple[str, ...] = (),
    writes: tuple[str, ...] = (),
) -> ExtractedInstruction:
    return ExtractedInstruction(
        arch=arch,
        address=address,
        size=4,
        code_bytes=b"\x01\x02\x03\x04",
        mnemonic=mnemonic,
        op_str=op_str,
        function="f",
        source=None,
        read_registers=reads,
        write_registers=writes,
    )


def _pair(
    guest: tuple[ExtractedInstruction, ...],
    host: tuple[ExtractedInstruction, ...],
) -> WindowPair:
    return WindowPair(
        region_id="r0",
        stage=(len(guest), len(host)),
        guest=InstructionWindow("r0", "guest", guest),
        host=InstructionWindow("r0", "host", host),
    )


def test_infers_equivalent_load_memory_spec() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),),
        )
    )

    assert surface.skip_reason is None
    assert len(surface.spec.slots) == 1
    assert surface.spec.bindings[0].guest_addr == "x1"
    assert surface.spec.bindings[0].host_addr == "rcx"
    assert surface.spec.accesses[0].kind == "read"
    assert surface.spec.accesses[0].width == 4
    assert surface.input_registers == (("x1", "rcx"),)


def test_infers_store_value_register_inputs() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w0, [x1, #4]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx + 4], eax"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "x1 + 4"
    assert surface.spec.bindings[0].host_addr == "rcx + 4"
    assert surface.spec.accesses[0].kind == "write"
    assert surface.input_registers == (("x1", "rcx"), ("w0", "eax"))


def test_rejects_memory_access_count_mismatch() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (
                _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),
                _inst("x86-64", 0x2004, "mov", "edx, dword ptr [rbx]"),
            ),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"


def test_infers_indexed_load_address_register_inputs() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx + rdx*4]"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "x1 + x2 * 4"
    assert surface.spec.bindings[0].host_addr == "rcx + rdx * 4"
    assert surface.input_registers == (("x1", "rcx"), ("x2", "rdx"))


def test_infers_indexed_store_value_and_address_inputs() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx + rdx*4], eax"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.input_registers == (
        ("x1", "rcx"),
        ("x2", "rdx"),
        ("w0", "eax"),
    )


def test_does_not_treat_internally_defined_store_value_as_input() -> None:
    """A store value produced by a prior instruction in the same window
    must not be treated as an external input; its producer's external
    source registers must appear instead."""
    surface = infer_memory_surface(
        _pair(
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "add",
                    "w8, w1, #1",
                    reads=("w1",),
                    writes=("w8",),
                ),
                _inst(
                    "aarch64",
                    0x1004,
                    "str",
                    "w8, [x9]",
                    reads=("w8", "x9"),
                    writes=(),
                ),
            ),
            (
                _inst(
                    "x86-64",
                    0x2000,
                    "lea",
                    "eax, [esi + 1]",
                    reads=("esi",),
                    writes=("eax",),
                ),
                _inst(
                    "x86-64",
                    0x2003,
                    "mov",
                    "dword ptr [rdi], eax",
                    reads=("rdi", "eax"),
                    writes=(),
                ),
            ),
        )
    )

    assert surface.skip_reason is None
    # Address registers + producer source registers; NOT the value registers w8/eax
    assert surface.input_registers == (("x9", "rdi"), ("w1", "esi"))


def test_rejects_memory_kind_or_width_mismatch() -> None:
    kind = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rcx], eax"),),
        )
    )
    width = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "rax, qword ptr [rcx]"),),
        )
    )

    assert kind.skip_reason == "unsupported_memory_surface"
    assert width.skip_reason == "unsupported_memory_surface"
