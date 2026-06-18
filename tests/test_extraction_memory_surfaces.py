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


def test_memory_surface_reports_one_sided_memory_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, ecx"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "one_sided_memory_access"


def test_memory_surface_reports_access_count_detail() -> None:
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
    assert surface.skip_detail == "memory_access_count_mismatch"


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


def test_uses_most_recent_producer_when_value_register_rewritten() -> None:
    """When the store value register is written multiple times,
    the most recent writer before the store must be the producer,
    not an earlier write whose value has been overwritten."""
    surface = infer_memory_surface(
        _pair(
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "mov",
                    "w8, w0",
                    reads=("w0",),
                    writes=("w8",),
                ),
                _inst(
                    "aarch64",
                    0x1004,
                    "add",
                    "w8, w1, #1",
                    reads=("w1",),
                    writes=("w8",),
                ),
                _inst(
                    "aarch64",
                    0x1008,
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
                    "mov",
                    "eax, edi",
                    reads=("edi",),
                    writes=("eax",),
                ),
                _inst(
                    "x86-64",
                    0x2003,
                    "lea",
                    "eax, [esi + 1]",
                    reads=("esi",),
                    writes=("eax",),
                ),
                _inst(
                    "x86-64",
                    0x2006,
                    "mov",
                    "dword ptr [rdx], eax",
                    reads=("rdx", "eax"),
                    writes=(),
                ),
            ),
        )
    )

    assert surface.skip_reason is None
    assert surface.input_registers == (("x9", "rdx"), ("w1", "esi"))


def test_chained_producer_collects_ultimate_external_sources() -> None:
    """When a producer's read register is itself internally defined,
    the chain must be traced back to collect the ultimate external sources."""
    surface = infer_memory_surface(
        _pair(
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "mov",
                    "w2, w0",
                    reads=("w0",),
                    writes=("w2",),
                ),
                _inst(
                    "aarch64",
                    0x1004,
                    "add",
                    "w8, w2, #1",
                    reads=("w2",),
                    writes=("w8",),
                ),
                _inst(
                    "aarch64",
                    0x1008,
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
                    "mov",
                    "esi, edi",
                    reads=("edi",),
                    writes=("esi",),
                ),
                _inst(
                    "x86-64",
                    0x2003,
                    "lea",
                    "eax, [esi + 1]",
                    reads=("esi",),
                    writes=("eax",),
                ),
                _inst(
                    "x86-64",
                    0x2006,
                    "mov",
                    "dword ptr [rdx], eax",
                    reads=("rdx", "eax"),
                    writes=(),
                ),
            ),
        )
    )

    assert surface.skip_reason is None
    # w2 is defined by mov w2, w0 (reads w0 external)
    # esi is defined by mov esi, edi (reads edi external)
    # Ultimate external sources: w0 and edi
    assert surface.input_registers == (("x9", "rdx"), ("w0", "edi"))


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


def test_memory_surface_reports_kind_and_width_details() -> None:
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

    assert kind.skip_detail == "memory_kind_mismatch"
    assert width.skip_detail == "memory_width_mismatch"


def test_memory_surface_reports_unparsed_access_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "q0, [x8]"),),
            (_inst("x86-64", 0x2000, "mov", "rax, qword ptr [rcx]"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "unparsed_memory_access"


def test_memory_surface_reports_address_register_count_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldr", "w0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "memory_address_register_count_mismatch"


def test_memory_surface_reports_store_value_internality_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "mov",
                    "w8, w1",
                    reads=("w1",),
                    writes=("w8",),
                ),
                _inst(
                    "aarch64",
                    0x1004,
                    "str",
                    "w8, [x9]",
                    reads=("w8", "x9"),
                ),
            ),
            (
                _inst(
                    "x86-64",
                    0x2000,
                    "mov",
                    "dword ptr [rdx], eax",
                    reads=("rdx", "eax"),
                ),
            ),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "store_value_internality_mismatch"


def test_rejects_register_to_immediate_store_value_pairing() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w8, [x29, #-4]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rbp - 4], 3"),),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "store_value_immediate_unsupported"


def test_memory_surface_reports_store_producer_source_count_detail() -> None:
    surface = infer_memory_surface(
        _pair(
            (
                _inst(
                    "aarch64",
                    0x1000,
                    "add",
                    "w8, w1, w2",
                    reads=("w1", "w2"),
                    writes=("w8",),
                ),
                _inst(
                    "aarch64",
                    0x1004,
                    "str",
                    "w8, [x9]",
                    reads=("w8", "x9"),
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
                    "dword ptr [rdx], eax",
                    reads=("rdx", "eax"),
                ),
            ),
        )
    )

    assert surface.skip_reason == "unsupported_memory_surface"
    assert surface.skip_detail == "store_producer_source_count_mismatch"


def test_frame_address_pairs_are_not_shared_input_registers() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "str", "w0, [sp, #12]"),),
            (_inst("x86-64", 0x2000, "mov", "dword ptr [rbp - 4], eax"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "sp + 12"
    assert surface.spec.bindings[0].host_addr == "rbp - 4"
    assert ("sp", "rbp") not in surface.input_registers
    assert ("w0", "eax") in surface.input_registers


def test_reverse_frame_address_pairs_are_not_shared_input_registers() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("x86-64", 0x1000, "mov", "dword ptr [rbp - 4], eax"),),
            (_inst("aarch64", 0x2000, "str", "w0, [sp, #12]"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.bindings[0].guest_addr == "rbp - 4"
    assert surface.spec.bindings[0].host_addr == "sp + 12"
    assert ("rbp", "sp") not in surface.input_registers
    assert ("eax", "w0") in surface.input_registers


def test_infers_sign_extension_load_surface() -> None:
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldrsw", "x0, [x1, x2, lsl #2]"),),
            (_inst("x86-64", 0x2000, "movsxd", "rax, dword ptr [rcx + rdx*4]"),),
        )
    )

    assert surface.skip_reason is None
    assert surface.spec.accesses[0].kind == "read"
    assert surface.spec.accesses[0].width == 4
    assert surface.input_registers == (("x1", "rcx"), ("x2", "rdx"))


# ── stack reordering tests ──────────────────────────────────────────────


def test_stp_pre_index_matches_push_push_by_address() -> None:
    """stp x0, x1, [sp, #-0x10]! (2 writes: x0@sp-16, x1@sp-8)
    should pair with push rsi; push rdi by address order:
    x0@-16 ↔ rdi@-16, x1@-8 ↔ rsi@-8."""
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "stp", "x0, x1, [sp, #-0x10]!"),),
            (
                _inst("x86-64", 0x2000, "push", "rsi"),
                _inst("x86-64", 0x2001, "push", "rdi"),
            ),
        )
    )

    assert surface.skip_reason is None
    assert len(surface.spec.slots) == 2
    assert surface.spec.accesses[0].kind == "write"
    # After reordering by address: guest[0](sp-16) ↔ host[1](rsp-16=rdi)
    assert surface.input_registers == (("x0", "rdi"), ("x1", "rsi"))


def test_ldp_post_index_matches_pop_pop_by_address() -> None:
    """ldp x0, x1, [sp], #0x10 (2 reads: x0@sp, x1@sp+8)
    should pair with pop rsi; pop rdi by effective address:
    x0@sp ↔ rdi@rsp, x1@sp+8 ↔ rsi@rsp+8."""
    surface = infer_memory_surface(
        _pair(
            (_inst("aarch64", 0x1000, "ldp", "x0, x1, [sp], #0x10"),),
            (
                _inst("x86-64", 0x2000, "pop", "rsi"),
                _inst("x86-64", 0x2001, "pop", "rdi"),
            ),
        )
    )

    assert surface.skip_reason is None
    assert len(surface.spec.slots) == 2
    assert surface.spec.accesses[0].kind == "read"
    # Bindings: after reorder by address, slot0=guest[0]↔host[1], slot1=guest[1]↔host[0]
    assert surface.spec.bindings[0].guest_addr == "sp"
    assert surface.spec.bindings[1].guest_addr == "sp + 8"
    assert surface.spec.bindings[0].host_addr == "rsp"
    assert surface.spec.bindings[1].host_addr == "rsp + 8"


def test_overlapping_stack_operands_return_unsupported() -> None:
    """Overlapping address ranges on the same side cannot be safely reordered."""
    # Non-overlapping: x0@sp-16 (8 bytes: -16..-9) and x1@sp-8 (8 bytes: -8..-1)
    surface = infer_memory_surface(
        _pair(
            (
                _inst("aarch64", 0x1000, "str", "x0, [sp, #-16]"),
                _inst("aarch64", 0x1004, "str", "x1, [sp, #-8]"),
            ),
            (
                _inst("x86-64", 0x2000, "push", "rsi"),
                _inst("x86-64", 0x2001, "push", "rdi"),
            ),
        )
    )
    assert surface.skip_reason is None

    # Overlapping: 4-byte writes at sp+4 (bytes 4-7) and sp+6 (bytes 6-9)
    surface2 = infer_memory_surface(
        _pair(
            (
                _inst("aarch64", 0x1000, "str", "w0, [sp, #4]"),
                _inst("aarch64", 0x1004, "str", "w1, [sp, #6]"),
            ),
            (
                _inst("x86-64", 0x2000, "mov", "dword ptr [rsp - 4], esi"),
                _inst("x86-64", 0x2005, "mov", "dword ptr [rsp - 2], edi"),
            ),
        )
    )
    assert surface2.skip_reason == "unsupported_memory_surface"
    assert surface2.skip_detail == "memory_address_order_conflict"


def test_original_order_preserved_for_non_stack_bases() -> None:
    """Operands with non-stack base registers keep original order."""
    surface = infer_memory_surface(
        _pair(
            (
                _inst("aarch64", 0x1000, "ldr", "w0, [x1]"),
                _inst("aarch64", 0x1004, "ldr", "w1, [x2]"),
            ),
            (
                _inst("x86-64", 0x2000, "mov", "eax, dword ptr [rcx]"),
                _inst("x86-64", 0x2003, "mov", "ebx, dword ptr [rdx]"),
            ),
        )
    )
    assert surface.skip_reason is None
    # Order preserved: guest[0]↔host[0], guest[1]↔host[1]
    assert surface.input_registers == (("x1", "rcx"), ("x2", "rdx"))
