from __future__ import annotations

from angr_rule_learning.verification.candidate import (
    CodeFragment,
    MemoryBinding,
    MemorySlot,
    MemorySpec,
    VerificationCandidate,
)
from angr_rule_learning.verification.config import VerificationConfig
from angr_rule_learning.verification.execution import FragmentExecutor
from angr_rule_learning.verification.memory import (
    MemoryEventRecorder,
    MemoryInitializer,
)


AARCH64_LDR_W0_X1 = "20 00 40 b9"  # ldr w0, [x1]
X86_64_MOV_EAX_RCX = "8b 01"  # mov eax, [rcx]


def _load_candidate() -> VerificationCandidate:
    return VerificationCandidate(
        candidate_id="load32",
        guest=CodeFragment("aarch64", 0x10000, AARCH64_LDR_W0_X1, 1),
        host=CodeFragment("x86-64", 0x8048000, X86_64_MOV_EAX_RCX, 1),
        memory=MemorySpec(
            slots=(MemorySlot("mem0", 4),),
            bindings=(MemoryBinding("mem0", "x1", "rcx", "read"),),
        ),
    )


def test_memory_initializer_binds_guest_and_host_address_registers() -> None:
    candidate = _load_candidate()
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)

    layout = MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )

    assert layout.slot_base("mem0") == 0x70000000
    assert guest_state.solver.eval(guest_state.regs.x1) == 0x70000000
    assert host_state.solver.eval(host_state.regs.rcx) == 0x70000000


def test_memory_event_recorder_captures_read_events() -> None:
    candidate = _load_candidate()
    executor = FragmentExecutor()
    guest_state = executor.make_state(candidate.guest)
    host_state = executor.make_state(candidate.host)
    MemoryInitializer(VerificationConfig()).initialize(
        candidate, guest_state, host_state
    )
    recorder = MemoryEventRecorder()
    recorder.install(guest_state, "guest")
    recorder.install(host_state, "host")

    executor.execute(candidate.guest, guest_state)
    executor.execute(candidate.host, host_state)

    assert len(recorder.events) == 2
    assert recorder.events[0].side == "guest"
    assert recorder.events[0].kind == "read"
    assert recorder.events[1].side == "host"
    assert recorder.events[1].kind == "read"
