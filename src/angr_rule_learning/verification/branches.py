from __future__ import annotations

import claripy

from angr_rule_learning.verification.candidate import CodeFragment
from angr_rule_learning.verification.context import CheckContext
from angr_rule_learning.verification.relations import RelationChecker
from angr_rule_learning.verification.report import CheckResult


CONDITIONAL_BRANCH_MNEMONICS = {
    "aarch64": ("b.", "cbz", "cbnz", "tbz", "tbnz"),
    "x86-64": ("j",),
}


def has_non_terminal_branch(fragment: CodeFragment, state: object) -> bool:
    insns = _fragment_insns(fragment, state)
    if len(insns) < 2:
        return False
    return any(
        _is_conditional_branch(fragment.arch, insn.mnemonic) for insn in insns[:-1]
    )


def _fragment_insns(fragment: CodeFragment, state: object) -> tuple[object, ...]:
    return tuple(
        state.project.arch.capstone.disasm(fragment.code_bytes, fragment.address)
    )


def _is_conditional_branch(arch: str, mnemonic: str) -> bool:
    normalized_arch = arch.strip().lower()
    normalized_mnemonic = mnemonic.strip().lower()
    prefixes = CONDITIONAL_BRANCH_MNEMONICS.get(normalized_arch, ())
    if normalized_arch == "x86-64" and normalized_mnemonic == "jmp":
        return False
    return any(normalized_mnemonic.startswith(prefix) for prefix in prefixes)


def _guard_to_bitvector(guard: object) -> claripy.ast.BV:
    if isinstance(guard, claripy.ast.Bool):
        return claripy.If(guard, claripy.BVV(1, 1), claripy.BVV(0, 1))
    if not isinstance(guard, claripy.ast.BV):
        raise ValueError("branch_shape_unsupported")
    if guard.size() == 1:
        return guard
    return guard[0:0]


def terminal_taken_guard(
    fragment: CodeFragment,
    state: object,
    successors: tuple[object, ...],
) -> claripy.ast.BV:
    if len(successors) != 2:
        raise ValueError("branch_shape_unsupported")
    insns = _fragment_insns(fragment, state)
    if not insns or not _is_conditional_branch(fragment.arch, insns[-1].mnemonic):
        raise ValueError("branch_shape_unsupported")
    fallthrough = insns[-1].address + insns[-1].size
    taken = [s for s in successors if s.addr != fallthrough]
    if len(taken) != 1:
        raise ValueError("unmatched_successor_shape")
    guard = taken[0].history.jump_guard
    if guard is None:
        raise ValueError("branch_shape_unsupported")
    return _guard_to_bitvector(guard)


def check_terminal_branch_guard(
    context: CheckContext,
    guest_fragment: CodeFragment,
    host_fragment: CodeFragment,
    guest_successors: tuple[object, ...],
    host_successors: tuple[object, ...],
) -> CheckResult | None:
    if has_non_terminal_branch(
        guest_fragment, context.guest_state
    ) or has_non_terminal_branch(host_fragment, context.host_state):
        return CheckResult(
            "branch",
            "unsupported",
            "branch",
            "branch",
            reason="non_terminal_branch_unsupported",
        )
    if len(guest_successors) == 1 and len(host_successors) == 1:
        return None
    try:
        guest_guard = terminal_taken_guard(
            guest_fragment,
            context.guest_state,
            guest_successors,
        )
        host_guard = terminal_taken_guard(
            host_fragment,
            context.host_state,
            host_successors,
        )
    except ValueError as exc:
        return CheckResult(
            "branch",
            "unsupported",
            "branch",
            "branch",
            reason=str(exc),
        )
    checker = RelationChecker(symbols=context.symbols, constraints=context.constraints)
    return checker.check_equal(
        kind="branch",
        guest="taken_guard",
        host="taken_guard",
        guest_expr=guest_guard,
        host_expr=host_guard,
        mismatch_reason="branch_guard_mismatch",
    )
