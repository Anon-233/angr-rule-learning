from __future__ import annotations

from dataclasses import dataclass
import logging

import angr

from angr_rule_learning.arch.registry import angr_arch_name
from angr_rule_learning.smt.solver import fit_width
from angr_rule_learning.verification.candidate import CodeFragment


logging.getLogger("angr.engines.unicorn").setLevel(logging.ERROR)


@dataclass(frozen=True)
class ExecutedFragment:
    state: angr.SimState


class FragmentExecutor:
    def make_state(self, fragment: CodeFragment) -> angr.SimState:
        project = angr.load_shellcode(
            fragment.code_bytes,
            arch=angr_arch_name(fragment.arch),
            load_address=fragment.address,
        )
        return project.factory.blank_state(addr=fragment.address)

    def execute(self, fragment: CodeFragment, state: angr.SimState) -> ExecutedFragment:
        successors = state.project.factory.successors(
            state, num_inst=fragment.instruction_count
        ).successors
        if len(successors) != 1:
            raise ValueError(f"expected exactly one successor, got {len(successors)}")
        return ExecutedFragment(successors[0])


def read_reg(state: angr.SimState, reg: str):
    return getattr(state.regs, reg)


def write_reg(state: angr.SimState, reg: str, value) -> None:
    setattr(state.regs, reg, fit_width(value, reg_width(state, reg)))


def reg_width(state: angr.SimState, reg: str) -> int:
    try:
        return state.arch.registers[reg][1] * state.arch.byte_width
    except KeyError as exc:
        raise ValueError(f"unknown register for {state.arch.name}: {reg}") from exc
