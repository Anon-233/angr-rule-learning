from __future__ import annotations

from collections.abc import Iterable

import claripy


def fit_width(value, width: int):
    value_width = value.size()
    if value_width == width:
        return value
    if value_width < width:
        return value.zero_extend(width - value_width)
    return value[width - 1 : 0]


def align_widths(*values):
    width = max(value.size() for value in values)
    return tuple(fit_width(value, width) for value in values)


def merged_solver(*states) -> claripy.Solver:
    solver = claripy.Solver()
    for constraint in _constraints_from_states(states):
        solver.add(constraint)
    return solver


def _constraints_from_states(states: Iterable) -> Iterable:
    for state in states:
        yield from state.solver.constraints
