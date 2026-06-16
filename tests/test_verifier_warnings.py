from __future__ import annotations

import logging

from angr_rule_learning.verification.candidate import CodeFragment
from angr_rule_learning.verification.execution import FragmentExecutor


def test_fragment_executor_suppresses_angr_default_filler_warnings(caplog) -> None:
    fragment = CodeFragment("x86-64", 0x400000, "01 c8", 1)  # add eax, ecx
    executor = FragmentExecutor()
    state = executor.make_state(fragment)

    caplog.set_level(
        logging.WARNING,
        logger="angr.storage.memory_mixins.default_filler_mixin",
    )

    executor.successors(fragment, state)

    assert not [
        record
        for record in caplog.records
        if record.name == "angr.storage.memory_mixins.default_filler_mixin"
    ]
