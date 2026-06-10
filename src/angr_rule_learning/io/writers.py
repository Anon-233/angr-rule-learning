from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from angr_rule_learning.io.schema import report_to_json
from angr_rule_learning.verification.batch import BatchSummary
from angr_rule_learning.verification.report import VerificationReport


def write_reports_jsonl(path: Path, reports: Iterable[VerificationReport]) -> None:
    with path.open("w", encoding="utf-8") as output:
        for report in reports:
            json.dump(report_to_json(report), output, sort_keys=True)
            output.write("\n")


def write_summary_json(path: Path, summary: BatchSummary) -> None:
    path.write_text(
        json.dumps(summary.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
