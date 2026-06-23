import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_run_all_tests_help_describes_ir_kernel_learning() -> None:
    result = subprocess.run(
        [str(ROOT / "scripts" / "run_all_tests.sh"), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "IR-kernel constructive learning pipeline" in result.stdout
    assert "angr-rule-learning learn" in result.stdout
    assert "diagnose-skips" not in result.stdout
