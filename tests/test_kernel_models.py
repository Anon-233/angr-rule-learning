from pathlib import Path

import pytest

from angr_rule_learning.kernel.models import KernelConfig, KernelSignature, KernelValue


def test_kernel_value_accepts_scalar_integer_types() -> None:
    value = KernelValue("a", "i32")

    assert value.name == "a"
    assert value.bit_width == 32


def test_kernel_value_rejects_unknown_types() -> None:
    with pytest.raises(ValueError, match="unsupported kernel value type"):
        KernelValue("a", "ptr")


def test_kernel_config_canonicalizes_architectures(tmp_path: Path) -> None:
    config = KernelConfig(work_dir=tmp_path, guest_arch="arm64", host_arch="amd64")

    assert config.guest_arch == "aarch64"
    assert config.host_arch == "x86-64"


def test_signature_rejects_missing_output() -> None:
    with pytest.raises(ValueError, match="at least one output"):
        KernelSignature(inputs=(KernelValue("a", "i32"),), outputs=())
