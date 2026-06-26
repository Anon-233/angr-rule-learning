from pathlib import Path

import pytest

from angr_rule_learning.kernel.models import (
    BindingSpec,
    KernelConfig,
    KernelSignature,
    KernelValue,
)


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


def test_signature_allows_void_output() -> None:
    signature = KernelSignature(inputs=(KernelValue("a", "i32"),), outputs=())

    assert signature.inputs == (KernelValue("a", "i32"),)
    assert signature.outputs == ()


def test_binding_spec_allows_no_register_outputs() -> None:
    spec = BindingSpec(inputs=(("a", "w0", "edi"),), outputs=())

    assert spec.input_registers == (("w0", "edi"),)
    assert spec.output_registers == ()
