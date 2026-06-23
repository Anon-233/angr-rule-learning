import shutil

import pytest

from angr_rule_learning.kernel.bind import KernelBindingBuilder
from angr_rule_learning.kernel.compile import KernelCompiler
from angr_rule_learning.kernel.extract import SnippetExtractor
from angr_rule_learning.kernel.models import KernelConfig
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


def _kernel(name: str):
    return next(k for k in HardcodedKernelSynthesizer().generate() if k.name == name)


def test_scalar_i32_abi_binding_for_aarch64_to_x86_64() -> None:
    spec = KernelBindingBuilder().build_spec(_kernel("kernel_add_i32"), "aarch64", "x86-64")

    assert spec.inputs == (("a", "w0", "edi"), ("b", "w1", "esi"))
    assert spec.outputs == (("r", "w0", "eax"),)


def test_scalar_i32_abi_binding_for_reverse_direction() -> None:
    spec = KernelBindingBuilder().build_spec(_kernel("kernel_add_i32"), "x86-64", "aarch64")

    assert spec.inputs == (("a", "edi", "w0"), ("b", "esi", "w1"))
    assert spec.outputs == (("r", "eax", "w0"),)


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_build_candidate_from_compiled_kernel_snippets(tmp_path) -> None:
    kernel = _kernel("kernel_add_i32")
    config = KernelConfig(work_dir=tmp_path, optimization="1")
    compiled = KernelCompiler().compile_pair(kernel, config)
    snippets = SnippetExtractor().extract_pair(compiled, config)

    pair, candidate = KernelBindingBuilder().build_candidate(kernel, snippets)

    assert pair.region_id == kernel.id
    assert candidate.candidate_id == "kernel_add_i32"
    assert candidate.input_registers == (("w0", "edi"), ("w1", "esi"))
    assert candidate.output_registers == (("w0", "eax"),)
    assert candidate.guest.code_hex == pair.guest.code_hex
    assert candidate.host.code_hex == pair.host.code_hex
