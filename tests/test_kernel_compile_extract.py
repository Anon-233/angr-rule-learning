import shutil

import pytest

from angr_rule_learning.kernel.compile import KernelCompiler
from angr_rule_learning.kernel.extract import SnippetExtractor
from angr_rule_learning.kernel.models import KernelConfig
from angr_rule_learning.kernel.synthesize import HardcodedKernelSynthesizer


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_compile_and_extract_add_kernel_for_both_architectures(tmp_path) -> None:
    kernel = next(
        k for k in HardcodedKernelSynthesizer().generate() if k.name == "kernel_add_i32"
    )
    config = KernelConfig(work_dir=tmp_path, optimization="1")

    compiled = KernelCompiler().compile_pair(kernel, config)
    snippets = SnippetExtractor().extract_pair(compiled, config)

    assert snippets.guest.instructions
    assert snippets.host.instructions
    assert all(inst.mnemonic != "ret" for inst in snippets.guest.instructions)
    assert all(inst.mnemonic != "ret" for inst in snippets.host.instructions)
    assert snippets.guest.instructions[0].arch == "aarch64"
    assert snippets.host.instructions[0].arch == "x86-64"
