# Architecture

The refactored project treats rule learning as a pipeline of small, testable
components.

```text
Compiler Driver
  -> Source Mapper
  -> Candidate Builder
  -> Semantic Verifier
  -> Rule Generalizer
  -> Rule Store
  -> Evaluation Harness
```

## Semantic Verifier

The verifier is the first component being rebuilt. The initial target pair is
AArch64 integer code to x86-64 integer code, because that can be evaluated
against an existing complete rule table. It uses:

- angr for shellcode loading, lifting, and symbolic execution
- Claripy for symbolic bit-vectors and SMT queries
- Z3 through Claripy's backend

The equivalence check is formulated by contradiction:

```text
If output_guest != output_host is UNSAT, the checked output is equivalent.
If it is SAT, the model is a counterexample.
```

The verifier checks semantic surfaces rather than instruction families:
register outputs, memory events, explicit flags, and terminal branch guards.
Instruction semantics come from angr; the verifier compares observed Claripy
expressions through shared SMT relation checks.

Reports use four top-level statuses: `pass`, `fail`, `unsupported`, and `error`.
Each check result includes stable machine-readable reasons, counterexamples, and
optional JSON-shaped metadata for downstream diagnostics.

## Request Boundary

Verifier input is intentionally JSON-shaped:

```json
{
  "candidate_id": "aarch64-add-x86-64-lea",
  "guest": {
    "arch": "aarch64",
    "address": 65536,
    "code_hex": "20 00 02 8b",
    "instruction_count": 1
  },
  "host": {
    "arch": "x86-64",
    "address": 134512640,
    "code_hex": "48 8d 04 11",
    "instruction_count": 1
  },
  "inputs": {
    "registers": [["x1", "rcx"], ["x2", "rdx"]]
  },
  "outputs": {
    "registers": [["x0", "rax"]],
    "flags": []
  },
  "memory": {
    "slots": [],
    "bindings": [],
    "accesses": [],
    "alias": []
  },
  "preconditions": [],
  "clobbers": {
    "guest": [],
    "host": []
  }
}
```

This boundary should remain stable as candidate extraction and rule
generalization are rebuilt around it.
