# Verifier-First Redesign

Date: 2026-06-09

## Context

The current project is a small angr prototype. It can verify one hand-written
AArch64 to x86-64 register-only candidate by executing both shellcode fragments
with angr and asking Claripy whether the output register difference is
satisfiable.

The preserved legacy implementation in `../legacy_original_20260609` contains
the older learning pipeline: compiler driving, source-line mapping, instruction
parsing, candidate filtering, liveness analysis, memory mapping, immediate
mapping, verification, rule generalization, and benchmark statistics. Its
Python glue is useful as a source of design intent, but the verifier integration
is not a good target for direct migration: the captured `do_verification()`
path no longer parses a structured verification result and mostly delegates to
the old external Vine/FuzzBALL toolchain.

The next phase will therefore rebuild the verifier as the stable core of the
new system. The learning pipeline, rule generation, and coverage reporting will
be built around that core later.

## Goals

- Build a robust verifier for short AArch64 integer to x86-64 integer rule
  candidates.
- Treat memory verification as a first-class design concern from the start.
- Keep the verifier reusable as a Python API for the future full learning
  pipeline.
- Keep JSON/JSONL and CLI support as external boundaries, not as internal data
  plumbing.
- Produce structured reports that classify failure reasons instead of returning
  only true or false.
- Organize code into packages early so memory modeling, SMT checks, schema I/O,
  and CLI logic do not become tangled.

## Non-Goals

- Recreate the entire legacy learning pipeline in this phase.
- Reimplement the old OCaml/Vine/FuzzBALL verifier behavior.
- Build a general-purpose symbolic execution framework on top of angr.
- Support loops, cross-function execution, or unrestricted path exploration.
- Prove complex `may_alias` cases in the first implementation.
- Accept legacy schema fields such as `init_map` in the new verifier schema.

## Recommended Approach

Use an event-tracking verifier specialized for short rule fragments.

The verifier executes the guest and host fragments separately with angr. During
execution it records only the semantic events that matter for rule validation:
register outputs, flag outputs, memory reads, memory writes, and branch guards
when those are later enabled. A relational checker then compares the paired
events and output values with Claripy SMT queries.

This approach is preferred over directly comparing final whole states because
it gives clear failure categories such as address mismatch, access-width
mismatch, read-value mismatch, write-value mismatch, register mismatch, and
unsupported alias relation. It is also much smaller than a custom relational
symbolic executor.

## Internal API

The verifier core is API-first. Future pipeline code should construct typed
Python objects and call the verifier directly:

```python
report = SemanticVerifier().verify(candidate)
```

Batch processing should also be available as a library API:

```python
reports = BatchVerifier(verifier).verify_many(candidates)
```

JSON/JSONL is an external exchange format for CLI usage, regression fixtures,
offline experiments, and failure-case archival. It is not the required internal
format between pipeline stages.

## Candidate Model

The internal candidate object should contain these conceptual sections:

- `candidate_id`: stable identifier used in batch reports and coverage joins.
- `guest`: architecture, load address, machine-code bytes, and instruction
  count for the guest fragment.
- `host`: architecture, load address, machine-code bytes, and instruction count
  for the host fragment.
- `inputs`: initial register relations and, later, constant or expression
  inputs.
- `outputs`: explicit register and flag pairs that must be equivalent after
  execution.
- `memory`: logical memory slots, guest/host address bindings, expected memory
  accesses, and alias declarations.
- `preconditions`: constraints that define the valid domain of the rule, such
  as alignment, nonzero divisors, or bounded shift amounts.
- `clobbers`: state that may differ and should not be treated as an output.

The verifier must not infer the entire rule context from raw machine code. The
candidate generator is responsible for providing the context needed to decide
which inputs are shared, which outputs matter, and how memory objects correspond
across ISAs.

## External JSON Shape

The JSON schema should mirror the internal model but remain isolated in the I/O
layer. A representative candidate looks like this:

```json
{
  "candidate_id": "rule-0001",
  "guest": {
    "arch": "aarch64",
    "address": 65536,
    "code_hex": "...",
    "instruction_count": 2
  },
  "host": {
    "arch": "x86-64",
    "address": 134512640,
    "code_hex": "...",
    "instruction_count": 2
  },
  "inputs": {
    "registers": [["x1", "rcx"], ["x2", "rdx"]]
  },
  "outputs": {
    "registers": [["x0", "rax"]],
    "flags": [["nzcv.z", "zf"]]
  },
  "memory": {
    "slots": [
      {
        "name": "mem0",
        "size": 8,
        "initial": "symbolic"
      }
    ],
    "bindings": [
      {
        "slot": "mem0",
        "guest_addr": "x1",
        "host_addr": "rcx",
        "access": "read_write"
      }
    ],
    "accesses": [
      {
        "slot": "mem0",
        "kind": "read",
        "width": 4
      },
      {
        "slot": "mem0",
        "kind": "write",
        "width": 4
      }
    ],
    "alias": [
      {
        "slots": ["mem0", "mem1"],
        "relation": "disjoint"
      }
    ]
  },
  "preconditions": ["mem0.aligned(4)"],
  "clobbers": {
    "guest": ["x9"],
    "host": ["r10", "r11"]
  }
}
```

Field intent:

- `guest` and `host` define the executable fragments and their execution
  bounds.
- `inputs.registers` declares shared symbolic inputs across ISAs.
- `outputs` declares the post-state facts the verifier must prove.
- `memory.slots` declares abstract memory objects.
- `memory.bindings` connects each abstract object to guest and host address
  expressions.
- `memory.accesses` states the expected access kind and width.
- `memory.alias` explicitly declares `disjoint`, `must_alias`, or `may_alias`
  relations.
- `preconditions` constrain the rule domain.
- `clobbers` documents state that may differ.

The schema layer should be strict. It should reject unknown legacy fields rather
than silently accepting them. If legacy imports become useful later, they should
live in a separate converter and emit the new candidate model.

## Memory Model

The first implementation should use a hybrid memory model.

The candidate declares abstract logical memory slots such as `mem0` and `mem1`.
The verifier still lets angr execute real ISA address computations. Recorded
memory events include the actual symbolic address expression, value expression,
access width, endianness, and instruction index.

For each slot, the verifier initializes symbolic bytes of the declared size.
Guest and host states are connected to the same logical initial content for
corresponding slots.

Alias handling is explicit:

- `disjoint`: add constraints that the involved slots do not overlap.
- `must_alias`: make the involved slots share the same logical object.
- `may_alias`: return an unsupported result in the first implementation.

This avoids hidden non-alias assumptions while keeping the first verifier
tractable.

## SMT Checks

The relational checker should use Claripy queries to validate the following:

- The guest and host fragments each produce exactly one successor in the first
  implementation.
- Memory access counts match the declared expectations.
- Paired memory access kinds match.
- Paired memory access widths match.
- Actual access addresses satisfy the declared guest/host bindings.
- Guest and host reads from the same logical slot observe equivalent values.
- Guest and host writes to the same logical slot write equivalent values.
- Declared output registers are equivalent after width normalization.
- Declared output flags are equivalent after architecture-specific extraction.
- Preconditions are applied to both executions before equivalence queries.

The equivalence proof remains contradiction-based:

```text
If guest_value != host_value is UNSAT, the checked fact is equivalent.
If it is SAT, the model is a counterexample.
```

## Failure Taxonomy

Reports should distinguish at least these outcomes:

- `pass`
- `fail`
- `unsupported`
- `angr_error`

Failure and unsupported reasons should include:

- `multi_successor_unsupported`
- `unsupported_may_alias`
- `undeclared_memory_access`
- `memory_access_count_mismatch`
- `memory_access_kind_mismatch`
- `memory_access_width_mismatch`
- `memory_address_mismatch`
- `memory_read_value_mismatch`
- `memory_write_value_mismatch`
- `register_mismatch`
- `flag_mismatch`
- `precondition_error`
- `angr_execution_error`

Each failed SMT check should provide a counterexample when the solver can
produce one. Reports should identify the candidate, check kind, guest object,
host object, reason, and relevant event index.

## Batch-Oriented CLI

The CLI should be a thin wrapper around the API. It should not contain verifier
logic.

The main command should support batch inputs from the beginning:

```bash
uv run angr-rule-learning verify candidates.jsonl --output report.jsonl
```

JSONL is the preferred batch exchange format because each line can represent
one candidate and results can be streamed. Directory input can be added for
debugging collections of individual candidate files:

```bash
uv run angr-rule-learning verify candidates/ --output reports/
```

Single-file JSON verification may remain available as a developer convenience,
but the architecture should be built around `CandidateReader`, `BatchVerifier`,
and `ReportWriter`.

Reports should be emitted as:

- detail JSONL: one verification report per candidate.
- summary JSON: aggregate counts by status and failure reason.

## Source Layout

The project should move away from a flat `src/angr_rule_learning` layout before
the verifier grows.

Target package structure:

```text
src/angr_rule_learning/
  __init__.py
  cli.py

  verification/
    __init__.py
    candidate.py
    config.py
    verifier.py
    batch.py
    execution.py
    memory.py
    checks.py
    report.py
    errors.py

  io/
    __init__.py
    schema.py
    readers.py
    writers.py

  arch/
    __init__.py
    registry.py
    registers.py
    flags.py

  smt/
    __init__.py
    solver.py
    counterexample.py
```

Boundary rules:

- Raw JSON dict access belongs only in `io/`.
- JSON schema parsing and validation belongs in `io/schema.py`.
- CLI code only orchestrates readers, batch verification, and writers.
- angr state setup and execution belongs in `verification/execution.py` or
  `verification/verifier.py`.
- memory slot modeling and event recording belongs in `verification/memory.py`.
- relational checks belong in `verification/checks.py`.
- Claripy helper utilities belong in `smt/`.
- architecture aliases, register widths, and flag extraction belong in `arch/`.

## Implementation Stages

1. Create the typed candidate/report/config model and package layout.
2. Move JSON parsing and writing into `io/`, using the new schema only.
3. Add a batch-oriented CLI wrapper over `BatchVerifier`.
4. Port the current register-only verifier into the new API.
5. Add memory event recording and single-load equivalence tests.
6. Add store and read-write memory equivalence tests.
7. Add explicit alias handling for `disjoint` and `must_alias`; report
   `may_alias` as unsupported.
8. Add flag and condition-code output checks.
9. Add summary reporting that can later feed coverage analysis against the
   complete AArch64 to x86-64 integer rule table.

Each stage should include positive and negative tests. Python source changes
should be followed by `uv run ruff format`, `uv run ruff check`, and relevant
tests.
