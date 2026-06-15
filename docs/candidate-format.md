# Candidate And Report Format

The verifier boundary is JSON-shaped and strict. Every top-level candidate field
is required, and unknown fields are rejected. JSON readers convert payloads into
typed dataclasses before verification.

The CLI accepts one of three input shapes through `io.readers`:

- a `.jsonl` file with one candidate object per non-empty line;
- any other file suffix as one JSON candidate object;
- a directory containing `.json` files, read in sorted path order.

## Candidate JSON

Minimal example:

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

### Top-Level Fields

- `candidate_id`: stable candidate identifier used in reports.
- `guest`: guest machine-code fragment.
- `host`: host machine-code fragment.
- `inputs`: paired symbolic inputs.
- `outputs`: requested semantic outputs.
- `memory`: memory slots, bindings, expected events, and alias declarations.
- `preconditions`: reserved for future SMT precondition support. Non-empty
  values currently return `unsupported`.
- `clobbers`: reserved clobber metadata. It is parsed but not yet used by the
  verifier.

### Fragment Fields

`guest` and `host` each contain:

- `arch`: project architecture name. Currently `aarch64` and `x86-64` are used.
- `address`: integer load address for shellcode execution.
- `code_hex`: hex-encoded machine code. Spaces, commas, underscores, and `0x`
  prefixes are normalized.
- `instruction_count`: number of instructions to execute.

### Inputs

`inputs.registers` is a list of `[guest_register, host_register]` pairs. Each
pair receives the same Claripy symbol before execution.

The symbol width is the maximum of the two register widths. Register writes are
width-adjusted before being assigned to the architecture state.

### Outputs

`outputs.registers` is a list of register pairs to compare after execution.

`outputs.flags` is a list of flag pairs to compare after execution. Supported
flag names are documented in [Verifier](verifier.md).

For terminal branch candidates, explicit register outputs currently produce
`branch_register_outputs_unsupported`.

### Memory

`memory.slots` declares symbolic memory regions:

- `name`: slot identifier.
- `size`: byte size.
- `initial`: currently only `symbolic` is supported; if omitted, it defaults to
  `symbolic`.

`memory.bindings` maps slots to guest/host address expressions:

- `slot`: declared slot name.
- `guest_addr`: guest address binding expression.
- `host_addr`: host address binding expression.
- `access`: `read`, `write`, or `read_write`.

Supported address expressions are:

- `reg`
- `reg + const`
- `reg - const`
- `reg + index * scale`
- `reg + index * scale + const`
- `reg + index * scale - const`

JSON fields remain string-based for compatibility, while the verifier
parses these strings into the shared ``AddressExpr`` model internally.

```json
{
  "slot": "mem0",
  "guest_addr": "x1 + x2 * 4 + 8",
  "host_addr": "rcx + rdx * 4 + 8",
  "access": "read"
}
```

`memory.accesses` declares expected memory events in order:

- `slot`: declared slot name.
- `kind`: `read` or `write`.
- `width`: byte width.

`memory.alias` declares slot alias relations:

- `slots`: two or more slot names.
- `relation`: `disjoint`, `must_alias`, or `may_alias`.

`must_alias` slots share one base address. `disjoint` slots receive separate
base addresses. `may_alias` currently returns `unsupported_may_alias`.

### Preconditions

`preconditions` is a list of strings reserved for future parsing and SMT
constraint injection. Any non-empty list currently returns `unsupported` with
reason `preconditions`.

### Clobbers

`clobbers.guest` and `clobbers.host` are parsed as register-name lists. They are
reserved for later rule metadata and are not enforced by the verifier today.

## Report JSON

Each verification report serializes as:

```json
{
  "candidate_id": "aarch64-add-x86-64-lea",
  "equivalent": true,
  "status": "pass",
  "checks": [
    {
      "kind": "register",
      "status": "pass",
      "guest": "x0",
      "host": "rax",
      "reason": "",
      "counterexample": {},
      "metadata": {}
    }
  ],
  "unsupported_features": [],
  "events": [],
  "failure_reasons": {}
}
```

Top-level fields:

- `candidate_id`: copied from the candidate.
- `equivalent`: true only when report status is `pass` and all checks pass.
- `status`: `pass`, `fail`, `unsupported`, or `error`.
- `checks`: per-surface check results.
- `unsupported_features`: top-level unsupported feature reasons.
- `events`: reserved structured event metadata.
- `failure_reasons`: reason counts aggregated from check reasons and
  unsupported features.

Check fields:

- `kind`: semantic surface, such as `register`, `memory`, `flag`, `branch`, or
  `execution`.
- `status`: `pass`, `fail`, `unsupported`, or `error`.
- `guest`: guest-side register, flag, slot, or diagnostic label.
- `host`: host-side register, flag, slot, or diagnostic label.
- `reason`: machine-readable reason. Empty for passing checks.
- `counterexample`: input-symbol model when a mismatch is satisfiable.
- `metadata`: JSON-shaped diagnostic data, such as event index, width, side, or
  error details.

## Batch Summary JSON

Batch verification writes a summary object:

```json
{
  "total": 1,
  "statuses": {
    "pass": 1
  },
  "failure_reasons": {},
  "by_kind": {
    "register": {
      "pass": 1
    }
  },
  "top_reasons": {}
}
```

Fields:

- `total`: number of reports.
- `statuses`: count by top-level report status.
- `failure_reasons`: aggregate reason counts across all reports.
- `by_kind`: count by check kind and check status.
- `top_reasons`: currently the same reason counts as `failure_reasons`.

## Compatibility Policy

The current project does not carry backward input compatibility. Schema changes
should be explicit, tested, and documented here. Unknown fields should continue
to fail fast so pipeline stages do not silently drift out of sync.
