# Q3956: value-return size in ext::post_quantum_keys_enabled

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling return values at and beyond the configured maximum length, drive `runtime/runtime/src/ext.rs::post_quantum_keys_enabled` to return more bytes than the limit while paying for fewer, breaking the invariant that returned data is bounded and charged by its real length, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `post_quantum_keys_enabled`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: return values at and beyond the configured maximum length
- Exploit idea: return more bytes than the limit while paying for fewer
- Invariant to test: returned data is bounded and charged by its real length
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
