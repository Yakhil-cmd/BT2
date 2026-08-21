# Q2768: crypto host cost in alt_bn128::decode_u256

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling input element counts at the configured maxima, drive `runtime/near-vm-runner/src/logic/alt_bn128.rs::decode_u256` to spend far more CPU on curve arithmetic than the gas charged, breaking the invariant that curve host functions are charged per element and per operation actually performed, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/alt_bn128.rs` -> `decode_u256`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: input element counts at the configured maxima
- Exploit idea: spend far more CPU on curve arithmetic than the gas charged
- Invariant to test: curve host functions are charged per element and per operation actually performed
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
