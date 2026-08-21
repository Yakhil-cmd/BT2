# Q1959: crypto host cost in signature::ml_dsa_65_from_seed

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling input element counts at the configured maxima, drive `core/crypto/src/signature.rs::ml_dsa_65_from_seed` to spend far more CPU on curve arithmetic than the gas charged, breaking the invariant that curve host functions are charged per element and per operation actually performed, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/crypto/src/signature.rs` -> `ml_dsa_65_from_seed`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: input element counts at the configured maxima
- Exploit idea: spend far more CPU on curve arithmetic than the gas charged
- Invariant to test: curve host functions are charged per element and per operation actually performed
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
