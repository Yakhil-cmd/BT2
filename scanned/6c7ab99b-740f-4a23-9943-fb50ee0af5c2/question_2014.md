# Q2014: parameter table divergence in vm::non_crypto_hash

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling paths that read the parameter table through different accessors, drive `core/parameters/src/vm.rs::non_crypto_hash` to have two accessors return different values for one parameter, breaking the invariant that all accessors agree on every parameter value, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/parameters/src/vm.rs` -> `non_crypto_hash`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: paths that read the parameter table through different accessors
- Exploit idea: have two accessors return different values for one parameter
- Invariant to test: all accessors agree on every parameter value
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
