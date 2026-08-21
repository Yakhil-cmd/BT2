# Q2767: pairing determinism in alt_bn128::decode_g2

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling edge-case inputs such as identity elements and zero scalars, drive `runtime/near-vm-runner/src/logic/alt_bn128.rs::decode_g2` to obtain results that could differ across builds or architectures, breaking the invariant that cryptographic host results are identical on every node, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/near-vm-runner/src/logic/alt_bn128.rs` -> `decode_g2`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: edge-case inputs such as identity elements and zero scalars
- Exploit idea: obtain results that could differ across builds or architectures
- Invariant to test: cryptographic host results are identical on every node
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
