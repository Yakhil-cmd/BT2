# Q1075: length-prefix confusion in bls12381::read_fp2_point

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling element counts that disagree with the supplied buffer length, drive `runtime/near-vm-runner/src/logic/bls12381.rs::read_fp2_point` to read past the supplied buffer during element parsing, breaking the invariant that declared element counts are validated against the real buffer length, and leading to network unable to confirm new transactions (shard/chain halt)?

## Target
- File/function: `runtime/near-vm-runner/src/logic/bls12381.rs` -> `read_fp2_point`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: element counts that disagree with the supplied buffer length
- Exploit idea: read past the supplied buffer during element parsing
- Invariant to test: declared element counts are validated against the real buffer length
- Expected Immunefi impact: Critical - network unable to confirm new transactions (shard/chain halt)
- Fast validation: extend the existing wasm fuzz target and assert no panic and identical gas across two runs
