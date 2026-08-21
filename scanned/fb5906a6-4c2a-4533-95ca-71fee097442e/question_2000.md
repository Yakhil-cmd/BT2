# Q2000: parameter version resolution in parameter_table::canonicalize_yaml_string

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling transactions timed across a protocol version boundary, drive `core/parameters/src/parameter_table.rs::canonicalize_yaml_string` to have two nodes charge different parameters for the same chunk, breaking the invariant that cost parameters are a pure function of the protocol version, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/parameters/src/parameter_table.rs` -> `canonicalize_yaml_string`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: transactions timed across a protocol version boundary
- Exploit idea: have two nodes charge different parameters for the same chunk
- Invariant to test: cost parameters are a pure function of the protocol version
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
