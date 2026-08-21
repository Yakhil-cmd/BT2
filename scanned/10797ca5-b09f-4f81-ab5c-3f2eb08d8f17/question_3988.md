# Q3988: apply nondeterminism in lib::own_congestion_info

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling inputs whose handling depends on iteration order or floating state, drive `runtime/runtime/src/lib.rs::own_congestion_info` to produce different state roots for the same chunk on two honest nodes, breaking the invariant that chunk application is deterministic given the chunk and the pre-state, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `runtime/runtime/src/lib.rs` -> `own_congestion_info`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: inputs whose handling depends on iteration order or floating state
- Exploit idea: produce different state roots for the same chunk on two honest nodes
- Invariant to test: chunk application is deterministic given the chunk and the pre-state
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
