# Q414: versioned enum confusion in receipt::receiver_id

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling version discriminants for actions, receipts and accounts, drive `core/primitives/src/receipt.rs::receiver_id` to have one payload decode as different variants on different nodes, breaking the invariant that a payload decodes to exactly one variant on every node, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/receipt.rs` -> `receiver_id`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: version discriminants for actions, receipts and accounts
- Exploit idea: have one payload decode as different variants on different nodes
- Invariant to test: a payload decodes to exactly one variant on every node
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: run the same chunk through both execution paths and assert identical state root, gas burnt and outcome ids
