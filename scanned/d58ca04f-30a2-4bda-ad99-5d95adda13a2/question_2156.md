# Q2156: borsh round-trip in receipt::already_delivered_shards

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling borsh encodings with trailing bytes, alternate field orders or duplicated fields, drive `core/primitives/src/receipt.rs::already_delivered_shards` to have two distinct encodings hash to one accepted transaction, breaking the invariant that every transaction has exactly one canonical serialization and hash, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/primitives/src/receipt.rs` -> `already_delivered_shards`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: borsh encodings with trailing bytes, alternate field orders or duplicated fields
- Exploit idea: have two distinct encodings hash to one accepted transaction
- Invariant to test: every transaction has exactly one canonical serialization and hash
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
