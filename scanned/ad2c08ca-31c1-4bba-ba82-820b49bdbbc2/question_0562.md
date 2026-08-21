# Q562: canonical encoding in views::is_false

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling two encodings of one logical value, drive `core/primitives/src/views.rs::is_false` to have one value produce two different hashes or accepted forms, breaking the invariant that every logical value has exactly one accepted encoding, and leading to unintended permanent chain split requiring a hard fork?

## Target
- File/function: `core/primitives/src/views.rs` -> `is_false`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: two encodings of one logical value
- Exploit idea: have one value produce two different hashes or accepted forms
- Invariant to test: every logical value has exactly one accepted encoding
- Expected Immunefi impact: Critical - unintended permanent chain split requiring a hard fork
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
