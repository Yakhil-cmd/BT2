# Q304: io helper overflow in types::from_str

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling sizes near the integer bounds in the shared io helpers, drive `core/primitives-core/src/types.rs::from_str` to overflow a size computation in shared decoding helpers, breaking the invariant that size arithmetic in decoding helpers is checked, and leading to RPC node crash or unavailability?

## Target
- File/function: `core/primitives-core/src/types.rs` -> `from_str`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: sizes near the integer bounds in the shared io helpers
- Exploit idea: overflow a size computation in shared decoding helpers
- Invariant to test: size arithmetic in decoding helpers is checked
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
