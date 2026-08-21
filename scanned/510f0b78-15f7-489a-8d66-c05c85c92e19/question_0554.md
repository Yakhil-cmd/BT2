# Q554: compression ratio abuse in views::default_is_promise

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling maximally compressible payloads at the wire limits, drive `core/primitives/src/views.rs::default_is_promise` to expand a small payload into a large decompressed buffer, breaking the invariant that decompressed size is bounded before allocation, and leading to RPC node crash or unavailability?

## Target
- File/function: `core/primitives/src/views.rs` -> `default_is_promise`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: maximally compressible payloads at the wire limits
- Exploit idea: expand a small payload into a large decompressed buffer
- Invariant to test: decompressed size is bounded before allocation
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
