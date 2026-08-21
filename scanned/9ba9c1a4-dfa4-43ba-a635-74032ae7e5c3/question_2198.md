# Q2198: compression bomb in signable_message::new_off_chain

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling highly compressible payloads at the size limits, drive `core/primitives/src/signable_message.rs::new_off_chain` to expand a small payload into a large in-memory structure, breaking the invariant that decompression output is bounded before allocation, and leading to RPC node crash or unavailability?

## Target
- File/function: `core/primitives/src/signable_message.rs` -> `new_off_chain`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: highly compressible payloads at the size limits
- Exploit idea: expand a small payload into a large in-memory structure
- Invariant to test: decompression output is bounded before allocation
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
