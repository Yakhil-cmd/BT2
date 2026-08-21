# Q395: compression bomb in receipt::input_data_ids

## Question
Can an unprivileged attacker who signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC, controlling highly compressible payloads at the size limits, drive `core/primitives/src/receipt.rs::input_data_ids` to expand a small payload into a large in-memory structure, breaking the invariant that decompression output is bounded before allocation, and leading to RPC node crash or unavailability?

## Target
- File/function: `core/primitives/src/receipt.rs` -> `input_data_ids`
- Entrypoint: unprivileged attacker signs and submits a `SignedTransaction` through the public `broadcast_tx_commit` RPC
- Attacker controls: highly compressible payloads at the size limits
- Exploit idea: expand a small payload into a large in-memory structure
- Invariant to test: decompression output is bounded before allocation
- Expected Immunefi impact: High - RPC node crash or unavailability
- Fast validation: drive the endpoint from `integration-tests` with the crafted payload and assert a typed error, not a panic or unbounded allocation
