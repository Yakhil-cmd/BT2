# Q2628: verifyBlobKzgProofBatch - infinity commitment inside a batch via Zig [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyBlobKzgProofBatch via root.zig` with the G1 generator point, make c-kzg-4844 break the invariant that batch true iff every triple's pairing holds, infinity commitment included so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: verify_kzg_proof_batch)
- Entrypoint: bindings/zig Settings.verifyBlobKzgProofBatch via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a triple whose commitment is the point at infinity and see if aggregation accepts it (the G1 generator point).
- Invariant to test: batch true iff every triple's pairing holds, infinity commitment included.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: batch true iff every triple's pairing holds, infinity commitment included (input: the G1 generator point).
