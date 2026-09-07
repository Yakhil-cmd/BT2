# Q2638: verifyBlobKzgProofBatch - infinity proof inside a batch via Zig [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyBlobKzgProofBatch via root.zig` with the G1 generator point, make c-kzg-4844 break the invariant that batch true iff every proof genuinely opens its claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: g1_lincomb_naive)
- Entrypoint: bindings/zig Settings.verifyBlobKzgProofBatch via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a triple whose proof is infinity; g1_lincomb_naive still weights it (the G1 generator point).
- Invariant to test: batch true iff every proof genuinely opens its claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: batch true iff every proof genuinely opens its claim (input: the G1 generator point).
