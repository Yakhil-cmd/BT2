# Q5860: verifyBlobKzgProofBatch - r derivable before proofs are chosen via Zig [a-batch-mixing-a-valid-entry-with-one-wh]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyBlobKzgProofBatch via root.zig` with a batch mixing a valid entry with one whose proof is the point at infinity, make c-kzg-4844 break the invariant that r == H(all entries); no attacker can fix proofs after learning r so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/zig Settings.verifyBlobKzgProofBatch via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: a batch mixing a valid entry with one whose proof is the point at infinity. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check the transcript in compute_r_powers hashes commitments/z/y/proofs so r cannot be predicted then gamed (a batch mixing a valid entry with one whose proof is the point at infinity).
- Invariant to test: r == H(all entries); no attacker can fix proofs after learning r.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: r == H(all entries); no attacker can fix proofs after learning r (input: a batch mixing a valid entry with one whose proof is the point at infinity).
