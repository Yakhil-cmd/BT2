# Q3418: verifyBlobKzgProofBatch - predictable r via duplicate entries via NodeJs [an-empty-batch-n-0]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyBlobKzgProofBatch via kzg.cxx (used by Lodestar)` with an empty batch (n == 0), make c-kzg-4844 break the invariant that the challenge r binds every entry uniquely; duplicates do not create a cancelling weight so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/node.js kzg.verifyBlobKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: an empty batch (n == 0). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: submit byte-identical entries so their r-powers coincide and probe for a cancellation the transcript cannot bind (an empty batch (n == 0)).
- Invariant to test: the challenge r binds every entry uniquely; duplicates do not create a cancelling weight.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: the challenge r binds every entry uniquely; duplicates do not create a cancelling weight (input: an empty batch (n == 0)).
