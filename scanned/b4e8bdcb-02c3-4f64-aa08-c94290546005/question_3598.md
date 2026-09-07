# Q3598: verifyCellKzgProofBatch - cell-batch r predictable before proofs via NodeJs [an-empty-batch-n-0]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar)` with an empty batch (n == 0), make c-kzg-4844 break the invariant that r == H(all inputs); proofs cannot be chosen after r is known so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_verify_cell_kzg_proof_batch_challenge)
- Entrypoint: bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: an empty batch (n == 0). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check compute_verify_cell_kzg_proof_batch_challenge binds commitments, indices, cells and proofs so r cannot be gamed (an empty batch (n == 0)).
- Invariant to test: r == H(all inputs); proofs cannot be chosen after r is known.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: r == H(all inputs); proofs cannot be chosen after r is known (input: an empty batch (n == 0)).
