# Q5201: VerifyCellKZGProofBatch - cell-batch r predictable before proofs via Go [a-128-cell-batch-all-mapped-to-one-colum]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyCellKZGProofBatch (used by Geth/Erigon/Prysm)` with a 128-cell batch all mapped to one column, make c-kzg-4844 break the invariant that r == H(all inputs); proofs cannot be chosen after r is known so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_verify_cell_kzg_proof_batch_challenge)
- Entrypoint: bindings/go ckzg4844.VerifyCellKZGProofBatch (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: a 128-cell batch all mapped to one column. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check compute_verify_cell_kzg_proof_batch_challenge binds commitments, indices, cells and proofs so r cannot be gamed (a 128-cell batch all mapped to one column).
- Invariant to test: r == H(all inputs); proofs cannot be chosen after r is known.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: r == H(all inputs); proofs cannot be chosen after r is known (input: a 128-cell batch all mapped to one column).
