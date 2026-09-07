# Q5939: verifyCellKzgProofBatch - column-aggregation interpolation collision via Nim [a-non-ascending-pair-that-violates-the-s]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with a non-ascending pair that violates the strict-order check, make c-kzg-4844 break the invariant that aggregated interpolation commitment == the true column polynomial iff each cell is genuine so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_commitment_to_aggregated_interpolation_poly)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a non-ascending pair that violates the strict-order check. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: aggregate crafted cells in one column so the interpolation poly matches the commitment without any single cell being valid (a non-ascending pair that violates the strict-order check).
- Invariant to test: aggregated interpolation commitment == the true column polynomial iff each cell is genuine.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: aggregated interpolation commitment == the true column polynomial iff each cell is genuine (input: a non-ascending pair that violates the strict-order check).
