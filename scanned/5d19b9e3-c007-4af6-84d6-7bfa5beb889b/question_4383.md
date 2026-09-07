# Q4383: verifyCellKzgProofBatch - commitment-index map collision via Nim [an-ascending-list-with-one-column-index]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with an ascending list with one column index repeated later, make c-kzg-4844 break the invariant that cell i is checked against commitment i's polynomial, never a remapped one so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: deduplicate_commitments)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: an ascending list with one column index repeated later. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: exploit commitment_indices from deduplicate_commitments so a cell is weighted against the wrong commitment (an ascending list with one column index repeated later).
- Invariant to test: cell i is checked against commitment i's polynomial, never a remapped one.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: cell i is checked against commitment i's polynomial, never a remapped one (input: an ascending list with one column index repeated later).
