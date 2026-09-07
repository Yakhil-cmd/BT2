# Q5621: verifyCellKzgProofBatch - openArray[0].getPtr on an empty batch via Nim [a-128-cell-batch-all-mapped-to-one-colum]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with a 128-cell batch all mapped to one column, make c-kzg-4844 break the invariant that an empty batch returns true without dereferencing element 0 so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: verifyCellKzgProofBatch)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: a 128-cell batch all mapped to one column. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass empty openArrays; the wrapper returns ok(true) before indexing [0], confirm no [0] deref of an empty seq (a 128-cell batch all mapped to one column).
- Invariant to test: an empty batch returns true without dereferencing element 0.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: an empty batch returns true without dereferencing element 0 (input: a 128-cell batch all mapped to one column).
