# Q1944: verifyCellKzgProofBatch - infinity cell proof filtered from the lincomb via Nim [an-on-curve-point-outside-the-order-r-g1]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus)` with an on-curve point outside the order-r G1 subgroup, make c-kzg-4844 break the invariant that *ok true iff every proof opens its cell; a filtered infinity proof cannot pass so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: g1_lincomb_fast)
- Entrypoint: bindings/nim kzg.verifyCellKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: an on-curve point outside the order-r G1 subgroup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a proof that is the point at infinity so g1_lincomb_fast drops it while its r^i weight still scales the commitment side (an on-curve point outside the order-r G1 subgroup).
- Invariant to test: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass (input: an on-curve point outside the order-r G1 subgroup).
