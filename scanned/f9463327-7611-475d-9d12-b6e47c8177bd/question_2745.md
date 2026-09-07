# Q2745: verifyCellKzgProofBatch - infinity cell proof filtered from the lincomb via NodeJs [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar)` with the G1 generator point, make c-kzg-4844 break the invariant that *ok true iff every proof opens its cell; a filtered infinity proof cannot pass so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: g1_lincomb_fast)
- Entrypoint: bindings/node.js kzg.verifyCellKzgProofBatch via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a proof that is the point at infinity so g1_lincomb_fast drops it while its r^i weight still scales the commitment side (the G1 generator point).
- Invariant to test: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: *ok true iff every proof opens its cell; a filtered infinity proof cannot pass (input: the G1 generator point).
