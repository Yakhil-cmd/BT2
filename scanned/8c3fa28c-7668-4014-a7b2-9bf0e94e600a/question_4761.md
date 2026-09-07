# Q4761: computeCells - cells differ across precompute via NodeJs [recovery-from-127-cells-a-single-missing]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeCells via kzg.cxx (used by Lodestar)` with recovery from 127 cells (a single missing column), make c-kzg-4844 break the invariant that cell bytes == the reference cells for the same blob regardless of precompute/build so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip7594/eip7594.c :: compute_cells_and_kzg_proofs (helper: poly_lagrange_to_monomial)
- Entrypoint: bindings/node.js kzg.computeCells via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: recovery from 127 cells (a single missing column). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: compute cells with precompute 0 and 8 and require identical bytes (recovery from 127 cells (a single missing column)).
- Invariant to test: cell bytes == the reference cells for the same blob regardless of precompute/build.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: cell bytes == the reference cells for the same blob regardless of precompute/build (input: recovery from 127 cells (a single missing column)).
