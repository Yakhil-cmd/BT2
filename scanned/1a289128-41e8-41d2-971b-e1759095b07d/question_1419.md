# Q1419: computeKzgProof - proof determinism across precompute/build via NodeJs [a-blob-whose-4096-field-elements-are-all]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.computeKzgProof via kzg.cxx (used by Lodestar)` with a blob whose 4096 field elements are all zero, make c-kzg-4844 break the invariant that proof bytes == the reference proof for the same (blob, z) on every build so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: compute_kzg_proof_impl)
- Entrypoint: bindings/node.js kzg.computeKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: a blob whose 4096 field elements are all zero. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: compute the proof under precompute 0 and 8 and confirm identical bytes (a blob whose 4096 field elements are all zero).
- Invariant to test: proof bytes == the reference proof for the same (blob, z) on every build.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: proof bytes == the reference proof for the same (blob, z) on every build (input: a blob whose 4096 field elements are all zero).
