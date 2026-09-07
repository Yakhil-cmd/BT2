# Q1754: verifyBlobKzgProof - evaluation shortcut soundness via Nim [r-1-largest-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProof (used by Nimbus)` with r-1 (largest canonical scalar), make c-kzg-4844 break the invariant that shortcut result == the barycentric result for the same challenge so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: evaluate_polynomial_in_evaluation_form)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: r-1 (largest canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: target the fr_equal shortcut branch during verification (r-1 (largest canonical scalar)).
- Invariant to test: shortcut result == the barycentric result for the same challenge.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: shortcut result == the barycentric result for the same challenge (input: r-1 (largest canonical scalar)).
