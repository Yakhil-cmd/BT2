# Q5769: verifyBlobKzgProof - evaluation shortcut soundness via Nim [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProof (used by Nimbus)` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that shortcut result == the barycentric result for the same challenge so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: evaluate_polynomial_in_evaluation_form)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProof (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: target the fr_equal shortcut branch during verification (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: shortcut result == the barycentric result for the same challenge.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: shortcut result == the barycentric result for the same challenge (input: 2^256 - r (wraps to a small residue if reduced without the check)).
