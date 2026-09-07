# Q5707: verifyKzgProof - verify agrees with compute via NodeJs [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/node.js kzg.verifyKzgProof via kzg.cxx (used by Lodestar)` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that verify_kzg_proof(compute_kzg_proof(blob,z)) == true for every blob and z so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: verify_kzg_proof_impl)
- Entrypoint: bindings/node.js kzg.verifyKzgProof via kzg.cxx (used by Lodestar); get_cell_index() coerces a JS double to uint64 and returns 0 (still continuing) when the value is not a number
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: confirm verify_kzg_proof accepts exactly the (proof,y) that compute_kzg_proof produced for the same z (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: verify_kzg_proof(compute_kzg_proof(blob,z)) == true for every blob and z.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a jest case in bindings/node.js/test/kzg.test.ts asserting the invariant holds: verify_kzg_proof(compute_kzg_proof(blob,z)) == true for every blob and z (input: 2^256 - r (wraps to a small residue if reduced without the check)).
