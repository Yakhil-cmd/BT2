# Q5980: verifyCellKzgProofBatch - non-canonical cell field element via Zig [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyCellKzgProofBatch via root.zig` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that the field element aggregated == canonical decode of the cell bytes, else BADARGS before *ok can be true so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: compute_commitment_to_aggregated_interpolation_poly)
- Entrypoint: bindings/zig Settings.verifyCellKzgProofBatch via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: put a non-canonical element in a cell; note the challenge hashes raw bytes before bytes_to_bls_field validates them (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: the field element aggregated == canonical decode of the cell bytes, else BADARGS before *ok can be true.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: the field element aggregated == canonical decode of the cell bytes, else BADARGS before *ok can be true (input: 2^256 - r (wraps to a small residue if reduced without the check)).
