# Q2155: computeBlobKzgProof - non-canonical commitment argument via Zig [an-on-curve-point-outside-the-order-r-g1]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.computeBlobKzgProof via root.zig` with an on-curve point outside the order-r G1 subgroup, make c-kzg-4844 break the invariant that the commitment used == the canonical validated point, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_blob_kzg_proof (helper: bytes_to_kzg_commitment)
- Entrypoint: bindings/zig Settings.computeBlobKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: an on-curve point outside the order-r G1 subgroup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a non-canonical/inf commitment and confirm bytes_to_kzg_commitment gates it before compute_challenge (an on-curve point outside the order-r G1 subgroup).
- Invariant to test: the commitment used == the canonical validated point, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: the commitment used == the canonical validated point, else C_KZG_BADARGS (input: an on-curve point outside the order-r G1 subgroup).
