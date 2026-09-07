# Q589: computeKzgProof - proof with a non-canonical z via Zig [the-value-equal-to-the-bls-modulus-r-0x7]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.computeKzgProof via root.zig` with the value equal to the BLS modulus r (0x7300, make c-kzg-4844 break the invariant that z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/zig Settings.computeKzgProof via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a z above the modulus and confirm bytes_to_bls_field rejects it before compute_kzg_proof_impl (the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
- Invariant to test: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS (input: the value equal to the BLS modulus r (0x7300...0001) encoded big-endian).
