# Q3237: VerifyKzgProof - non-canonical y accepted via CSharp [a-value-in-r-2-256-that-blst-scalar-fr-c]

## Question
Can an unprivileged attacker, calling `bindings/csharp Ckzg.VerifyKzgProof via ckzg_wrap.c (used by Nethermind)` with a value in [r, 2^256) that blst_scalar_fr_check must reject, make c-kzg-4844 break the invariant that y used == canonical decode of y_bytes, else C_KZG_BADARGS and *ok stays false so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/csharp Ckzg.VerifyKzgProof via ckzg_wrap.c (used by Nethermind); the wrapper casts an int `numCells` to UInt64 and maps C_KZG_BADARGS to an ArgumentException
- Attacker controls: attacker-published bytes: a value in [r, 2^256) that blst_scalar_fr_check must reject. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply a y above the modulus and confirm bytes_to_bls_field rejects before pairing (a value in [r, 2^256) that blst_scalar_fr_check must reject).
- Invariant to test: y used == canonical decode of y_bytes, else C_KZG_BADARGS and *ok stays false.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: an xUnit case in bindings/csharp Ckzg.Test/ReferenceTests.cs asserting the invariant holds: y used == canonical decode of y_bytes, else C_KZG_BADARGS and *ok stays false (input: a value in [r, 2^256) that blst_scalar_fr_check must reject).
