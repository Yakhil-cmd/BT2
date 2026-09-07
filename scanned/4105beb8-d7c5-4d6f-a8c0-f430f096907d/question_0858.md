# Q858: VerifyKzgProof - z at the modulus boundary via CSharp [r-1-smallest-non-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/csharp Ckzg.VerifyKzgProof via ckzg_wrap.c (used by Nethermind)` with r+1 (smallest non-canonical scalar), make c-kzg-4844 break the invariant that z accepted iff canonical; verdict matches the reference at the boundary so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/csharp Ckzg.VerifyKzgProof via ckzg_wrap.c (used by Nethermind); the wrapper casts an int `numCells` to UInt64 and maps C_KZG_BADARGS to an ArgumentException
- Attacker controls: attacker-published bytes: r+1 (smallest non-canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe z exactly at r and r-1 for a canonical-check off-by-one (r+1 (smallest non-canonical scalar)).
- Invariant to test: z accepted iff canonical; verdict matches the reference at the boundary.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: an xUnit case in bindings/csharp Ckzg.Test/ReferenceTests.cs asserting the invariant holds: z accepted iff canonical; verdict matches the reference at the boundary (input: r+1 (smallest non-canonical scalar)).
