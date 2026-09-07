# Q1639: VerifyKZGProof - non-canonical z accepted via Go [r-1-largest-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyKZGProof (used by Geth/Erigon/Prysm)` with r-1 (largest canonical scalar), make c-kzg-4844 break the invariant that z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/go ckzg4844.VerifyKZGProof (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: r-1 (largest canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply a z above the modulus and confirm bytes_to_bls_field rejects before pairing (r-1 (largest canonical scalar)).
- Invariant to test: z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: z used == canonical decode of z_bytes, else C_KZG_BADARGS and *ok stays false (input: r-1 (largest canonical scalar)).
