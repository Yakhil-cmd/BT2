# Q2992: ComputeKZGProof - proof with a non-canonical z via Go [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.ComputeKZGProof (used by Geth/Erigon/Prysm)` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/go ckzg4844.ComputeKZGProof (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a z above the modulus and confirm bytes_to_bls_field rejects it before compute_kzg_proof_impl (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
