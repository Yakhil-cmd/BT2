# Q1649: VerifyKZGProof - y at the modulus boundary via Go [r-1-largest-canonical-scalar]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyKZGProof (used by Geth/Erigon/Prysm)` with r-1 (largest canonical scalar), make c-kzg-4844 break the invariant that *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/go ckzg4844.VerifyKZGProof (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: r-1 (largest canonical scalar). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: probe y exactly at r and r-1 to find an off-by-one in the canonical check (r-1 (largest canonical scalar)).
- Invariant to test: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: *ok true iff p(z)==y with y the canonical value; boundary values must be handled per spec (input: r-1 (largest canonical scalar)).
