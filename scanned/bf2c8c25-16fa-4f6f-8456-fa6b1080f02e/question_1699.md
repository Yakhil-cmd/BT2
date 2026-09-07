# Q1699: VerifyBlobKZGProof - infinity commitment for a blob via Go [an-on-curve-point-outside-the-order-r-g1]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyBlobKZGProof (used by Geth/Erigon/Prysm)` with an on-curve point outside the order-r G1 subgroup, make c-kzg-4844 break the invariant that *ok true iff the infinity commitment truly commits to the blob polynomial so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: bindings/go ckzg4844.VerifyBlobKZGProof (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: an on-curve point outside the order-r G1 subgroup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment for a chosen blob and see whether the derived (challenge,y) still verifies (an on-curve point outside the order-r G1 subgroup).
- Invariant to test: *ok true iff the infinity commitment truly commits to the blob polynomial.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: *ok true iff the infinity commitment truly commits to the blob polynomial (input: an on-curve point outside the order-r G1 subgroup).
