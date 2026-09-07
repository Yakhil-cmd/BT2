# Q2412: VerifyKZGProof - accept an infinity commitment via Go [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyKZGProof (used by Geth/Erigon/Prysm)` with the G1 generator point, make c-kzg-4844 break the invariant that *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: validate_kzg_g1)
- Entrypoint: bindings/go ckzg4844.VerifyKZGProof (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass the point at infinity as the commitment (validate_kzg_g1 accepts it before the subgroup check) with a matching chosen y and proof (the G1 generator point).
- Invariant to test: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: *ok == true only if e(C-[y]G1,G2)==e(pi,[s-z]G2) truly holds for the decoded C (input: the G1 generator point).
