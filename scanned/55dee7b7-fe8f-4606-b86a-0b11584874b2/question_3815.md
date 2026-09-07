# Q3815: ComputeKZGProof - fr_batch_inv on a zero denominator via Go [a-value-in-r-2-256-that-blst-scalar-fr-c]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.ComputeKZGProof (used by Geth/Erigon/Prysm)` with a value in [r, 2^256) that blst_scalar_fr_check must reject, make c-kzg-4844 break the invariant that no proof is returned when any inversion input is zero; out is never used after a BADARGS so that one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: fr_batch_inv)
- Entrypoint: bindings/go ckzg4844.ComputeKZGProof (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: a value in [r, 2^256) that blst_scalar_fr_check must reject. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: craft inputs so a denominator (w_i - z) is zero and check fr_batch_inv returns C_KZG_BADARGS without emitting a bogus proof (a value in [r, 2^256) that blst_scalar_fr_check must reject).
- Invariant to test: no proof is returned when any inversion input is zero; out is never used after a BADARGS.
- Expected Immunefi impact: High - one attacker-published blob/sidecar aborts or corrupts memory in every node linking c-kzg (reachable assert / OOB / UB), a network-wide liveness fault.
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: no proof is returned when any inversion input is zero; out is never used after a BADARGS (input: a value in [r, 2^256) that blst_scalar_fr_check must reject).
