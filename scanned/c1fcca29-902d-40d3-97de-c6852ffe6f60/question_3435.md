# Q3435: VerifyBlobKZGProofBatch - infinity proof inside a batch via Go [a-compressed-point-with-the-sign-y-bit-f]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyBlobKZGProofBatch (used by Geth/Erigon/Prysm)` with a compressed point with the sign/y-bit flipped, make c-kzg-4844 break the invariant that batch true iff every proof genuinely opens its claim so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: g1_lincomb_naive)
- Entrypoint: bindings/go ckzg4844.VerifyBlobKZGProofBatch (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: a compressed point with the sign/y-bit flipped. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: include a triple whose proof is infinity; g1_lincomb_naive still weights it (a compressed point with the sign/y-bit flipped).
- Invariant to test: batch true iff every proof genuinely opens its claim.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: batch true iff every proof genuinely opens its claim (input: a compressed point with the sign/y-bit flipped).
