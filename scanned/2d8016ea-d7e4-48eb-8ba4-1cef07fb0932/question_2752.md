# Q2752: VerifyCellKZGProofBatch - deduplicate_commitments compares bytes not points via Go [the-g1-generator-point]

## Question
Can an unprivileged attacker, calling `bindings/go ckzg4844.VerifyCellKZGProofBatch (used by Geth/Erigon/Prysm)` with the G1 generator point, make c-kzg-4844 break the invariant that commitments dedupe iff they are the same group element, matching the reference so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: deduplicate_commitments)
- Entrypoint: bindings/go ckzg4844.VerifyCellKZGProofBatch (used by Geth/Erigon/Prysm); the wrapper reslices with unsafe.Pointer and casts len() to C.uint64_t with no per-element bound
- Attacker controls: attacker-published bytes: the G1 generator point. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply two commitment encodings a client thinks are equal/unequal and see if deduplicate_commitments splits or merges them wrongly (the G1 generator point).
- Invariant to test: commitments dedupe iff they are the same group element, matching the reference.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a table test in bindings/go/main_test.go asserting the invariant holds: commitments dedupe iff they are the same group element, matching the reference (input: the G1 generator point).
