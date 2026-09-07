# Q1948: verify_cell_kzg_proof_batch - deduplicate_commitments compares bytes not points via Rust [an-on-curve-point-outside-the-order-r-g1]

## Question
Can an unprivileged attacker, calling `bindings/rust KZGSettings::verify_cell_kzg_proof_batch (used by Reth/Lighthouse-adjacent crates)` with an on-curve point outside the order-r G1 subgroup, make c-kzg-4844 break the invariant that commitments dedupe iff they are the same group element, matching the reference so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip7594/eip7594.c :: verify_cell_kzg_proof_batch (helper: deduplicate_commitments)
- Entrypoint: bindings/rust KZGSettings::verify_cell_kzg_proof_batch (used by Reth/Lighthouse-adjacent crates); the wrapper checks slice lengths, casts len() as u64, and reads a MaybeUninit<bool> only on C_KZG_OK
- Attacker controls: attacker-published bytes: an on-curve point outside the order-r G1 subgroup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply two commitment encodings a client thinks are equal/unequal and see if deduplicate_commitments splits or merges them wrongly (an on-curve point outside the order-r G1 subgroup).
- Invariant to test: commitments dedupe iff they are the same group element, matching the reference.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: the differential fuzzer fuzz/fuzz_targets/fuzz_verify_cell_kzg_proof_batch.rs (`cargo fuzz`, vs Rust-Eth-KZG/Constantine) or a #[test] in bindings/rust asserting the invariant holds: commitments dedupe iff they are the same group element, matching the reference (input: an on-curve point outside the order-r G1 subgroup).
