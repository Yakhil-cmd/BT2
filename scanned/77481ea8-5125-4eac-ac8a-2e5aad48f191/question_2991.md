# Q2991: compute_kzg_proof - proof with a non-canonical z via Rust [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `bindings/rust KZGSettings::compute_kzg_proof (used by Reth/Lighthouse-adjacent crates)` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/rust KZGSettings::compute_kzg_proof (used by Reth/Lighthouse-adjacent crates); the wrapper checks slice lengths, casts len() as u64, and reads a MaybeUninit<bool> only on C_KZG_OK
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a z above the modulus and confirm bytes_to_bls_field rejects it before compute_kzg_proof_impl (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: the differential fuzzer fuzz/fuzz_targets/fuzz_compute_kzg_proof.rs (`cargo fuzz`, vs Rust-Eth-KZG/Constantine) or a #[test] in bindings/rust asserting the invariant holds: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
