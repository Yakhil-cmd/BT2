# Q5643: verify_kzg_proof - non-canonical y accepted via Rust [2-256-r-wraps-to-a-small-residue-if-redu]

## Question
Can an unprivileged attacker, calling `bindings/rust KZGSettings::verify_kzg_proof (used by Reth/Lighthouse-adjacent crates)` with 2^256 - r (wraps to a small residue if reduced without the check), make c-kzg-4844 break the invariant that y used == canonical decode of y_bytes, else C_KZG_BADARGS and *ok stays false so that a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split?

## Target
- File/function: src/eip4844/eip4844.c :: verify_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: bindings/rust KZGSettings::verify_kzg_proof (used by Reth/Lighthouse-adjacent crates); the wrapper checks slice lengths, casts len() as u64, and reads a MaybeUninit<bool> only on C_KZG_OK
- Attacker controls: attacker-published bytes: 2^256 - r (wraps to a small residue if reduced without the check). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: supply a y above the modulus and confirm bytes_to_bls_field rejects before pairing (2^256 - r (wraps to a small residue if reduced without the check)).
- Invariant to test: y used == canonical decode of y_bytes, else C_KZG_BADARGS and *ok stays false.
- Expected Immunefi impact: Critical - a forged proof/commitment/cell verifies as valid, so unavailable or wrong blob data is accepted and finalized; consensus can be split (EF bug bounty, c-kzg-4844 in-scope crucial dependency).
- Fast validation: the differential fuzzer fuzz/fuzz_targets/fuzz_verify_kzg_proof.rs (`cargo fuzz`, vs Rust-Eth-KZG/Constantine) or a #[test] in bindings/rust asserting the invariant holds: y used == canonical decode of y_bytes, else C_KZG_BADARGS and *ok stays false (input: 2^256 - r (wraps to a small residue if reduced without the check)).
