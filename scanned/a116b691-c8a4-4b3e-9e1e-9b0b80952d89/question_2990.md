# Q2990: compute_kzg_proof - proof with a non-canonical z via C [an-all-0xff-32-byte-string-2-255-non-can]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with an all-0xFF 32-byte string (>= 2^255, non-canonical), make c-kzg-4844 break the invariant that z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS so that honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement?

## Target
- File/function: src/eip4844/eip4844.c :: compute_kzg_proof (helper: bytes_to_bls_field)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: an all-0xFF 32-byte string (>= 2^255, non-canonical). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: pass a z above the modulus and confirm bytes_to_bls_field rejects it before compute_kzg_proof_impl (an all-0xFF 32-byte string (>= 2^255, non-canonical)).
- Invariant to test: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS.
- Expected Immunefi impact: High - honest nodes compute different commitment/proof/cell bytes for one blob, breaking data-availability-sampling agreement.
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: z used in the proof == the canonical decode of z_bytes, else C_KZG_BADARGS (input: an all-0xFF 32-byte string (>= 2^255, non-canonical)).
