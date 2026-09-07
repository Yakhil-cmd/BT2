# Q1044: verify_blob_kzg_proof_batch - affine-compress vs bytes_from_g1 in the transcript via C [a-48-byte-string-with-the-infinity-flag]

## Question
Can an unprivileged attacker, calling `Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code` with a 48-byte string with the infinity flag set but a nonzero x coordinate, make c-kzg-4844 break the invariant that transcript point bytes == the canonical commitment/proof encoding used elsewhere so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: Linked C ABI (src/ckzg.c) called by a client's blob-pool / DAS code; the client passes the raw pointer and a trusted `n`/`num_cells` straight to C with no length re-check
- Attacker controls: attacker-published bytes: a 48-byte string with the infinity flag set but a nonzero x coordinate. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check blst_p1_affine_compress used for the transcript equals bytes_from_g1 for every point incl. infinity (a 48-byte string with the infinity flag set but a nonzero x coordinate).
- Invariant to test: transcript point bytes == the canonical commitment/proof encoding used elsewhere.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a tinytest case in src/test/tests.c (`make -C src test`) that load_trusted_setup_file()s trusted_setup.txt and asserts the invariant holds: transcript point bytes == the canonical commitment/proof encoding used elsewhere (input: a 48-byte string with the infinity flag set but a nonzero x coordinate).
