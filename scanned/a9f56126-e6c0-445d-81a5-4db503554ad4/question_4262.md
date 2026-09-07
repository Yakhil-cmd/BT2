# Q4262: verify_blob_kzg_proof_batch - affine-compress vs bytes_from_g1 in the transcript via Python [an-all-zero-48-byte-string-with-every-fl]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_blob_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients)` with an all-zero 48-byte string with every flag clear, make c-kzg-4844 break the invariant that transcript point bytes == the canonical commitment/proof encoding used elsewhere so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/python ckzg.verify_blob_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: an all-zero 48-byte string with every flag clear. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check blst_p1_affine_compress used for the transcript equals bytes_from_g1 for every point incl. infinity (an all-zero 48-byte string with every flag clear).
- Invariant to test: transcript point bytes == the canonical commitment/proof encoding used elsewhere.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: transcript point bytes == the canonical commitment/proof encoding used elsewhere (input: an all-zero 48-byte string with every flag clear).
