# Q5065: verify_blob_kzg_proof_batch - affine-compress vs bytes_from_g1 in the transcript via Python [a-point-whose-compression-is-accepted-by]

## Question
Can an unprivileged attacker, calling `bindings/python ckzg.verify_blob_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients)` with a point whose compression is accepted by blst_p1_uncompress but is not in G1, make c-kzg-4844 break the invariant that transcript point bytes == the canonical commitment/proof encoding used elsewhere so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/python ckzg.verify_blob_kzg_proof_batch via ckzg_wrap.c (spec / tooling clients); counts are derived from PyBytes_Size/list length and each cell index goes through PyLong_AsUnsignedLongLong
- Attacker controls: attacker-published bytes: a point whose compression is accepted by blst_p1_uncompress but is not in G1. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check blst_p1_affine_compress used for the transcript equals bytes_from_g1 for every point incl. infinity (a point whose compression is accepted by blst_p1_uncompress but is not in G1).
- Invariant to test: transcript point bytes == the canonical commitment/proof encoding used elsewhere.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a case in bindings/python/tests.py asserting the invariant holds: transcript point bytes == the canonical commitment/proof encoding used elsewhere (input: a point whose compression is accepted by blst_p1_uncompress but is not in G1).
