# Q248: verifyBlobKzgProofBatch - affine-compress vs bytes_from_g1 in the transcript via Nim [the-compressed-point-at-infinity-0xc0-th]

## Question
Can an unprivileged attacker, calling `bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus)` with the compressed point at infinity (0xc0 then 47 zero bytes), make c-kzg-4844 break the invariant that transcript point bytes == the canonical commitment/proof encoding used elsewhere so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/nim kzg.verifyBlobKzgProofBatch (used by Nimbus); the wrapper takes openArray[0].getPtr and passes len.uint64, returning ok(true) on empty batches
- Attacker controls: attacker-published bytes: the compressed point at infinity (0xc0 then 47 zero bytes). Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check blst_p1_affine_compress used for the transcript equals bytes_from_g1 for every point incl. infinity (the compressed point at infinity (0xc0 then 47 zero bytes)).
- Invariant to test: transcript point bytes == the canonical commitment/proof encoding used elsewhere.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/nim/tests/tests.nim asserting the invariant holds: transcript point bytes == the canonical commitment/proof encoding used elsewhere (input: the compressed point at infinity (0xc0 then 47 zero bytes)).
