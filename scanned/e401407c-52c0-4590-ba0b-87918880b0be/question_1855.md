# Q1855: verifyBlobKzgProofBatch - affine-compress vs bytes_from_g1 in the transcript via Zig [an-on-curve-point-outside-the-order-r-g1]

## Question
Can an unprivileged attacker, calling `bindings/zig Settings.verifyBlobKzgProofBatch via root.zig` with an on-curve point outside the order-r G1 subgroup, make c-kzg-4844 break the invariant that transcript point bytes == the canonical commitment/proof encoding used elsewhere so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/zig Settings.verifyBlobKzgProofBatch via root.zig; the wrapper returns error.LengthMismatch on unequal lengths and passes slice.len as the count
- Attacker controls: attacker-published bytes: an on-curve point outside the order-r G1 subgroup. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check blst_p1_affine_compress used for the transcript equals bytes_from_g1 for every point incl. infinity (an on-curve point outside the order-r G1 subgroup).
- Invariant to test: transcript point bytes == the canonical commitment/proof encoding used elsewhere.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: a test in bindings/zig/src/tests.zig asserting the invariant holds: transcript point bytes == the canonical commitment/proof encoding used elsewhere (input: an on-curve point outside the order-r G1 subgroup).
