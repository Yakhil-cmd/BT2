# Q5866: VerifyBlobKzgProofBatch - affine-compress vs bytes_from_g1 in the transcript via CSharp [two-distinct-byte-strings-a-client-belie]

## Question
Can an unprivileged attacker, calling `bindings/csharp Ckzg.VerifyBlobKzgProofBatch via ckzg_wrap.c (used by Nethermind)` with two distinct byte strings a client believes encode the same commitment, make c-kzg-4844 break the invariant that transcript point bytes == the canonical commitment/proof encoding used elsewhere so that this library's verdict or output bytes diverge from the reference?

## Target
- File/function: src/eip4844/eip4844.c :: verify_blob_kzg_proof_batch (helper: compute_r_powers_for_verify_kzg_proof_batch)
- Entrypoint: bindings/csharp Ckzg.VerifyBlobKzgProofBatch via ckzg_wrap.c (used by Nethermind); the wrapper casts an int `numCells` to UInt64 and maps C_KZG_BADARGS to an ArgumentException
- Attacker controls: attacker-published bytes: two distinct byte strings a client believes encode the same commitment. Delivered as a blob transaction / blob sidecar / data-column sidecar and forwarded unchanged by honest nodes.
- Exploit idea: check blst_p1_affine_compress used for the transcript equals bytes_from_g1 for every point incl. infinity (two distinct byte strings a client believes encode the same commitment).
- Invariant to test: transcript point bytes == the canonical commitment/proof encoding used elsewhere.
- Expected Immunefi impact: High - this library's verdict or output bytes diverge from the reference (Constantine / Rust-Eth-KZG), forking nodes that run different clients (>1/3 split territory).
- Fast validation: an xUnit case in bindings/csharp Ckzg.Test/ReferenceTests.cs asserting the invariant holds: transcript point bytes == the canonical commitment/proof encoding used elsewhere (input: two distinct byte strings a client believes encode the same commitment).
