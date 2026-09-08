Based on my investigation, I was unable to find the actual body of `verify_blob_kzg_proof_batch` in `src/eip4844/eip4844.c` (my last read returned only the file header/includes, not the function implementation), so I cannot verify or refute the specific algebraic claim about the `n==1` short-circuit diverging from `verify_blob_kzg_proof` on a byte-identical duplicate-entry batch.

What I *can* confirm from the code I did read:

- The Elixir NIF `verify_blob_kzg_proof_batch_nif` in `bindings/elixir/native/src/ckzg_wrap.c` computes `blobs_len`, `commitments_len`, `proofs_len` purely from binary sizes divided by fixed struct sizes, checks they're equal, and passes `blobs_len` straight through to `verify_blob_kzg_proof_batch` as `n` with no special-casing of `n==1` or deduplication logic in the binding itself. [1](#0-0) 

- All batch item type/size checks are enforced (blob, commitment, proof lengths), so malformed lengths are rejected before reaching `verify_blob_kzg_proof_batch`; there is no protection against duplicate *valid-length* entries at the binding layer. [2](#0-1) 

I was not able to retrieve the actual `n == 1` short-circuit code, the Fiat-Shamir/`r_powers` aggregation logic, or the `deduplicate_commitments` helper referenced in the question, because my tool budget was exhausted before I could read the relevant section of `src/eip4844/eip4844.c` (past line 50) where `verify_blob_kzg_proof_batch` is actually defined. Without seeing:
1. The exact short-circuit condition (`if (n == 0) ... if (n == 1) return verify_blob_kzg_proof(...)`),
2. How `r_powers` are derived from the Fiat-Shamir transcript,
3. Whether `deduplicate_commitments` or any commitment-index collapsing occurs before the pairing check,

I cannot state whether the claimed equality `verify(...,1) == verify_blob_kzg_proof(same triple)` actually breaks for a 3-item batch with two byte-identical entries.

**This is inconclusive due to incomplete code retrieval, not because I found evidence against the vulnerability.** A definitive answer requires reading `src/eip4844/eip4844.c` lines covering `verify_blob_kzg_proof_batch` (likely in the 200–400 line range based on file structure) to compare the pairing-check equation for `n==1` vs. `n==3` with duplicate commitments/proofs/blobs, and to check whether the random `r_powers` linear combination could cancel out a forged term when two of the three triples are identical.

I recommend re-running this investigation with a fresh session to directly `read_file` the full body of `verify_blob_kzg_proof_batch` in `src/eip4844/eip4844.c`, or starting a Devin session to trace this function's exact implementation and construct the C/Elixir test comparing both sides of the equality.

### Citations

**File:** bindings/elixir/native/src/ckzg_wrap.c (L371-408)
```c
    ErlNifBinary blobs;
    if (!enif_inspect_binary(env, argv[0], &blobs))
        return make_error(env, ckzg_atoms.blob_not_binary);

    if (blobs.size % BYTES_PER_BLOB != 0) return make_error(env, ckzg_atoms.invalid_blob_length);

    ErlNifBinary commitments;
    if (!enif_inspect_binary(env, argv[1], &commitments))
        return make_error(env, ckzg_atoms.commitment_not_binary);

    if (commitments.size % BYTES_PER_COMMITMENT != 0)
        return make_error(env, ckzg_atoms.invalid_commitment_length);

    ErlNifBinary proofs;
    if (!enif_inspect_binary(env, argv[2], &proofs))
        return make_error(env, ckzg_atoms.proof_not_binary);

    if (proofs.size % BYTES_PER_PROOF != 0) return make_error(env, ckzg_atoms.invalid_proof_length);

    int blobs_len = blobs.size / BYTES_PER_BLOB;
    int commitments_len = commitments.size / BYTES_PER_COMMITMENT;
    int proofs_len = proofs.size / BYTES_PER_PROOF;
    if (commitments_len != blobs_len || commitments_len != proofs_len)
        return make_error(env, ckzg_atoms.expected_same_array_size);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[3], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    bool ok;
    C_KZG_RET ret = verify_blob_kzg_proof_batch(
        &ok,
        (const Blob *)blobs.data,
        (const Bytes48 *)commitments.data,
        (const Bytes48 *)proofs.data,
        blobs_len,
        settings
    );
```
