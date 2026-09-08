Based on the code in `src/eip4844/eip4844.c`, the equality holds correctly. Every step uses the same loop index `i` to bind all four values (commitment, z, y, proof) together, both in the transcript hash and in the pairing equation.

**Trace of the equality:**

1. **Transcript hash construction** — `compute_r_powers_for_verify_kzg_proof_batch` iterates `for (size_t i = 0; i < n; i++)` and serializes `commitments_affine[i]`, `zs_fr[i]`, `ys_fr[i]`, `proofs_affine[i]` in that single loop iteration, so the hash binds the tuple at index `i` together. [1](#0-0) 

2. **`C_minus_y` and `r_times_z` construction** — both are computed in the *same* `for (size_t i = 0; i < n; i++)` loop body: `g1_sub(&C_minus_y[i], &commitments_g1[i], &ys_encrypted)` (with `ys_encrypted` derived from `ys_fr[i]`) and `fr_mul(&r_times_z[i], &r_powers[i], &zs_fr[i])`. There is no offset, reversed iteration, or separate index variable — `i` is shared for both statements. [2](#0-1) 

3. **Lincomb calls** — `g1_lincomb_naive(&proof_z_lincomb, proofs_g1, r_times_z, n)` pairs `proofs_g1[i]` with `r_times_z[i] = r_powers[i]*zs_fr[i]`, and `g1_lincomb_naive(&C_minus_y_lincomb, C_minus_y, r_powers, n)` pairs `C_minus_y[i]` with `r_powers[i]`. Since `proofs_g1[i]`, `zs_fr[i]`, `ys_fr[i]`, `commitments_g1[i]` were all populated from the caller's index `i` in `verify_blob_kzg_proof_batch`'s own single loop, the tuple used in the transcript matches the tuple used in the pairing sums for every `i`.
<invoke name="codebase_search">
<parameter name="query">verify_blob_kzg_proof_batch loop fills commitments_g1 proofs_g1 evaluation_challenges_fr ys_fr by index</parameter>
</invoke>

### Citations

**File:** src/eip4844/eip4844.c (L648-664)
```c
    for (size_t i = 0; i < n; i++) {
        /* Copy commitment */
        blst_p1_affine_compress(offset, &commitments_affine[i]);
        offset += BYTES_PER_COMMITMENT;

        /* Copy z */
        bytes_from_bls_field((Bytes32 *)offset, &zs_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy y */
        bytes_from_bls_field((Bytes32 *)offset, &ys_fr[i]);
        offset += BYTES_PER_FIELD_ELEMENT;

        /* Copy proof */
        blst_p1_affine_compress(offset, &proofs_affine[i]);
        offset += BYTES_PER_PROOF;
    }
```

**File:** src/eip4844/eip4844.c (L733-741)
```c
    for (size_t i = 0; i < n; i++) {
        g1_t ys_encrypted;
        /* Get [y_i] */
        g1_mul(&ys_encrypted, blst_p1_generator(), &ys_fr[i]);
        /* Get C_i - [y_i] */
        g1_sub(&C_minus_y[i], &commitments_g1[i], &ys_encrypted);
        /* Get r^i * z_i */
        fr_mul(&r_times_z[i], &r_powers[i], &zs_fr[i]);
    }
```
