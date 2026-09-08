### No vulnerability found for this question.

**Analysis supporting this conclusion:**

The code path for `n == 0` is an explicit, documented short-circuit: [1](#0-0) . The function's own doc comment states "This function accepts if called with `n==0`" [2](#0-1) .

This is not a bypass of the "batch verdict == AND of per-triple verdicts" invariant — it is the correct implementation of it. An empty conjunction (AND over zero elements) is vacuously `true` by definition; there are no triples to falsify the AND. Since `n == 0` means zero blobs, commitments, and proofs are supplied, there is no blob data, commitment, or proof being asserted as valid for any content — there is nothing to "forge" and nothing for a linear combination to cancel, because the linear-combination machinery (`compute_r_powers_for_verify_kzg_proof_batch`, `verify_kzg_proof_batch` at [3](#0-2) ) is never even invoked for `n == 0`; it is only reached for `n > 1`, guarded by `assert(n > 0)` [4](#0-3) .

No blob transaction or sidecar can actually carry zero blobs in practice at the consensus layer (an empty blob-sidecar/data-column with zero commitments corresponds to zero blob data to make available), so accepting `ok = true` for an empty set does not cause any unavailable or wrong blob data to be treated as available/valid — there is no data in scope of this call. This matches standard EIP-4844 spec behavior (the Python spec's equivalent list-comprehension `all([])` over an empty list is also `True`), so there is no divergence from the reference specification and no consensus-splitting behavior introduced by this repository.

Since both sides of the claimed equality (`batch verdict` and `AND of per-triple verdicts`) evaluate to `true`/vacuous-true for `n == 0`, and no forged commitment/proof/cell content is involved at all, there is no broken invariant here.

### Citations

**File:** src/eip4844/eip4844.c (L697-758)
```c
static C_KZG_RET verify_kzg_proof_batch(
    bool *ok,
    const g1_t *commitments_g1,
    const fr_t *zs_fr,
    const fr_t *ys_fr,
    const g1_t *proofs_g1,
    size_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t proof_lincomb, proof_z_lincomb, C_minus_y_lincomb, rhs_g1;
    fr_t *r_powers = NULL;
    g1_t *C_minus_y = NULL;
    fr_t *r_times_z = NULL;

    assert(n > 0);

    *ok = false;

    /* First let's allocate our arrays */
    ret = new_fr_array(&r_powers, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&C_minus_y, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&r_times_z, n);
    if (ret != C_KZG_OK) goto out;

    /* Compute the random lincomb challenges */
    ret = compute_r_powers_for_verify_kzg_proof_batch(
        r_powers, commitments_g1, zs_fr, ys_fr, proofs_g1, n
    );
    if (ret != C_KZG_OK) goto out;

    /* Compute \sum r^i * Proof_i */
    g1_lincomb_naive(&proof_lincomb, proofs_g1, r_powers, n);

    for (size_t i = 0; i < n; i++) {
        g1_t ys_encrypted;
        /* Get [y_i] */
        g1_mul(&ys_encrypted, blst_p1_generator(), &ys_fr[i]);
        /* Get C_i - [y_i] */
        g1_sub(&C_minus_y[i], &commitments_g1[i], &ys_encrypted);
        /* Get r^i * z_i */
        fr_mul(&r_times_z[i], &r_powers[i], &zs_fr[i]);
    }

    /* Get \sum r^i z_i Proof_i */
    g1_lincomb_naive(&proof_z_lincomb, proofs_g1, r_times_z, n);
    /* Get \sum r^i (C_i - [y_i]) */
    g1_lincomb_naive(&C_minus_y_lincomb, C_minus_y, r_powers, n);
    /* Get C_minus_y_lincomb + proof_z_lincomb */
    g1_add(&rhs_g1, &C_minus_y_lincomb, &proof_z_lincomb);

    /* Do the pairing check! */
    *ok = pairings_verify(&proof_lincomb, &s->g2_values_monomial[1], &rhs_g1, blst_p2_generator());

out:
    c_kzg_free(r_powers);
    c_kzg_free(C_minus_y);
    c_kzg_free(r_times_z);
    return ret;
}
```

**File:** src/eip4844/eip4844.c (L771-771)
```c
 * @remark This function accepts if called with `n==0`.
```

**File:** src/eip4844/eip4844.c (L790-794)
```c
    /* Exit early if we are given zero blobs */
    if (n == 0) {
        *ok = true;
        return C_KZG_OK;
    }
```
