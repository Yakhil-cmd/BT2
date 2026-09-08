### No vulnerability found for this question.

**Equality checked:** for `n==1`, `verify_blob_kzg_proof_batch` returns the verdict of `verify_blob_kzg_proof(&blobs[0], ...)` [1](#0-0) , while for `n>1` it goes through `verify_kzg_proof_batch`, which computes random powers `r_powers` via `compute_r_powers_for_verify_kzg_proof_batch` and does a single combined pairing check over `proof_lincomb`, `C_minus_y_lincomb`, and `proof_z_lincomb` [2](#0-1) .

**Why the two paths agree, including for an infinity commitment:**

`compute_powers(r_powers_out, &r, n)` always produces `r_powers[0] = r^0 = 1` regardless of the actual challenge `r`. So for `n==1` fed through the general path, `proof_lincomb = 1*proof_0 = proof_0`, `C_minus_y_lincomb = 1*(C_0 - y_0*G) = C_0 - y_0*G`, and `proof_z_lincomb = z_0*proof_0`. This is algebraically identical to what the non-batch `verify_kzg_proof_impl` computes for a single item (as reached via `verify_blob_kzg_proof` → `verify_kzg_proof_impl`, referenced in [3](#0-2) ). There is no dependence on randomization when `n==1`, so the shortcut cannot diverge from the general algorithm at that boundary.

Crucially, neither path needs a special case for the commitment being the point at infinity, because elliptic-curve group law (`g1_sub`, `g1_add`, `g1_mul`, `g1_lincomb_naive`) treats the identity element correctly by construction — subtracting `[y]*G` from the infinity point, adding lincomb terms, and scalar-multiplying by `r_powers[i]` all behave correctly whether or not any input point is the identity. `validate_kzg_g1` explicitly accepts the point at infinity as valid input (`blst_p1_is_inf` check) [4](#0-3) , and the existing test vector `verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3` confirms the reference behavior for this exact scenario (commitment = proof = infinity, output `true`) is handled uniformly, without any code branch treating it specially [5](#0-4) .

Extending to the padded `n==2` duplicate scenario proposed in the question: with `r_powers = [1, r]`, the combined equation becomes `(1+r) * (original single-item equation)`. Since group/pairing equality scales linearly, this holds if and only if the original single-item equation holds (barring the negligible-probability case `1+r ≡ 0 mod q`, which is a generic property of the random-linear-combination technique itself, not specific to infinity commitments, and not attacker-controllable since `r` is derived via Fiat–Shamir over the transcript including the actual commitment/proof bytes).

Thus the `n==1` shortcut and the general `n>1` path (including the `n=2` duplicate case) are mathematically consistent for infinity commitments, and no divergence exists that would cause a batch verdict to depend on batch size for logically identical inputs.

### Citations

**File:** src/eip4844/eip4844.c (L282-328)
```c
/* Forward function declaration */
static C_KZG_RET verify_kzg_proof_impl(
    bool *ok,
    const g1_t *commitment,
    const fr_t *z,
    const fr_t *y,
    const g1_t *proof,
    const KZGSettings *s
);

/**
 * Verify a KZG proof claiming that `p(z) == y`.
 *
 * @param[out]  ok          True if the proofs are valid, otherwise false
 * @param[in]   commitment  The KZG commitment corresponding to poly p(x)
 * @param[in]   z           The evaluation point
 * @param[in]   y           The claimed evaluation result
 * @param[in]   kzg_proof   The KZG proof
 * @param[in]   s           The trusted setup
 */
C_KZG_RET verify_kzg_proof(
    bool *ok,
    const Bytes48 *commitment_bytes,
    const Bytes32 *z_bytes,
    const Bytes32 *y_bytes,
    const Bytes48 *proof_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t z_fr, y_fr;
    g1_t commitment_g1, proof_g1;

    *ok = false;

    /* Convert untrusted inputs to trusted inputs */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_bls_field(&z_fr, z_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_bls_field(&y_fr, y_bytes);
    if (ret != C_KZG_OK) return ret;
    ret = bytes_to_kzg_proof(&proof_g1, proof_bytes);
    if (ret != C_KZG_OK) return ret;

    /* Call helper to do pairings check */
    return verify_kzg_proof_impl(ok, &commitment_g1, &z_fr, &y_fr, &proof_g1, s);
}
```

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

**File:** src/eip4844/eip4844.c (L796-799)
```c
    /* For a single blob, just do a regular single verification */
    if (n == 1) {
        return verify_blob_kzg_proof(ok, &blobs[0], &commitments_bytes[0], &proofs_bytes[0], s);
    }
```

**File:** src/common/bytes.c (L81-95)
```c
static C_KZG_RET validate_kzg_g1(g1_t *out, const Bytes48 *b) {
    blst_p1_affine p1_affine;

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(&p1_affine, b->bytes) != BLST_SUCCESS) return C_KZG_BADARGS;
    blst_p1_from_affine(out, &p1_affine);

    /* The point at infinity is accepted! */
    if (blst_p1_is_inf(out)) return C_KZG_OK;
    /* The point must be on the right subgroup */
    if (!blst_p1_in_g1(out)) return C_KZG_BADARGS;

    return C_KZG_OK;
}
```

**File:** tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3/data.yaml (L1-6)
```yaml
input:
  commitment: '0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
  z: '0x5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62'
  y: '0x0000000000000000000000000000000000000000000000000000000000000000'
  proof: '0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
output: true
```
