Based on the analysis, the code explicitly and intentionally accepts the point at infinity as a valid commitment/proof, matching the reference specification's behavior. This is documented behavior, not a bug: `validate_kzg_g1` in `src/common/bytes.c` has an explicit comment "The point at infinity is accepted!" before returning `C_KZG_OK` for infinity points.

The `blst_miller_loop`/`blst_final_exp` pairing math in `pairings_verify` (`src/common/utils.c:172-196`) correctly handles the point at infinity algebraically — a Miller loop with an infinity G1 point yields the identity element in G_T, which is the mathematically correct pairing result `e(∞, X) = 1`. This is standard elliptic-curve pairing behavior, not a bypass.

For `verify_blob_kzg_proof_batch` (`src/eip4844/eip4844.c:775-844`), the evaluation challenge `z_i` is derived via Fiat-Shamir over the blob and commitment bytes in `compute_challenge`, and `y_i` is computed deterministically from the actual blob polynomial via `evaluate_polynomial_in_evaluation_form` — neither is attacker-freely-chosen. So even with an infinity commitment, the pairing equation `e(ProofLincomb, [τ]) == e(C_minus_y_lincomb + proof_z_lincomb, G2)` still must hold with values tied to the real blob content; an attacker cannot forge an unrelated/wrong blob's acceptance by merely substituting an infinity commitment, since `y_i`/`z_i` remain bound to the actual polynomial data.

The repo's own test suite already exercises this scenario: `tests/verify_blob_kzg_proof_batch/kzg-mainnet/verify_blob_kzg_proof_batch_case_incorrect_proof_point_at_infinity/data.yaml` supplies an infinity-point proof and expects `output: false`, confirming the pairing check correctly rejects invalid infinity-related inputs rather than universally accepting them. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

Accepting the point at infinity as a valid G1 element (when properly on-curve, which infinity trivially satisfies) is the documented, spec-conformant behavior shared with the Ethereum consensus-specs reference implementation; it does not create a divergence between honest nodes, nor does it allow a forged proof/commitment to pass verification for data that doesn't match, since `y_i` and `z_i` remain cryptographically bound to the real blob content through the Fiat-Shamir transcript. No broken invariant was found.

### No vulnerability found for this question.

### Citations

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

**File:** src/common/utils.c (L172-196)
```c
bool pairings_verify(const g1_t *a1, const g2_t *a2, const g1_t *b1, const g2_t *b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    /*
     * As an optimisation, we want to invert one of the pairings,
     * so we negate one of the points.
     */
    g1_t a1neg = *a1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&aa1, &a1neg);
    blst_p1_to_affine(&bb1, b1);
    blst_p2_to_affine(&aa2, a2);
    blst_p2_to_affine(&bb2, b2);

    blst_miller_loop(&loop0, &aa2, &aa1);
    blst_miller_loop(&loop1, &bb2, &bb1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
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

**File:** src/eip4844/eip4844.c (L775-844)
```c
C_KZG_RET verify_blob_kzg_proof_batch(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    uint64_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t *commitments_g1 = NULL;
    g1_t *proofs_g1 = NULL;
    fr_t *evaluation_challenges_fr = NULL;
    fr_t *ys_fr = NULL;
    fr_t *poly = NULL;

    /* Exit early if we are given zero blobs */
    if (n == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    /* For a single blob, just do a regular single verification */
    if (n == 1) {
        return verify_blob_kzg_proof(ok, &blobs[0], &commitments_bytes[0], &proofs_bytes[0], s);
    }

    /* We will need a bunch of arrays to store our objects... */
    ret = new_g1_array(&commitments_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&evaluation_challenges_fr, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&ys_fr, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (size_t i = 0; i < n; i++) {
        /* Convert each commitment to a g1 point */
        ret = bytes_to_kzg_commitment(&commitments_g1[i], &commitments_bytes[i]);
        if (ret != C_KZG_OK) goto out;

        /* Convert each blob from bytes to a poly */
        ret = blob_to_polynomial(poly, &blobs[i]);
        if (ret != C_KZG_OK) goto out;

        compute_challenge(&evaluation_challenges_fr[i], &blobs[i], &commitments_g1[i]);

        ret = evaluate_polynomial_in_evaluation_form(
            &ys_fr[i], poly, &evaluation_challenges_fr[i], s
        );
        if (ret != C_KZG_OK) goto out;

        ret = bytes_to_kzg_proof(&proofs_g1[i], &proofs_bytes[i]);
        if (ret != C_KZG_OK) goto out;
    }

    ret = verify_kzg_proof_batch(
        ok, commitments_g1, evaluation_challenges_fr, ys_fr, proofs_g1, n, s
    );

out:
    c_kzg_free(commitments_g1);
    c_kzg_free(proofs_g1);
    c_kzg_free(evaluation_challenges_fr);
    c_kzg_free(ys_fr);
    c_kzg_free(poly);
    return ret;
}
```

**File:** tests/verify_blob_kzg_proof_batch/kzg-mainnet/verify_blob_kzg_proof_batch_case_incorrect_proof_point_at_infinity/data.yaml (L1-8)
```yaml
input:
  blobs:
  - '0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe304962b3598a0adf33189fdfd9789feab1096ff40006900400000003fffffffc6092c566b31415be66313fbfb2f13fd56212dfe8000d200800000007fffffff84d37e37a3c8aae349928a7775c40a7a570681bcd001be41100000010ffffffef26821fa14f77df20ff1776e6aedf77458d12939700396c2300000022ffffffdd4d043f429eefbe41fe2eedcd5dbeee8b1a25272e0072d84600000045ffffffba261ad7321441ff3bc9240392b1dc0510e08caa5900e7548d0000008cffffff734c35ae642883fe779248072563b80a21c11954b201cea91a00000119fffffee6247db575276a7fa6f1563642bdce3c3e2e750561039ef63500000234fffffdcb48fb6aea4ed4ff4de2ac6c857b9c787c5cea0ac2073dec6a00000469fffffb961e092e81740c8153921f0102ed9718f3661671810e7d7cd5000008d4fffff72b3c125d02e81902a7243e0205db2e31e6cc2ce3021cfaf9aa000011a9ffffee56043712b2a694880615422c03a ... (truncated)
  commitments:
  - '0xa421e229565952cfff4ef3517100a97da1d4fe57956fa50a442f92af03b1bf37adacc8ad4ed209b31287ea5bb94d9d06'
  proofs:
  - '0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
output: false
```
