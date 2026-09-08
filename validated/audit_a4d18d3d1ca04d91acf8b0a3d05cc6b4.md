### No vulnerability found for this question.

**Analysis:** The described flaw does not exist in this codebase. In `compute_kzg_proof_impl`, the sentinel design already avoids conflating "not found" with "found at index 0": [1](#0-0) , then [2](#0-1) .

For `z = 0`, since `0` is never among `brp_roots_of_unity` (all roots of unity are nonzero field elements), `fr_equal(z, &brp_roots_of_unity[i])` is false for every `i`, so `m` remains `0` throughout the loop and the `if (m != 0)` block is never entered — `q_poly[0]` is never spuriously zeroed or rebuilt. The generic out-of-domain formula computed in the first loop, `fr_sub(&q_poly[i], &poly[i], y_out); fr_sub(&inverses_in[i], &brp_roots_of_unity[i], z);` [3](#0-2) , is exactly what is used, matching the correct out-of-domain divide formula `(p_i - y)/(ω_i - z)`.

The `m == 0` value is a sentinel meaning "not found", never confused with "found at index 0", because the actual found index is encoded as `m - 1` (via `m = i + 1` on write and `--m` on read). This is the standard correct pattern precisely to prevent the ambiguity the question hypothesizes. There is no divergent branch or alternate implementation of this logic in the repository (only one `compute_kzg_proof_impl` exists, used identically by both `compute_kzg_proof` and `compute_blob_kzg_proof`) [4](#0-3) [5](#0-4) .

Existing tests already exercise round-trip verification for both random out-of-domain `z` and in-domain `z` values and assert `ok == true` [6](#0-5) , and no code path treats `m==0` as "found at index 0."

### Citations

**File:** src/eip4844/eip4844.c (L382-406)
```c
C_KZG_RET compute_kzg_proof(
    KZGProof *proof_out,
    Bytes32 *y_out,
    const Blob *blob,
    const Bytes32 *z_bytes,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *poly = NULL;
    fr_t frz, fry;

    ret = new_fr_array(&poly, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = blob_to_polynomial(poly, blob);
    if (ret != C_KZG_OK) goto out;
    ret = bytes_to_bls_field(&frz, z_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = compute_kzg_proof_impl(proof_out, &fry, poly, &frz, s);
    if (ret != C_KZG_OK) goto out;
    bytes_from_bls_field(y_out, &fry);

out:
    c_kzg_free(poly);
    return ret;
}
```

**File:** src/eip4844/eip4844.c (L430-451)
```c
    uint64_t i;
    /* m != 0 indicates that the evaluation point z equals root_of_unity[m-1] */
    uint64_t m = 0;

    ret = new_fr_array(&inverses_in, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&inverses, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&q_poly, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    for (i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        if (fr_equal(z, &brp_roots_of_unity[i])) {
            /* We are asked to compute a KZG proof inside the domain */
            m = i + 1;
            inverses_in[i] = FR_ONE;
            continue;
        }
        // (p_i - y) / (ω_i - z)
        fr_sub(&q_poly[i], &poly[i], y_out);
        fr_sub(&inverses_in[i], &brp_roots_of_unity[i], z);
    }
```

**File:** src/eip4844/eip4844.c (L460-461)
```c
    if (m != 0) { /* ω_{m-1} == z */
        q_poly[--m] = FR_ZERO;
```

**File:** src/eip4844/eip4844.c (L506-535)
```c
C_KZG_RET compute_blob_kzg_proof(
    KZGProof *out, const Blob *blob, const Bytes48 *commitment_bytes, const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *poly = NULL;
    g1_t commitment_g1;
    fr_t evaluation_challenge_fr;
    fr_t y;

    /* Allocate space for our polynomial */
    ret = new_fr_array(&poly, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Do conversions first to fail fast, compute_challenge is expensive */
    ret = bytes_to_kzg_commitment(&commitment_g1, commitment_bytes);
    if (ret != C_KZG_OK) goto out;
    ret = blob_to_polynomial(poly, blob);
    if (ret != C_KZG_OK) goto out;

    /* Compute the challenge for the given blob/commitment */
    compute_challenge(&evaluation_challenge_fr, blob, &commitment_g1);

    /* Call helper function to compute proof and y */
    ret = compute_kzg_proof_impl(out, &y, poly, &evaluation_challenge_fr, s);
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(poly);
    return ret;
}
```

**File:** src/test/tests.c (L1108-1203)
```c
static void test_compute_and_verify_kzg_proof__succeeds_round_trip(void) {
    C_KZG_RET ret;
    Bytes48 proof;
    Bytes32 z, y, computed_y;
    KZGCommitment c;
    Blob blob;
    fr_t poly[FIELD_ELEMENTS_PER_BLOB];
    fr_t y_fr, z_fr;
    bool ok;
    int diff;

    get_rand_field_element(&z);
    get_rand_blob(&blob);

    /* Get a commitment to that particular blob */
    ret = blob_to_kzg_commitment(&c, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Compute the proof */
    ret = compute_kzg_proof(&proof, &computed_y, &blob, &z, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /*
     * Now let's attempt to verify the proof.
     * First convert the blob to field elements.
     */
    ret = blob_to_polynomial(poly, &blob);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Also convert z to a field element */
    ret = bytes_to_bls_field(&z_fr, &z);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Now evaluate the poly at `z` to learn `y` */
    ret = evaluate_polynomial_in_evaluation_form(&y_fr, poly, &z_fr, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Now also get `y` in bytes */
    bytes_from_bls_field(&y, &y_fr);

    /* Compare the recently evaluated y to the computed y */
    diff = memcmp(y.bytes, computed_y.bytes, sizeof(Bytes32));
    ASSERT_EQUALS(diff, 0);

    /* Finally verify the proof */
    ret = verify_kzg_proof(&ok, &c, &z, &y, &proof, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);
    ASSERT_EQUALS(ok, true);
}

static void test_compute_and_verify_kzg_proof__succeeds_within_domain(void) {
    for (size_t i = 0; i < 25; i++) {
        C_KZG_RET ret;
        Blob blob;
        KZGCommitment c;
        fr_t poly[FIELD_ELEMENTS_PER_BLOB];
        Bytes48 proof;
        Bytes32 z, y, computed_y;
        fr_t y_fr, z_fr;
        bool ok;
        int diff;

        get_rand_blob(&blob);

        /* Get a commitment to that particular blob */
        ret = blob_to_kzg_commitment(&c, &blob, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);

        /* Get the polynomial version of the blob */
        ret = blob_to_polynomial(poly, &blob);
        ASSERT_EQUALS(ret, C_KZG_OK);

        z_fr = s.brp_roots_of_unity[i];
        bytes_from_bls_field(&z, &z_fr);

        /* Compute the proof */
        ret = compute_kzg_proof(&proof, &computed_y, &blob, &z, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);

        /* Now evaluate the poly at `z` to learn `y` */
        ret = evaluate_polynomial_in_evaluation_form(&y_fr, poly, &z_fr, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);

        /* Now also get `y` in bytes */
        bytes_from_bls_field(&y, &y_fr);

        /* Compare the recently evaluated y to the computed y */
        diff = memcmp(y.bytes, computed_y.bytes, sizeof(Bytes32));
        ASSERT_EQUALS(diff, 0);

        /* Finally verify the proof */
        ret = verify_kzg_proof(&ok, &c, &z, &y, &proof, &s);
        ASSERT_EQUALS(ret, C_KZG_OK);
        ASSERT_EQUALS(ok, true);
    }
}
```
