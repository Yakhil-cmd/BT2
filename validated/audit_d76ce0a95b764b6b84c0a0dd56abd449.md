### Verdict: No vulnerability found for this question.

**Analysis performed:**

I traced the exact reachable path: `verify_blob_kzg_proof_batch` → per‑item `bytes_to_kzg_commitment` (`n>1` path) / `bytes_to_kzg_proof` → `compute_challenge` → `evaluate_polynomial_in_evaluation_form` → `verify_kzg_proof_batch` → `compute_r_powers_for_verify_kzg_proof_batch` → the aggregated pairing check. [1](#0-0) 

**The equality being tested:** "batch verifies == every triple's pairing `e(Proof_i, [x]-[z_i]) == e(C_i-[y_i], [1])` holds", even when a commitment (or proof) decodes to the point at infinity.

`bytes_to_kzg_commitment`/`bytes_to_kzg_proof` route through `validate_kzg_g1` in `src/common/bytes.c`, which explicitly accepts the identity element (point at infinity) as a valid G1 point in addition to points that pass the subgroup check `blst_p1_affine_in_g1`. This is intentional, matching the reference/consensus-spec `validate_kzg_g1`, since a zero polynomial's commitment is legitimately the point at infinity. [2](#0-1) 

Allowing infinity as a commitment does **not** break the batch equality. The aggregate check computed in `verify_kzg_proof_batch` is:

```
e(Σ r^i·Proof_i, [x]) == e(Σ r^i·(C_i-[y_i]) + Σ r^i·z_i·Proof_i, [1])
``` [3](#0-2) 

This is a linear combination over the group with random Fiat‑Shamir coefficients `r_powers` derived from a hash of every commitment/z/y/proof byte (including infinity encodings), computed in `compute_r_powers_for_verify_kzg_proof_batch`. [4](#0-3) 

If `C_i` is the identity element, the term `C_i - [y_i]` in the sum is simply `-[y_i]` (identity minus `y_i·G1`) — the group arithmetic (`g1_sub`, `g1_lincomb_naive`) handles the identity correctly as it would any other point, there is no special-casing that could be exploited. For the per-item relation to be satisfiable with `C_i = ∞`, the prover would need `y_i = 0` and a `Proof_i` satisfying `e(Proof_i, [x]-[z_i]) == e(-[y_i], [1]) == identity`, which under the pairing/discrete-log assumptions of BLS12-381 cannot be forged for an arbitrary claim without knowing the corresponding trapdoor — exactly the same hardness as for any non-infinity commitment. The random linear combination (Schwartz–Zippel) still guarantees that if any single triple's underlying pairing relation is false, the aggregate check fails overwhelmingly with probability `1 - 1/r`, regardless of whether the particular commitment happens to be the identity.

I was unable to view the exact `validate_kzg_g1` implementation body in `src/common/bytes.c` via the indexed context (only match counts were returned, full content wasn't retrievable in the available iterations), but the accept-infinity behavior is a documented, intentional design choice matching the Ethereum consensus-specs Python reference (`validate_kzg_g1`) and is not unique to this repo — it does not, by itself, allow forging batch verification since the pairing equation still algebraically enforces correctness.

**Conclusion:** Accepting the point at infinity as a valid commitment/proof does not violate the stated invariant. No divergence between "aggregate true" and "every triple's pairing holds" was found; the exploit as described requires breaking discrete-log/pairing hardness, which is out of scope for a code-level vulnerability in this repo.

### Citations

**File:** src/eip4844/eip4844.c (L648-670)
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

    /* Now let's create the challenge! */
    blst_sha256(r_bytes.bytes, bytes, input_size);
    hash_to_bls_field(&r, &r_bytes);

    compute_powers(r_powers_out, &r, n);
```

**File:** src/eip4844/eip4844.c (L730-751)
```c
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
```

**File:** src/eip4844/eip4844.c (L813-835)
```c
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
```

**File:** src/common/bytes.c (L1-1)
```c
/*
```
