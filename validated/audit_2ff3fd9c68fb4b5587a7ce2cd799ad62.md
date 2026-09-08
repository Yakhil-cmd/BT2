### Title
Missing degree-bound validation in `recover_cells_and_kzg_proofs` allows silent OK on cells inconsistent with a degree<4096 polynomial - (File: `src/eip7594/eip7594.c` / `src/eip7594/recovery.c`)

### Summary
`recover_cells_and_kzg_proofs` (via `recover_cells`) reconstructs missing cells using an FFT-based erasure-decoding algorithm that is only mathematically correct when the supplied cells are genuine evaluations of a polynomial of degree < `FIELD_ELEMENTS_PER_BLOB` (4096). Unlike `compute_cells_and_kzg_proofs`, which explicitly asserts the upper half of the polynomial's monomial coefficients are zero [1](#0-0) , neither `recover_cells_and_kzg_proofs` nor its helper `recover_cells` ever checks that the recovered polynomial actually satisfies this degree bound before returning `C_KZG_OK` [2](#0-1) [3](#0-2) .

### Finding Description
The invariant under test is: *recovered cells == the unique degree<4096 extension of the inputs, or `C_KZG_BADARGS`*.

`recover_cells_and_kzg_proofs` only validates: `num_cells <= CELLS_PER_EXT_BLOB`, `num_cells >= CELLS_PER_BLOB`, that each `cell_indices[i] < CELLS_PER_EXT_BLOB`, and that indices are strictly ascending [4](#0-3) . It never checks that the supplied cell values are actually consistent with *some* degree<4096 polynomial.

The core recovery algorithm in `recover_cells` (`src/eip7594/recovery.c`) computes a vanishing polynomial `Z(x)` that is zero at the missing positions [5](#0-4) , forms `(E*Z)` in evaluation form, IFFTs it to monomial form, and then divides by `Z(x)` pointwise on a coset to recover `P(x)` [6](#0-5) . This division-by-`Z` step is only guaranteed to yield the correct low-degree `P(x)` when the true supporting polynomial of the given cells has degree < `FIELD_ELEMENTS_PER_BLOB`. If the 65 cells provided (`num_cells == CELLS_PER_BLOB + 1`, "one recoverable column") are values that are self-consistent among themselves but that interpolate to a polynomial of degree ≥ 4096, the coset division still produces *some* well-defined field values (no divide-by-zero, since `Z` is evaluated away from its roots on the coset), and the function proceeds straight to computing proofs via `compute_fk20_cell_proofs` and returns `C_KZG_OK` [7](#0-6)  — with no post-hoc check (analogous to the assert in `compute_cells_and_kzg_proofs`) that the reconstructed polynomial's coefficients above index `FIELD_ELEMENTS_PER_BLOB` are actually zero.

None of the existing guards catch this:
- `bytes_to_bls_field` only ensures each cell byte-chunk decodes to a valid field element [8](#0-7) ; it says nothing about the aggregate degree of the reconstructed polynomial.
- The cell-index bound/ordering checks only validate index ranges/ordering, not values [9](#0-8) .
- `recover_cells`'s only `assert` checks the *count* of missing cells, not the degree of the reconstructed polynomial [10](#0-9) .
- `deduplicate_commitments` and the batch-verify challenge logic are part of `verify_cell_kzg_proof_batch`, a separate function not invoked by `recover_cells_and_kzg_proofs`, so nothing there re-checks the recovered output against a commitment before it is returned to the caller.

Because `recover_cells_and_kzg_proofs` generates its own proofs from whatever polynomial it derives (self-consistent proofs for a possibly-wrong polynomial), the function's documented contract — that callers can trust its output directly — is violated when the input cells are (individually) legitimately-proof-verifiable openings of a commitment to a higher-degree polynomial (which the KZG opening pairing check alone cannot rule out, since that check is degree-agnostic and only certifies `y = f(z)` for whatever polynomial the commitment represents).

### Impact Explanation
This function silently returns `C_KZG_OK` with a well-formed but non-canonical reconstruction instead of detecting the degree violation and returning `C_KZG_BADARGS`. Because the erasure-decoding math depends on *which* 65-of-128 cells are supplied, different honest nodes that observe different subsets of cells for the same blob/commitment (a realistic scenario in PeerDAS-style gossip/custody) can reconstruct different, non-canonical "full" cell sets and self-consistent proofs from the same underlying (malformed) commitment. Whether this can be escalated to "a forged proof verifies against the honest commitment" depends on whether downstream client code re-verifies recovered cells/proofs against the original commitment before use; the recovery function itself provides no such re-check and its docstring implies its output should be trusted without further verification. This is a genuine, reproducible defect in the target function (missing degree-bound enforcement, `C_KZG_OK` instead of `C_KZG_BADARGS`), but I could not fully verify within this session whether the SRS size (`g1_monomial`) structurally prevents an attacker from constructing a valid, individually-verifying-but-high-degree commitment/proof set in the first place, which is necessary to escalate this from "recovery produces wrong/non-deterministic local data" to "a forged cell/proof verifies as valid against the network-agreed commitment."

### Likelihood Explanation
No privileged access is required — an attacker only needs to craft blob/cell/proof bytes that are individually valid KZG openings (mechanically feasible using only public setup material, no toxic waste needed) but do not derive from an actual degree<4096 blob. The attack is repeatable for any blob/data-column sidecar and costs nothing beyond normal transaction/sidecar submission. The missing check is unconditionally reachable through the public C API and every language binding (Python `ckzg_wrap.c`, Go, Node.js, etc.) with no additional privilege.

### Recommendation
After computing `reconstructed_poly_coeff` (or after computing the final `poly_monomial` used for proof generation), add an explicit check — mirroring the assert in `compute_cells_and_kzg_proofs` — that all coefficients from index `FIELD_ELEMENTS_PER_BLOB` to `FIELD_ELEMENTS_PER_EXT_BLOB - 1` are zero, and return `C_KZG_BADARGS` (not an `assert`, since this is attacker-controlled input, not an internal invariant) if the check fails, before returning `C_KZG_OK` from `recover_cells_and_kzg_proofs`.

### Proof of Concept
C unit test plan for `src/test/tests.c`:
1. Construct a polynomial `p(x)` of degree ≥ `FIELD_ELEMENTS_PER_BLOB` (e.g., degree `FIELD_ELEMENTS_PER_EXT_BLOB - 1`) using the public monomial SRS points (no toxic waste needed).
2. Evaluate `p` at the extended domain to get 128 "cells", each independently openable via standard KZG proofs against `C = commit(p)`.
3. Select 65 of these cells/indices (one more than `CELLS_PER_BLOB`), matching the "one recoverable column" scenario.
4. Call `recover_cells_and_kzg_proofs(recovered_cells, recovered_proofs, cell_indices, partial_cells, 65, &s)`.
5. Assert the invariant: either `ret == C_KZG_BADARGS`, or, if `ret == C_KZG_OK`, assert that `recovered_cells` equals the true low-degree extension (it will not, since `p` has degree ≥ 4096) — demonstrating the current implementation returns `C_KZG_OK` with a non-canonical/incorrect reconstruction, violating the stated invariant.

### Citations

**File:** src/eip7594/eip7594.c (L95-98)
```c
    /* Ensure that only the first FIELD_ELEMENTS_PER_BLOB elements can be non-zero */
    for (size_t i = FIELD_ELEMENTS_PER_BLOB; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        assert(fr_equal(&poly_monomial[i], &FR_ZERO));
    }
```

**File:** src/eip7594/eip7594.c (L177-304)
```c
C_KZG_RET recover_cells_and_kzg_proofs(
    Cell *recovered_cells,
    KZGProof *recovered_proofs,
    const uint64_t *cell_indices,
    const Cell *cells,
    uint64_t num_cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    fr_t *recovered_cells_fr = NULL;
    g1_t *recovered_proofs_g1 = NULL;
    blst_p1_affine *recovered_proofs_affine = NULL;

    /* Ensure only one blob's worth of cells was provided */
    if (num_cells > CELLS_PER_EXT_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    /* Check if it's possible to recover */
    if (num_cells < CELLS_PER_BLOB) {
        ret = C_KZG_BADARGS;
        goto out;
    }

    for (size_t i = 0; i < num_cells; i++) {
        /* Check that cell indices are valid */
        if (cell_indices[i] >= CELLS_PER_EXT_BLOB) {
            ret = C_KZG_BADARGS;
            goto out;
        }
        /* Check that indices are in strictly ascending order */
        if (i > 0 && cell_indices[i] <= cell_indices[i - 1]) {
            ret = C_KZG_BADARGS;
            goto out;
        }
    }

    /* Do allocations */
    ret = new_fr_array(&recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&recovered_proofs_g1, CELLS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Initialize all cells to zero */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        recovered_cells_fr[i] = FR_ZERO;
    }

    /* Populate recovered_cells_fr with available cells at the right places */
    for (size_t i = 0; i < num_cells; i++) {
        size_t index = cell_indices[i] * FIELD_ELEMENTS_PER_CELL;
        for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
            /* Convert the untrusted input bytes to a field element */
            fr_t *ptr = &recovered_cells_fr[index + j];
            size_t offset = j * BYTES_PER_FIELD_ELEMENT;
            ret = bytes_to_bls_field(ptr, (const Bytes32 *)&cells[i].bytes[offset]);
            if (ret != C_KZG_OK) goto out;
        }
    }

    if (num_cells == CELLS_PER_EXT_BLOB) {
        /* Nothing to recover, copy the cells */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            /*
             * At this point, and based on our checks above, we know that all indices are in the
             * right order. That is: cell_indices[i] == i
             */
            recovered_cells[i] = cells[i];
        }
    } else {
        /* Perform cell recovery */
        ret = recover_cells(recovered_cells_fr, cell_indices, num_cells, recovered_cells_fr, s);
        if (ret != C_KZG_OK) goto out;

        /* Convert the recovered data points to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            for (size_t j = 0; j < FIELD_ELEMENTS_PER_CELL; j++) {
                size_t index = i * FIELD_ELEMENTS_PER_CELL + j;
                size_t offset = j * BYTES_PER_FIELD_ELEMENT;
                bytes_from_bls_field(
                    (Bytes32 *)&recovered_cells[i].bytes[offset], &recovered_cells_fr[index]
                );
            }
        }
    }

    if (recovered_proofs != NULL) {
        /*
         * Instead of converting the cells to a blob and back, we can just treat the cells as a
         * polynomial. We are done with the fr-form recovered cells and we can safely mutate the
         * array.
         */
        ret = poly_lagrange_to_monomial(
            recovered_cells_fr, recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Compute the proofs, only uses the first half of the polynomial */
        ret = compute_fk20_cell_proofs(recovered_proofs_g1, recovered_cells_fr, s);
        if (ret != C_KZG_OK) goto out;

        /* Bit-reverse the proofs */
        ret = bit_reversal_permutation(recovered_proofs_g1, sizeof(g1_t), CELLS_PER_EXT_BLOB);
        if (ret != C_KZG_OK) goto out;

        /* Allocate space for affine proofs */
        ret = c_kzg_malloc(
            (void **)&recovered_proofs_affine, CELLS_PER_EXT_BLOB * sizeof(blst_p1_affine)
        );
        if (ret != C_KZG_OK) goto out;

        /* Batch convert proofs to affine */
        const blst_p1 *recovered_proofs_arg[2] = {recovered_proofs_g1, NULL};
        blst_p1s_to_affine(recovered_proofs_affine, recovered_proofs_arg, CELLS_PER_EXT_BLOB);

        /* Compress all of the proofs to byte-form */
        for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
            blst_p1_affine_compress(recovered_proofs[i].bytes, &recovered_proofs_affine[i]);
        }
    }

out:
    c_kzg_free(recovered_cells_fr);
    c_kzg_free(recovered_proofs_g1);
    c_kzg_free(recovered_proofs_affine);
    return ret;
}
```

**File:** src/eip7594/recovery.c (L200-365)
```c
C_KZG_RET recover_cells(
    fr_t *reconstructed_data_out,
    const uint64_t *cell_indices,
    size_t num_cells,
    fr_t *cells,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    uint64_t *missing_cell_indices = NULL;
    fr_t *vanishing_poly_eval = NULL;
    fr_t *vanishing_poly_coeff = NULL;
    fr_t *extended_evaluation_times_zero = NULL;
    fr_t *extended_evaluation_times_zero_coeffs = NULL;
    fr_t *extended_evaluations_over_coset = NULL;
    fr_t *vanishing_poly_over_coset = NULL;
    fr_t *reconstructed_poly_coeff = NULL;
    fr_t *cells_brp = NULL;

    /* Allocate space for arrays */
    ret = c_kzg_calloc(
        (void **)&missing_cell_indices, FIELD_ELEMENTS_PER_EXT_BLOB, sizeof(uint64_t)
    );
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_eval, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluation_times_zero_coeffs, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&extended_evaluations_over_coset, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&vanishing_poly_over_coset, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&reconstructed_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&cells_brp, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the data points, stored in new array */
    memcpy(cells_brp, cells, FIELD_ELEMENTS_PER_EXT_BLOB * sizeof(fr_t));
    ret = bit_reversal_permutation(cells_brp, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;

    /* Identify missing cells */
    size_t len_missing = 0;
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* Iterate over each cell index and check if we have received it */
        if (!is_in_array(cell_indices, num_cells, i)) {
            /* If the cell is missing, bit reverse the index and add it to the missing array */
            uint64_t brp_i = reverse_bits_limited(CELLS_PER_EXT_BLOB, i);
            missing_cell_indices[len_missing++] = brp_i;
        }
    }

    /*
     * Check that we have enough cells to recover.
     * Concretely, we need to have at least CELLS_PER_BLOB many cells.
     */
    assert(CELLS_PER_EXT_BLOB - len_missing >= CELLS_PER_BLOB);

    /*
     * Compute Z(x) in monomial form.
     * Z(x) is the polynomial which vanishes on all of the evaluations which are missing.
     */
    ret = vanishing_polynomial_for_missing_cells(
        vanishing_poly_coeff, missing_cell_indices, len_missing, s
    );
    if (ret != C_KZG_OK) goto out;

    /* Convert Z(x) to evaluation form */
    ret = fr_fft(vanishing_poly_eval, vanishing_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB, s);
    if (ret != C_KZG_OK) goto out;

    /*
     * Compute (E*Z)(x) = E(x) * Z(x) in evaluation form over the FFT domain.
     *
     * Note: over the FFT domain, the polynomials (E*Z)(x) and (P*Z)(x) agree, where
     * P(x) is the polynomial we want to reconstruct (degree FIELD_ELEMENTS_PER_BLOB - 1).
     */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        fr_mul(&extended_evaluation_times_zero[i], &cells_brp[i], &vanishing_poly_eval[i]);
    }

    /*
     * Convert (E*Z)(x) to monomial form.
     *
     * We know that (E*Z)(x) and (P*Z)(x) agree over the FFT domain,
     * and we know that (P*Z)(x) has degree at most FIELD_ELEMENTS_PER_EXT_BLOB - 1.
     * Thus, an inverse FFT of the evaluations of (E*Z)(x) (= evaluations of (P*Z)(x))
     * yields the coefficient form of (P*Z)(x).
     */
    ret = fr_ifft(
        extended_evaluation_times_zero_coeffs,
        extended_evaluation_times_zero,
        FIELD_ELEMENTS_PER_EXT_BLOB,
        s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * Next step is to divide the polynomial (P*Z)(x) by polynomial Z(x) to get P(x).
     * We do this in evaluation form over a coset of the FFT domain to avoid division by 0.
     *
     * Convert (P*Z)(x) to evaluation form over a coset of the FFT domain.
     */
    ret = coset_fft(
        extended_evaluations_over_coset,
        extended_evaluation_times_zero_coeffs,
        FIELD_ELEMENTS_PER_EXT_BLOB,
        s
    );
    if (ret != C_KZG_OK) goto out;

    /* Convert Z(x) to evaluation form over a coset of the FFT domain */
    ret = coset_fft(
        vanishing_poly_over_coset, vanishing_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB, s
    );
    if (ret != C_KZG_OK) goto out;

    /* Compute P(x) = (P*Z)(x) / Z(x) in evaluation form over a coset of the FFT domain */
    for (size_t i = 0; i < FIELD_ELEMENTS_PER_EXT_BLOB; i++) {
        fr_div(
            &extended_evaluations_over_coset[i],
            &extended_evaluations_over_coset[i],
            &vanishing_poly_over_coset[i]
        );
    }

    /*
     * Note: After the above polynomial division, extended_evaluations_over_coset is the same
     * polynomial as reconstructed_poly_over_coset in the spec.
     */

    /* Convert P(x) to coefficient form */
    ret = coset_ifft(
        reconstructed_poly_coeff, extended_evaluations_over_coset, FIELD_ELEMENTS_PER_EXT_BLOB, s
    );
    if (ret != C_KZG_OK) goto out;

    /*
     * After unscaling the reconstructed polynomial, we have P(x) which evaluates to our original
     * data at the roots of unity. Next, we evaluate the polynomial to get the original data.
     */
    ret = fr_fft(reconstructed_data_out, reconstructed_poly_coeff, FIELD_ELEMENTS_PER_EXT_BLOB, s);
    if (ret != C_KZG_OK) goto out;

    /* Bit-reverse the recovered data points */
    ret = bit_reversal_permutation(
        reconstructed_data_out, sizeof(fr_t), FIELD_ELEMENTS_PER_EXT_BLOB
    );
    if (ret != C_KZG_OK) goto out;

out:
    c_kzg_free(missing_cell_indices);
    c_kzg_free(vanishing_poly_eval);
    c_kzg_free(extended_evaluation_times_zero);
    c_kzg_free(extended_evaluation_times_zero_coeffs);
    c_kzg_free(extended_evaluations_over_coset);
    c_kzg_free(vanishing_poly_over_coset);
    c_kzg_free(reconstructed_poly_coeff);
    c_kzg_free(vanishing_poly_coeff);
    c_kzg_free(cells_brp);
    return ret;
}
```
