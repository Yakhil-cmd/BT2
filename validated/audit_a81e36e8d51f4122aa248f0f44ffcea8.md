### No vulnerability found for this question.

**Reasoning:**

The claimed exploit requires that grouping duplicate `cell_indices` before interpolation breaks the correspondence between the per-position weighted commitments and the per-position weighted interpolation polynomials. This does not hold because every relevant transformation involved is **linear**, so grouping is purely a computational optimization, not a soundness-affecting change.

Trace through `verify_cell_kzg_proof_batch` (`src/eip7594/eip7594.c:840-974`):

1. **No dedup of `cell_indices`** — only a bounds check exists [1](#0-0) , confirming duplicates are structurally possible, as the question assumes.

2. **Column aggregation is linear.** For position `i` with `cell_indices[i] = k`, the code adds `r_powers[i] * data_i` into `aggregated_column_cells[k]` via `fr_add`/`fr_mul` [2](#0-1) . Since `fr_ifft` is a linear operator, `IDFT(r_powers[0]*data0 + r_powers[1]*data1) = r_powers[0]*IDFT(data0) + r_powers[1]*IDFT(data1)` exactly [3](#0-2) . So the "aggregated interpolation polynomial" for a duplicated column is mathematically identical to the sum of the two individually-weighted interpolation polynomials — no cross term is lost or corrupted.

3. **Commitment linearity matches.** `g1_lincomb_fast` over the aggregated polynomial [4](#0-3)  commits to that same linear combination, because KZG commitment is itself linear in the SRS. On the other side, `compute_weighted_sum_of_commitments` sums `r_powers[i]` per position against the (deduplicated) actual commitment bytes at that position [5](#0-4) , which is computed independently of `cell_indices` duplication and depends only on the raw `commitments_bytes` per position.

4. **Net effect:** the whole `final_g1_sum` / `proof_lincomb` construction reduces to `sum_i r^i * (individual per-position KZG opening equation for cell i)`, exactly the standard Fiat–Shamir random-linear-combination batch-verification technique. Duplicating `cell_indices` at two positions `i,j` (with independent, possibly conflicting cell bytes) does not merge or cancel their contributions asymmetrically — it just means both individual per-position equations are folded into the same random sum, as they would be for any two positions regardless of whether they share a `cell_index`.

5. **Soundness argument holds regardless of duplicates.** If any one of the `num_cells` per-position openings is invalid, by the Schwartz–Zippel lemma the random combination can only cancel with negligible probability over the choice of `r`. Crucially, `r` is derived via `compute_verify_cell_kzg_proof_batch_challenge` from a transcript that already includes `cell_indices`, `cells`, and `proofs_bytes` [6](#0-5) , so the attacker cannot choose conflicting cell content *after* seeing `r` — `r` is fixed by hashing exactly the bytes the attacker is trying to exploit, precluding any chosen-collision strategy to align duplicate/conflicting cells favorably.

Therefore the equality "aggregated_interpolation_poly commitment corresponds to a single consistent interpolation" is not actually required for soundness — the real invariant is "the pairing check equals the random linear combination of n independent per-position KZG equations," which remains intact whether or not `cell_indices` repeat. No forged/conflicting cell content can pass verification through this path without breaking the discrete-log/KZG binding assumption itself, which is out of scope per the rules (no defect in blst/KZG binding is claimed or found).

### Citations

**File:** src/eip7594/eip7594.c (L676-686)
```c
            fr_mul(&scaled_fr, &original_fr, &r_powers[cell_index]);

            /* Figure out the right index for this field element within the extended array */
            size_t array_index = column_index * FIELD_ELEMENTS_PER_CELL + fr_index;
            /* Aggregate the scaled field element into the array */
            fr_add(
                &aggregated_column_cells[array_index],
                &aggregated_column_cells[array_index],
                &scaled_fr
            );
        }
```

**File:** src/eip7594/eip7594.c (L712-751)
```c
    /* Interpolate each column */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        /* We can skip columns without any cells */
        if (!is_cell_used[i]) continue;

        /* Offset to the first cell for this column */
        size_t index = i * FIELD_ELEMENTS_PER_CELL;

        /*
         * Reach into the big array and permute the right column.
         * No need to copy the data, we are not gonna use them again.
         */
        ret = bit_reversal_permutation(
            &aggregated_column_cells[index], sizeof(fr_t), FIELD_ELEMENTS_PER_CELL
        );
        if (ret != C_KZG_OK) goto out;

        /*
         * Get interpolation polynomial for this column. To do so we first do an IDFT over the roots
         * of unity and then we scale the coefficients by the coset factor. We can't do an IDFT
         * directly over the coset because it's not a subgroup.
         */
        ret = fr_ifft(
            column_interpolation_poly, &aggregated_column_cells[index], FIELD_ELEMENTS_PER_CELL, s
        );
        if (ret != C_KZG_OK) goto out;

        /* Shift the poly by h_k^{-1} where h_k is the coset factor for this cell */
        fr_t inv_coset_factor;
        get_inv_coset_shift_for_cell(&inv_coset_factor, i, s);
        shift_poly(column_interpolation_poly, FIELD_ELEMENTS_PER_CELL, &inv_coset_factor);

        /* Update the aggregated poly */
        for (size_t k = 0; k < FIELD_ELEMENTS_PER_CELL; k++) {
            fr_add(
                &aggregated_interpolation_poly[k],
                &aggregated_interpolation_poly[k],
                &column_interpolation_poly[k]
            );
        }
```

**File:** src/eip7594/eip7594.c (L758-764)
```c
    ret = g1_lincomb_fast(
        commitment_out,
        s->g1_values_monomial,
        aggregated_interpolation_poly,
        FIELD_ELEMENTS_PER_CELL
    );
    if (ret != C_KZG_OK) goto out;
```

**File:** src/eip7594/eip7594.c (L861-864)
```c
    for (size_t i = 0; i < num_cells; i++) {
        /* Make sure column index is valid */
        if (cell_indices[i] >= CELLS_PER_EXT_BLOB) return C_KZG_BADARGS;
    }
```

**File:** src/eip7594/eip7594.c (L898-908)
```c
    ret = compute_verify_cell_kzg_proof_batch_challenge(
        &r,
        unique_commitments,
        num_commitments,
        commitment_indices,
        cell_indices,
        cells,
        proofs_bytes,
        num_cells
    );
    if (ret != C_KZG_OK) goto out;
```

**File:** src/eip7594/eip7594.c (L933-936)
```c
    ret = compute_weighted_sum_of_commitments(
        &final_g1_sum, unique_commitments, commitment_indices, r_powers, num_commitments, num_cells
    );
    if (ret != C_KZG_OK) goto out;
```
