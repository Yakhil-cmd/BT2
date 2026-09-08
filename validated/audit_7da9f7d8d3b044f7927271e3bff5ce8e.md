### No vulnerability found for this question.

**Analysis**: The code exactly matches the safe behavior the question tests for. The validation loop at [1](#0-0)  calls `bytes_to_bls_field` on every field element of every provided cell into the *local* `recovered_cells_fr` buffer, writing into `recovered_cells_fr[index + j]` where `index = cell_indices[i] * FIELD_ELEMENTS_PER_CELL`. The bounds check at [2](#0-1)  only guarantees `cell_indices[i] < CELLS_PER_EXT_BLOB` and strict ascending order — it does not validate the field-element bytes themselves, so a non-canonical field element (≥ modulus) in a later cell can indeed cause `bytes_to_bls_field` to return `C_KZG_BADARGS` after earlier cells have already been converted and written into `recovered_cells_fr`.

However, that mutation is confined entirely to the locally-allocated `recovered_cells_fr` array (`new_fr_array` at [3](#0-2) ). The caller-visible output arrays `recovered_cells` and `recovered_proofs` are only written *after* this validation loop completes successfully — at [4](#0-3)  for `recovered_cells`, and at [5](#0-4)  for `recovered_proofs`. On failure, control jumps to `goto out` at [6](#0-5) , which reaches the `out:` label that frees `recovered_cells_fr`, `recovered_proofs_g1`, and `recovered_proofs_affine` — [7](#0-6)  — and returns `C_KZG_BADARGS` without ever touching the caller's output buffers.

Since the equality "state already mutated implies caller-visible corruption" does not hold — the mutated state is a private, freed scratch buffer, never propagated to `recovered_cells`/`recovered_proofs` — there is no forged/accepted invalid data, no cross-node divergence, and no memory-safety issue. The partial mutation is fully and safely discarded exactly as the question's proof idea anticipates.

### Citations

**File:** src/eip7594/eip7594.c (L202-213)
```c
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
```

**File:** src/eip7594/eip7594.c (L216-217)
```c
    ret = new_fr_array(&recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
```

**File:** src/eip7594/eip7594.c (L227-236)
```c
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
```

**File:** src/eip7594/eip7594.c (L238-262)
```c
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
```

**File:** src/eip7594/eip7594.c (L264-296)
```c
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
```

**File:** src/eip7594/eip7594.c (L299-303)
```c
out:
    c_kzg_free(recovered_cells_fr);
    c_kzg_free(recovered_proofs_g1);
    c_kzg_free(recovered_proofs_affine);
    return ret;
```
