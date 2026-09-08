[1](#0-0) [2](#0-1)

### Citations

**File:** src/eip7594/eip7594.c (L177-213)
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
```
