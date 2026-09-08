The evidence is conclusive. The equality to verify is: does `recover_cells_and_kzg_proofs` reject non-ascending/duplicate `cell_indices` **before** any write to `recovered_cells_fr`? Tracing the code confirms it does.

### Title
No vulnerability — strict-ascending/bounds check on `cell_indices` in `recover_cells_and_kzg_proofs` executes fully before any write to `recovered_cells_fr` - (File: src/eip7594/eip7594.c)

### Summary
The validation loop that checks `cell_indices[i] >= CELLS_PER_EXT_BLOB` and strict ascending order runs to completion, with `goto out` on any violation, entirely before `recovered_cells_fr` is allocated or written. A cell index of `127` (`CELLS_PER_EXT_BLOB - 1`) is a valid, in-bounds value and does not bypass this check; a non-ascending or duplicate sequence containing it is still rejected with `C_KZG_BADARGS`.

### Finding Description
In `recover_cells_and_kzg_proofs` [1](#0-0) , this loop is executed immediately after the `num_cells` bounds checks and unconditionally before `new_fr_array(&recovered_cells_fr, ...)` is even called [2](#0-1) . Since `goto out` jumps past all allocation and population logic, no read/write of `recovered_cells_fr` (which is `NULL` at that point) can occur if the index-ordering check fails. A cell index equal to `127` = `CELLS_PER_EXT_BLOB - 1` is simply the largest legal value and is treated like any other index by both checks — it does not disable or skip them.

This is directly confirmed by the reference test vectors bundled in the repo: `recover_cells_and_kzg_proofs_case_invalid_cell_index` (index 128, out of bounds), `recover_cells_and_kzg_proofs_case_invalid_duplicate_cell_index` (indices `[1,1,2,...]`, non-ascending), `recover_cells_and_kzg_proofs_case_invalid_shuffled_half_missing` and `..._shuffled_no_missing` (shuffled/non-ascending orderings including index 127) all expect no output (i.e., rejection). The C unit test `test_recover_cells_and_kzg_proofs__succeeds_random_blob` [3](#0-2)  exercises the valid-input path for contrast.

The Elixir NIF (`ckzg_wrap.c`) and `lib/kzg.ex` binding merely marshal the Elixir list of cell indices/cells into the C arrays and call `recover_cells_and_kzg_proofs` with `num_cells` derived from the list length [4](#0-3) ; the binding introduces no additional attacker-controlled path that could reorder or bypass the C-level validation loop.

### Impact Explanation
No divergence, crash, or memory corruption occurs. An attacker submitting a blob/cell-index sequence with cell index `127` in a non-ascending or duplicated position simply receives `C_KZG_BADARGS` (mapped to an `{:error, atom()}` in the Elixir binding) before any allocation or write to `recovered_cells_fr`. This matches the intended behavior across all client bindings and does not create a Critical or High severity condition per the stated impact categories.

### Likelihood Explanation
Not applicable — there is no exploitable condition. The check is unconditional, runs first, and is exercised by the project's own test vectors for exactly this scenario (including sequences containing index 127).

### Recommendation
No fix required. Optionally, consider adding an explicit unit/binding-level regression test in `bindings/elixir/test/ckzg_test.exs` that submits a non-ascending sequence ending in/containing cell index `127` to `KZG.recover_cells_and_kzg_proofs` and asserts `{:error, _}` is returned, to make the invariant explicit at the binding layer (mirroring the existing C-level YAML test vectors).

### Proof of Concept
Not applicable (no vulnerability). For verification, the existing test vectors already cover this exact class of input:
- `tests/recover_cells_and_kzg_proofs/kzg-mainnet/recover_cells_and_kzg_proofs_case_invalid_duplicate_cell_index/data.yaml` — duplicate/non-ascending indices, expects rejection.
- `tests/recover_cells_and_kzg_proofs/kzg-mainnet/recover_cells_and_kzg_proofs_case_invalid_shuffled_no_missing/data.yaml` and `..._shuffled_one_missing/data.yaml` — shuffled orderings including index 127, expect rejection.

A minimal C-level assertion mirroring these:
```c
uint64_t cell_indices[CELLS_PER_EXT_BLOB] = {1, 1, 2, 3, /* ... */ 127};
Cell cells[CELLS_PER_EXT_BLOB];
Cell recovered_cells[CELLS_PER_EXT_BLOB];
KZGProof recovered_proofs[CELLS_PER_EXT_BLOB];
C_KZG_RET ret = recover_cells_and_kzg_proofs(
    recovered_cells, recovered_proofs, cell_indices, cells, CELLS_PER_EXT_BLOB, &s);
ASSERT_EQUALS(ret, C_KZG_BADARGS); /* recovered_cells_fr must never have been written */
```

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

**File:** src/eip7594/eip7594.c (L215-219)
```c
    /* Do allocations */
    ret = new_fr_array(&recovered_cells_fr, FIELD_ELEMENTS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&recovered_proofs_g1, CELLS_PER_EXT_BLOB);
    if (ret != C_KZG_OK) goto out;
```

**File:** src/test/tests.c (L1897-1935)
```c
static void test_recover_cells_and_kzg_proofs__succeeds_random_blob(void) {
    C_KZG_RET ret;
    Blob blob;
    const size_t num_partial_cells = CELLS_PER_EXT_BLOB / 2;
    uint64_t cell_indices[CELLS_PER_EXT_BLOB];
    Cell cells[CELLS_PER_EXT_BLOB];
    Cell partial_cells[num_partial_cells];
    Cell recovered_cells[CELLS_PER_EXT_BLOB];
    KZGProof proofs[CELLS_PER_EXT_BLOB];
    KZGProof recovered_proofs[CELLS_PER_EXT_BLOB];
    int diff;

    /* Get a random blob */
    get_rand_blob(&blob);

    /* Get the cells and proofs */
    ret = compute_cells_and_kzg_proofs(cells, proofs, &blob, &s);
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Erase half of the cells */
    for (size_t i = 0; i < num_partial_cells; i++) {
        cell_indices[i] = i * 2;
        memcpy(&partial_cells[i], &cells[cell_indices[i]], sizeof(Cell));
    }

    /* Reconstruct with half of the cells */
    ret = recover_cells_and_kzg_proofs(
        recovered_cells, recovered_proofs, cell_indices, partial_cells, num_partial_cells, &s
    );
    ASSERT_EQUALS(ret, C_KZG_OK);

    /* Check that all of the cells match */
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        diff = memcmp(&cells[i], &recovered_cells[i], sizeof(Cell));
        ASSERT_EQUALS(diff, 0);
        diff = memcmp(&proofs[i], &recovered_proofs[i], sizeof(KZGProof));
        ASSERT_EQUALS(diff, 0);
    }
}
```

**File:** bindings/elixir/lib/kzg.ex (L250-254)
```elixir
  @spec recover_cells_and_kzg_proofs([non_neg_integer()], [binary], settings) ::
          {:ok, [binary()], [binary()]} | {:error, atom()}
  def recover_cells_and_kzg_proofs(_cell_indices, _cells, _settings) do
    :erlang.nif_error(:not_loaded)
  end
```
