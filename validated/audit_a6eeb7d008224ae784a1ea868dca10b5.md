`new_f_array` uses `c_kzg_calloc`, which calls the standard `calloc()` function. The `calloc()` function zeros all allocated memory. Therefore, `poly_monomial` is initialized to all zeros at line 77 of `eip7594.c`.

Let me trace the exact code path:

**Equality to validate:**
```
poly_monomial[i] == FR_ZERO for all i in [FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_EXT_BLOB)
```

**Code path from attacker-supplied blob bytes:**

1. **Line 88** (`blob_to_polynomial`): Attacker-supplied blob bytes are deserialized into `poly_lagrange[0..FIELD_ELEMENTS_PER_BLOB-1]` via `bytes_to_bls_field()`. The upper half `poly_lagrange[FIELD_ELEMENTS_PER_BLOB..FIELD_ELEMENTS_PER_EXT_BLOB-1]` is **never written to** and remains zero (from `new_fr_array` calloc).

2. **Line 92** (`poly_lagrange_to_monomial`): 
   - Line 69 of `poly.c`: `memcpy(lagrange_brp, lagrange, sizeof(fr_t) * len)` copies the entire `len` (which is `FIELD_ELEMENTS_PER_BLOB` from line 92 of `eip7594.c`) elements. This copies only the first 4096 elements.
   - Line 70 of `poly.c`: `bit_reversal_permutation(lagrange_brp, sizeof(fr_t), len)` bit-reverses only `len` elements.
   - Line 74 of `poly.c`: `fr_ifft(monomial_out, lagrange_brp, len, s)` performs inverse FFT on `len` elements.

3. **The IFFT operation**: The inverse FFT is performed on a polynomial of size `FIELD_ELEMENTS_PER_BLOB` (4096), not `FIELD_ELEMENTS_PER_EXT_BLOB` (8192). The output `monomial_out` (which is `poly_monomial`) is written to by `fr_ifft()`.

Let me check the FFT implementation to understand what it writes: