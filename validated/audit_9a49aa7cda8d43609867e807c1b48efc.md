### No vulnerability found for this question.

**Analysis:** `blob_to_kzg_commitment` calls `blob_to_polynomial` to decode the blob's 4096 field elements, then calls `poly_to_kzg_commitment`, which computes `g1_lincomb_fast(out, s->g1_values_lagrange_brp, poly, FIELD_ELEMENTS_PER_BLOB)` [1](#0-0) . This is a single, deterministic linear combination over the setup's bit-reversal-permuted Lagrange-basis SRS points (`s->g1_values_lagrange_brp`), which by construction of the trusted setup equals the monomial-basis commitment of the same polynomial — this equivalence is a mathematical property of the KZG trusted setup generation (Lagrange SRS points are derived from the same secret `tau` as the monomial SRS points), not something computed twice via two different code paths that could diverge. There is no branch, no basis selection, and no attacker-controlled parameter that changes which computation path executes; the function always uses the same lincomb over the same fixed setup array regardless of blob content.

For an all-zero blob, `blob_to_polynomial` produces 4096 zero `fr_t` scalars, and `g1_lincomb_fast` with all-zero scalars deterministically yields the point at infinity (the additive identity commitment) — the unique, well-defined KZG commitment of the zero polynomial in any basis, since it's simply `0 * g1_values_lagrange_brp[0] + ... + 0 * g1_values_lagrange_brp[4095] = infinity`.

The `get_cell_index()` / JS-double-coercion detail cited in the question target concerns cell-index handling for cell/proof recovery functions (e.g., `recoverCellsAndProofs`/`computeCellsAndKzgProofs`), which is unrelated to `blobToKzgCommitment` — that binding takes only a blob and returns a commitment, with no cell indices involved [2](#0-1) . There is no code path by which that coercion logic could affect `poly_to_kzg_commitment`'s output.

Since there is only one deterministic algorithm computing the commitment (no dual monomial/Lagrange computation paths that could disagree), and the all-zero-blob case trivially reduces to the identity element in any basis, the claimed invariant break does not have a reachable code path. This is a property that holds by mathematical construction of the trusted setup, not a runtime check that could be bypassed by attacker-controlled blob bytes.

### Citations

**File:** src/eip4844/eip4844.c (L253-280)
```c
static C_KZG_RET poly_to_kzg_commitment(g1_t *out, const fr_t *poly, const KZGSettings *s) {
    return g1_lincomb_fast(out, s->g1_values_lagrange_brp, poly, FIELD_ELEMENTS_PER_BLOB);
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param[out]  out     The resulting commitment
 * @param[in]   blob    The blob representing the polynomial to be committed to
 * @param[in]   s       The trusted setup
 */
C_KZG_RET blob_to_kzg_commitment(KZGCommitment *out, const Blob *blob, const KZGSettings *s) {
    C_KZG_RET ret;
    fr_t *poly = NULL;
    g1_t commitment;

    ret = new_fr_array(&poly, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;
    ret = blob_to_polynomial(poly, blob);
    if (ret != C_KZG_OK) goto out;
    ret = poly_to_kzg_commitment(&commitment, poly, s);
    if (ret != C_KZG_OK) goto out;
    bytes_from_g1(out, &commitment);

out:
    c_kzg_free(poly);
    return ret;
}
```

**File:** bindings/node.js/src/kzg.cxx (L1-1)
```text
#include "blst.h"
```
