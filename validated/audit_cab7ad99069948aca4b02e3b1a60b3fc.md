The premise of this finding is refuted by the existing code. `validate_kzg_g1` in `src/common/bytes.c` explicitly rejects any on-curve point that is not in the correct order-r subgroup: it accepts the point at infinity, but for any non-infinity point it calls `blst_p1_in_g1(out)` and returns `C_KZG_BADARGS` if that check fails [1](#0-0) .

Both `bytes_to_kzg_commitment` and `bytes_to_kzg_proof` — the functions used to deserialize the untrusted commitment and proof bytes before `verify_kzg_proof` performs the pairing check — call `validate_kzg_g1` [2](#0-1) . This means any attacker-supplied proof or commitment bytes representing "an on-curve point outside the order-r G1 subgroup" will fail deserialization and `verify_kzg_proof` will return `C_KZG_BADARGS` before any pairing computation occurs — the point never reaches the pairing check the question describes.

The repository's own test suite explicitly exercises this guard, e.g. `test_validate_kzg_g1__fails_not_in_g1` constructs an on-curve-but-not-in-subgroup point and asserts `C_KZG_BADARGS` [3](#0-2) , and other tests cover various infinity-encoding edge cases (true/false b-flag combinations) all correctly resolving to either `C_KZG_OK` (valid infinity encoding) or `C_KZG_BADARGS` (invalid encodings) [4](#0-3) .

Since the claimed attack input (an on-curve point outside the order-r G1 subgroup) is rejected at the deserialization/validation stage — well before the pairing relation is evaluated — the invariant "*ok == true iff the pairing relation holds" cannot be violated by this input. The equality holds on both sides: before the code runs, the attacker's malformed point is invalid input; after tracing the code, `validate_kzg_g1` returns `C_KZG_BADARGS`, so `verify_kzg_proof` never sets `*ok = true` for this input.

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

**File:** src/common/bytes.c (L103-115)
```c
C_KZG_RET bytes_to_kzg_commitment(g1_t *out, const Bytes48 *b) {
    return validate_kzg_g1(out, b);
}

/**
 * Convert untrusted bytes into a trusted and validated KZGProof.
 *
 * @param[out]  out The output proof
 * @param[in]   b   The proof bytes
 */
C_KZG_RET bytes_to_kzg_proof(g1_t *out, const Bytes48 *b) {
    return validate_kzg_g1(out, b);
}
```

**File:** src/test/tests.c (L565-577)
```c
static void test_validate_kzg_g1__fails_not_in_g1(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "8123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}
```

**File:** src/test/tests.c (L621-661)
```c
static void test_validate_kzg_g1__succeeds_infinity_with_true_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "c00000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_OK);
}

static void test_validate_kzg_g1__fails_infinity_with_true_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "c01000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}

static void test_validate_kzg_g1__fails_infinity_with_false_b_flag(void) {
    C_KZG_RET ret;
    Bytes48 g1_bytes;
    g1_t g1;

    bytes48_from_hex(
        &g1_bytes,
        "800000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000"
    );
    ret = validate_kzg_g1(&g1, &g1_bytes);
    ASSERT_EQUALS(ret, C_KZG_BADARGS);
}
```
