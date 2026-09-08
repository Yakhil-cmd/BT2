### Title
Integer overflow in the `count` size-check of `verifyBlobKzgProofBatch` bypasses length validation and drives an out-of-bounds read in `verify_blob_kzg_proof_batch` - (File: `bindings/java/ckzg_jni.c`)

### Summary
The Java JNI binding's `verifyBlobKzgProofBatch` computes the expected byte-array sizes by multiplying an attacker/caller-supplied `count` (a signed `jlong`, cast to `size_t`) by the fixed per-item size (`BYTES_PER_BLOB`, `BYTES_PER_COMMITMENT`, `BYTES_PER_PROOF`). Because this multiplication is done in unchecked 64-bit arithmetic, a large or negative `count` value can wrap around and produce a small "expected size" that matches a small, actually-provided array, causing the size-validation checks to spuriously pass. The wrapped/mismatched `count_native` is then forwarded unchanged as `n` to `verify_blob_kzg_proof_batch()`, which trusts `n` to be the true number of elements in the arrays and iterates over `n` elements with no further bounds checking.

### Finding Description
`Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProofBatch` receives `count` as `jlong` and casts it to `size_t`: [1](#0-0) 

The size checks are:
```
size_t count_native = (size_t)count;
size_t blobs_size = (size_t)(*env)->GetArrayLength(env, blobs);
if (blobs_size != count_native * BYTES_PER_BLOB) { ... }
``` [2](#0-1) 

`BYTES_PER_BLOB` is a power of two (`4096 * 32 = 131072 = 2^17`). Because `size_t` arithmetic is modulo `2^64`, any `count_native` value congruent to the intended count modulo `2^64 / 2^17 = 2^47` produces an identical `count_native * BYTES_PER_BLOB` result modulo `2^64`. Consequently a caller/attacker-influenced `count` such as `intended_count + k·2^47` (which still fits comfortably in a signed 64-bit `jlong`) makes `blobs_size != count_native * BYTES_PER_BLOB` evaluate as `false` (i.e., "sizes match") even though `count_native` is wildly larger than the number of blobs actually present in the `blobs` byte array.

If the analogous wrap can be made to also satisfy the `commitments_bytes_size` and `proofs_bytes_size` checks (48-byte elements) via the Chinese Remainder Theorem across the three moduli, all three "size" gates pass with a `count_native` far larger than the real element count. This bypassed `count_native` is passed straight through to the core library: [3](#0-2) 

`verify_blob_kzg_proof_batch()` explicitly documents that it trusts `n` to be the real number of elements and does not itself re-validate buffer sizes: [4](#0-3) 

It then allocates internal arrays sized by `n` and loops `for (size_t i = 0; i < n; i++)` reading `blobs[i]`, `commitments_bytes[i]`, `proofs_bytes[i]` directly from the caller-supplied native pointers: [5](#0-4) 

Since the actual JNI-pinned byte arrays (`blobs_native`, `commitments_native`, `proofs_native`) are only as large as the genuinely-allocated Java arrays, iterating up to the bogus, overflow-passed `n` reads far past the end of these buffers — an out-of-bounds heap read (`CWE-190` → `CWE-787`-adjacent OOB access), matching the size/overflow bug class in the reported PyCA advisory (large values causing size/offset arithmetic to overflow and buffers to be mishandled).

### Impact Explanation
This breaks the equality that the JNI size-check is supposed to enforce: "declared `count` correctly reflects the number of `BYTES_PER_BLOB`/`BYTES_PER_COMMITMENT`/`BYTES_PER_PROOF`-sized elements actually present in the arrays." Once that equality is violated via the overflow, `verify_blob_kzg_proof_batch` reads out-of-bounds memory, which will typically manifest as a segmentation fault / process abort in any Java client relying on this native binding for blob/sidecar verification — i.e., a crash of the node process handling verification, consistent with the "High" impact tier ("one blob or sidecar crashes or aborts every node running this library").

### Likelihood Explanation
Exploitability depends entirely on how the surrounding Java client derives and passes `count` to this native method. If `count` is ever derived from or influenced by externally-supplied data (e.g., a length field associated with a blob/sidecar list) without being cross-checked against the true array length before the JNI call, an attacker only needs to supply a `count` value in the specific residue class described above — well within the range of a `long` — while providing genuinely small `blobs`/`commitments`/`proofs` byte arrays. No multi-gigabyte allocation is required, since the small arrays stay small; only the loop bound is inflated by the wraparound, so this does not fall under the "large allocation" exclusion. Reaching the triple-simultaneous-overflow condition on `blobs_size`, `commitments_bytes_size`, and `proofs_bytes_size` at once is a non-trivial but solvable modular-arithmetic constraint (CRT across the three fixed sizes), which is the main factor limiting immediate exploitability.

### Recommendation
- Validate that `count` is non-negative and within a sane bound (e.g., `count >= 0 && count <= INT32_MAX`) before any multiplication.
- Perform the size checks using overflow-checked multiplication (e.g., check `count_native > SIZE_MAX / BYTES_PER_BLOB` before multiplying, or use compiler overflow-checking builtins) rather than relying on the wraparound-prone `count_native * BYTES_PER_BLOB` comparison.
- Alternatively, derive `count` solely from the verified array lengths (e.g., `blobs_size / BYTES_PER_BLOB`) instead of accepting it as an independent parameter, and then assert that all three derived counts agree.

### Proof of Concept
Conceptual PoC (values illustrative):
1. Compute `k = 2^64 / gcd-based multiples` such that `count = intended_count + k·(2^64 / BYTES_PER_BLOB)` (with `BYTES_PER_BLOB = 2^17`, so `k·2^47`) remains representable as a `long` in Java.
2. Search (via CRT over the three element sizes `BYTES_PER_BLOB=131072`, `BYTES_PER_COMMITMENT=48`, `BYTES_PER_PROOF=48`) for a `count` value that simultaneously satisfies:
   - `blobs_size == (count mod 2^64) * BYTES_PER_BLOB mod 2^64`
   - `commitments_bytes_size == (count mod 2^64) * BYTES_PER_COMMITMENT mod 2^64`
   - `proofs_bytes_size == (count mod 2^64) * BYTES_PER_PROOF mod 2^64`
   for small, genuinely-provided arrays (e.g., 1-blob-sized arrays).
3. Call `CKZG4844JNI.verifyBlobKzgProofBatch(blobs, commitments, proofs, count)` with these small arrays and the crafted large `count`.
4. Expect the size checks at [2](#0-1)  to pass, followed by an out-of-bounds read/crash inside `verify_blob_kzg_proof_batch` at [6](#0-5)  when it iterates `count` elements over buffers only large enough for the intended small count.

### Citations

**File:** bindings/java/ckzg_jni.c (L425-456)
```c
JNIEXPORT jboolean JNICALL
Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProofBatch(
    JNIEnv *env, jclass thisCls, jbyteArray blobs, jbyteArray commitments_bytes,
    jbyteArray proofs_bytes, jlong count) {
  if (settings == NULL) {
    throw_exception(env, TRUSTED_SETUP_NOT_LOADED);
    return 0;
  }

  size_t count_native = (size_t)count;
  size_t blobs_size = (size_t)(*env)->GetArrayLength(env, blobs);
  if (blobs_size != count_native * BYTES_PER_BLOB) {
    throw_invalid_size_exception(env, "Invalid blobs size.", blobs_size,
                                 count_native * BYTES_PER_BLOB);
    return 0;
  }

  size_t commitments_bytes_size =
      (size_t)(*env)->GetArrayLength(env, commitments_bytes);
  if (commitments_bytes_size != count_native * BYTES_PER_COMMITMENT) {
    throw_invalid_size_exception(env, "Invalid commitments size.",
                                 commitments_bytes_size,
                                 count_native * BYTES_PER_COMMITMENT);
    return 0;
  }

  size_t proofs_bytes_size = (size_t)(*env)->GetArrayLength(env, proofs_bytes);
  if (proofs_bytes_size != count_native * BYTES_PER_PROOF) {
    throw_invalid_size_exception(env, "Invalid proofs size.", proofs_bytes_size,
                                 count_native * BYTES_PER_PROOF);
    return 0;
  }
```

**File:** bindings/java/ckzg_jni.c (L458-468)
```c
  Blob *blobs_native = (Blob *)(*env)->GetByteArrayElements(env, blobs, NULL);
  Bytes48 *commitments_native =
      (Bytes48 *)(*env)->GetByteArrayElements(env, commitments_bytes, NULL);
  Bytes48 *proofs_native =
      (Bytes48 *)(*env)->GetByteArrayElements(env, proofs_bytes, NULL);

  bool out;
  C_KZG_RET ret =
      verify_blob_kzg_proof_batch(&out, blobs_native, commitments_native,
                                  proofs_native, count_native, settings);

```

**File:** src/eip4844/eip4844.c (L760-782)
```c
/**
 * Given a list of blobs and blob KZG proofs, verify that they correspond to the provided
 * commitments.
 *
 * @param[out]  ok                  True if the proofs are valid, otherwise false
 * @param[in]   blobs               Array of blobs to verify
 * @param[in]   commitments_bytes   Array of commitments to verify
 * @param[in]   proofs_bytes        Array of proofs used for verification
 * @param[in]   n                   The number of blobs/commitments/proofs
 * @param[in]   s                   The trusted setup
 *
 * @remark This function accepts if called with `n==0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
 */
C_KZG_RET verify_blob_kzg_proof_batch(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    uint64_t n,
    const KZGSettings *s
) {
```

**File:** src/eip4844/eip4844.c (L801-831)
```c
    /* We will need a bunch of arrays to store our objects... */
    ret = new_g1_array(&commitments_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_g1_array(&proofs_g1, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&evaluation_challenges_fr, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&ys_fr, n);
    if (ret != C_KZG_OK) goto out;
    ret = new_fr_array(&poly, FIELD_ELEMENTS_PER_BLOB);
    if (ret != C_KZG_OK) goto out;

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
```
