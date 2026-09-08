### Title
Integer-overflow bypass of size validation in `verifyBlobKzgProofBatch` JNI binding leads to out-of-bounds native array access - (File: `bindings/java/ckzg_jni.c`)

### Summary
The Java JNI binding for `verify_blob_kzg_proof_batch` computes expected buffer sizes as `count_native * BYTES_PER_BLOB` (and similarly for commitments/proofs) using unchecked 64-bit multiplication before comparing them against the actual array lengths. A crafted `count` value can make this multiplication wrap around `2^64`, causing the size check to silently pass even though the caller supplied tiny (or empty) arrays, after which the native `verify_blob_kzg_proof_batch` C function is called with the huge, attacker-supplied `count` and iterates far past the bounds of the actual (tiny) buffers.

### Finding Description
`Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProofBatch` validates input sizes like this: [1](#0-0) 

```
size_t count_native = (size_t)count;
size_t blobs_size = (size_t)(*env)->GetArrayLength(env, blobs);
if (blobs_size != count_native * BYTES_PER_BLOB) { ... throw ... }
...
if (commitments_bytes_size != count_native * BYTES_PER_COMMITMENT) { ... throw ... }
...
if (proofs_bytes_size != count_native * BYTES_PER_PROOF) { ... throw ... }
```

`count` is a caller-supplied `jlong` that is not otherwise constrained to match the true array length. Because `BYTES_PER_BLOB` (131072 = 2^17) is a power of two, choosing `count_native = 2^60` makes `count_native * BYTES_PER_BLOB mod 2^64 == 0`. Working through the arithmetic (`BYTES_PER_COMMITMENT`/`BYTES_PER_PROOF` = 48 = 2^4·3), the same `count_native = 2^60` also makes `count_native * 48 mod 2^64 == 0`, so **all three size checks simultaneously wrap to zero**. An attacker (or a buggy caller) supplying zero-length (or otherwise mismatched, small) `blobs`, `commitments_bytes`, and `proofs_bytes` arrays together with `count = 2^60` passes every validation check.

Execution then proceeds to: [2](#0-1) 

where `verify_blob_kzg_proof_batch` is invoked with `count_native = 2^60` against pointers backed by essentially empty JVM arrays. The native C function (`src/eip4844/eip4844.c`) will then read/iterate `count_native` blob/commitment/proof-sized elements from memory that does not actually exist, causing an out-of-bounds read and process abort/crash (or memory corruption) well before any pairing check occurs.

This breaks the intended equality that "the size of every array supplied to the native verifier corresponds exactly to `count`" — the binding's own validation is defeated by the overflow, so the count used to drive native array traversal no longer matches the true buffer size, i.e., **a count that differs between what the binding validated and what the C function actually consumes**.

### Impact Explanation
This can crash or abort the Java-based JNI consumer process (High-impact per the given classification: "one blob or sidecar crashes or aborts every node running this library") because the native read walks off the end of a JVM byte array into unrelated / unmapped memory, triggering a JVM segfault. It does not involve resource exhaustion, slow inputs, or unbounded loops — it is a discrete size-check bypass via integer overflow, structurally analogous to the Tomcat `parseChunkHeader` integer overflow (CVE-2014-0075), where an internal size/count value was allowed to overflow and defeat a bounds check.

### Likelihood Explanation
Exploitability depends on how the calling application obtains and passes `count`. In the reference test harness and typical usage, `count` is derived directly from `array.length / BYTES_PER_BLOB`, in which case this specific overflow cannot occur because the actual array length would need to be astronomically large (petabytes) to match. The bug becomes reachable only if a consumer of the JNI API passes a `count` value that is not tied to the real length of the arrays it supplies (e.g., a value taken from an untrusted source separately from the array size) — which would itself be a caller-side integrity violation. I was not able to fully verify, within the available context, whether any current binding call site derives `count` independently from array length in a way that untrusted network input could reach this path; the Java-side wrapper class (`CKZG4844JNI.java`) that exposes this native method was not available in the indexed content to confirm.

### Recommendation
Guard the multiplications in `Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProofBatch` (and the analogous `verifyCellKzgProofBatch`) against overflow before comparing to actual array lengths — e.g., check `count_native > SIZE_MAX / BYTES_PER_BLOB` first, or derive `count` internally from the actual array length divided by the element size rather than trusting a separately supplied `count` parameter, consistent with how the Python (`bindings/python/ckzg_wrap.c`) and Node.js bindings derive counts from array/list lengths.

### Proof of Concept
1. Call `CKZG4844JNI.verifyBlobKzgProofBatch(new byte[0], new byte[0], new byte[0], 1152921504606846976L /* 2^60 */)`.
2. `count_native = 2^60`; `count_native * BYTES_PER_BLOB mod 2^64 == 0`, `count_native * BYTES_PER_COMMITMENT mod 2^64 == 0`, `count_native * BYTES_PER_PROOF mod 2^64 == 0`.
3. All three `GetArrayLength(...) != count_native * BYTES_PER_X` checks in `bindings/java/ckzg_jni.c` (lines 434-456) evaluate `0 != 0`, i.e. false, so no exception is thrown.
4. `verify_blob_kzg_proof_batch` is called with `count = 2^60` against zero-length backing arrays, causing native out-of-bounds reads and a JVM crash. [3](#0-2)

### Citations

**File:** bindings/java/ckzg_jni.c (L425-467)
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
