### Title
Integer overflow in `count * BYTES_PER_BLOB`/`BYTES_PER_COMMITMENT`/`BYTES_PER_PROOF` size checks lets attacker-controlled `count` bypass array-length validation, causing an out-of-bounds read - ([File: bindings/java/ckzg_jni.c])

### Summary
`Java_ethereum_ckzg4844_CKZG4844JNI_verifyBlobKzgProofBatch` validates array sizes by comparing the real JVM array length against `count_native * BYTES_PER_BLOB` (and the analogous commitment/proof products) computed in `size_t`, without any overflow check. Because `BYTES_PER_BLOB` (131072 = 2^17) and `BYTES_PER_COMMITMENT`/`BYTES_PER_PROOF` (48) are constants and `size_t` arithmetic wraps modulo 2^64 on 64-bit platforms, an attacker can choose a `count` value that makes all three products wrap to 0 (or to some small number) while supplying tiny/empty arrays, so the checks pass and `verify_blob_kzg_proof_batch` is then invoked with a huge `count_native` against tiny buffers.

### Finding Description
The broken equality is: **BOUNDS TRUTH** — the check at [1](#0-0)  asserts `blobs_size == count_native * BYTES_PER_BLOB`, intending to guarantee `count_native` blob-sized reads all stay within the real buffer. Because the multiplication is unchecked `size_t` arithmetic, this equality can hold even when `count_native` is astronomically larger than the number of blobs the buffer can actually hold, because the product wraps around 2^64.

Concretely: pick `count = 2^60` (a valid positive `jlong`, well within `jlong`'s range). Then:
- `count_native * BYTES_PER_BLOB = 2^60 * 2^17 = 2^77 ≡ 0 (mod 2^64)`
- `count_native * BYTES_PER_COMMITMENT = 2^60 * 48 = 2^65 + 2^64 ≡ 0 (mod 2^64)`
- `count_native * BYTES_PER_PROOF` is the same as the commitment case ≡ 0

So an attacker supplies `blobs`, `commitments_bytes`, `proofs_bytes` as **empty (zero-length) byte arrays** together with `count = 2^60`. All three checks at [2](#0-1)  compare `0 == 0` and pass. `GetByteArrayElements` then returns pointers backed by zero-length (or trivially small) buffers [3](#0-2) , and `verify_blob_kzg_proof_batch` is called with `count_native = 2^60` [4](#0-3) , causing the native routine to iterate `count_native` blob/commitment/proof-sized chunks over buffers that hold none — an out-of-bounds read reachable with a single, cheap, fully attacker-controlled JNI call.

No guard in the JNI layer performs an overflow-checked multiplication or bounds `count` against a sane maximum before this arithmetic; nothing downstream (`verify_blob_kzg_proof_batch`) re-validates that the supplied buffer sizes are consistent with `n`, since that responsibility is delegated entirely to the binding's size check, which is broken here.

### Impact Explanation
This is a High-severity finding: a single attacker-supplied JNI call (`count`, plus empty/undersized `blobs`/`commitments_bytes`/`proofs_bytes` arrays) passes the binding's own bounds check due to unchecked `size_t` multiplication overflow, and then drives `verify_blob_kzg_proof_batch` to read far past the end of near-empty native buffers. This is a memory-corruption / crash primitive reachable from a single call on any node using the Java binding — an availability issue affecting every such node identically (not a consensus-divergence/forgery issue, but a crash/UB issue), matching the "High" impact category (memory corruption/crash reachable from attacker input).

### Likelihood Explanation
- Preconditions: 64-bit `size_t` build (the common case for the Java JNI binding on modern JVMs/OSes), reachable directly through the public `verifyBlobKzgProofBatch` JNI entry point.
- Attacker cost: trivial — no need to allocate huge arrays; the exploit uses `count = 2^60` and *empty* arrays, which are cheap to construct.
- Repeatable: yes, deterministic and reproducible on any node exposing this JNI call with the same setup.
- The scenario described in the question ("32-bit size_t" or "overflow of size_t") is confirmed feasible even on ordinary 64-bit platforms because `BYTES_PER_BLOB`, `BYTES_PER_COMMITMENT`, and `BYTES_PER_PROOF` are powers of two (or small multiples thereof), letting the multiplication wrap exactly to 0 for a conveniently sized `count` well within `jlong`'s legal range.

### Recommendation
Perform overflow-checked arithmetic before comparing to the JVM-reported array length, e.g. reject `count` if `count_native > SIZE_MAX / BYTES_PER_BLOB` (and similarly for `BYTES_PER_COMMITMENT`/`BYTES_PER_PROOF`) before computing the product, or compute `blobs_size / BYTES_PER_BLOB` and compare to `count_native` instead of multiplying `count_native` by the per-item size. Apply the same fix to all other JNI batch-size checks in `ckzg_jni.c` that multiply an attacker-controlled `count`/`n` by a byte-size constant (e.g., `verifyCellKzgProofBatch`, `recoverCellsAndKzgProofs` equivalents), and additionally clamp `count` to a sane maximum (e.g., `< INT32_MAX`) since JVM array lengths can never exceed `Integer.MAX_VALUE`.

### Proof of Concept
JNI test:
1. Load a trusted setup, call `CKZG4844JNI.loadTrustedSetup(...)`.
2. Construct `blobs = new byte[0]`, `commitments_bytes = new byte[0]`, `proofs_bytes = new byte[0]`.
3. Call `verifyBlobKzgProofBatch(blobs, commitments_bytes, proofs_bytes, 1152921504606846976L /* 2^60 */)`.
4. Assert on the C side (or via a native harness) that the length checks in `ckzg_jni.c` (`blobs_size != count_native * BYTES_PER_BLOB`, etc.) incorrectly evaluate `0 == 0` and do NOT throw `InvalidSizeException`, and that `verify_blob_kzg_proof_batch` is invoked with `count_native == 2^60` against zero-length native buffers, producing an out-of-bounds read (observable as a crash/segfault or via AddressSanitizer flagging heap-buffer-overflow on `blobs_native`/`commitments_native`/`proofs_native` access).
5. Correct behavior: the binding should throw an exception rejecting the mismatched/overflowing `count` before calling into `verify_blob_kzg_proof_batch`.

### Citations

**File:** bindings/java/ckzg_jni.c (L434-455)
```c
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
```

**File:** bindings/java/ckzg_jni.c (L458-462)
```c
  Blob *blobs_native = (Blob *)(*env)->GetByteArrayElements(env, blobs, NULL);
  Bytes48 *commitments_native =
      (Bytes48 *)(*env)->GetByteArrayElements(env, commitments_bytes, NULL);
  Bytes48 *proofs_native =
      (Bytes48 *)(*env)->GetByteArrayElements(env, proofs_bytes, NULL);
```

**File:** bindings/java/ckzg_jni.c (L464-467)
```c
  bool out;
  C_KZG_RET ret =
      verify_blob_kzg_proof_batch(&out, blobs_native, commitments_native,
                                  proofs_native, count_native, settings);
```
