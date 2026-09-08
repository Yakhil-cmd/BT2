## No vulnerability found for this question.

**Analysis:**

The claimed invariant is: `verify_blob_kzg_proof_batch(..., n=0) == reference_verdict_for_empty_batch` (vacuously true). Tracing this in the code confirms the invariant holds and is explicitly documented, not accidental.

In `src/eip4844/eip4844.c`, `verify_blob_kzg_proof_batch` explicitly short-circuits:
```c
/* Exit early if we are given zero blobs */
if (n == 0) {
    *ok = true;
    return C_KZG_OK;
}
``` [1](#0-0) 

This is documented in the function's docstring as intended behavior: `@remark This function accepts if called with n==0.` [2](#0-1) 

On the Zig binding side, `Settings.verifyBlobKzgProofBatch` only returns `error.LengthMismatch` when the three slice lengths differ from each other; it does not reject zero-length slices, so an all-empty call (`blobs.len == commitments_bytes.len == proofs_bytes.len == 0`) proceeds to call `c.verify_blob_kzg_proof_batch` with `n = 0` and null pointers (since `sliceConstPtr` returns `null` for empty slices):
```zig
if (blobs.len != commitments_bytes.len or blobs.len != proofs_bytes.len) {
    return error.LengthMismatch;
}
var ok = false;
try checkRet(c.verify_blob_kzg_proof_batch(&ok, sliceConstPtr(Blob, blobs), ..., blobs.len, &self.inner));
return ok;
``` [3](#0-2) [4](#0-3) 

Both before and after tracing: the `n == 0` branch returns `ok = true` with `C_KZG_OK`, no array is read, no `assert` is triggered (the `assert(n > 0)` guard lives only in the inner `verify_kzg_proof_batch` helper, which is never reached when `n == 0`) [5](#0-4) , and this matches the Ethereum consensus-spec reference behavior where an empty batch of universally-quantified checks is vacuously true — the same behavior other implementations (Constantine, Rust-Eth-KZG) are expected to follow per the spec. The scenario detail about "a 128-cell batch all mapped to one column" describes `verify_cell_kzg_proof_batch`/column-mapping semantics, which is unrelated to and does not interact with this `n == 0` blob-batch short-circuit — it doesn't apply here and introduces no additional attack surface for this specific invariant.

No divergence between the two sides of the equality was found; the short-circuit is intentional, documented, and consistent with the reference specification.

### Citations

**File:** src/eip4844/eip4844.c (L712-712)
```c
    assert(n > 0);
```

**File:** src/eip4844/eip4844.c (L771-774)
```c
 * @remark This function accepts if called with `n==0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
 */
```

**File:** src/eip4844/eip4844.c (L790-794)
```c
    /* Exit early if we are given zero blobs */
    if (n == 0) {
        *ok = true;
        return C_KZG_OK;
    }
```

**File:** bindings/zig/src/root.zig (L147-168)
```text
    pub fn verifyBlobKzgProofBatch(
        self: *const Settings,
        blobs: []const Blob,
        commitments_bytes: []const Bytes48,
        proofs_bytes: []const Bytes48,
    ) !bool {
        try self.ensureLoaded();
        if (blobs.len != commitments_bytes.len or blobs.len != proofs_bytes.len) {
            return error.LengthMismatch;
        }

        var ok = false;
        try checkRet(c.verify_blob_kzg_proof_batch(
            &ok,
            sliceConstPtr(Blob, blobs),
            sliceConstPtr(Bytes48, commitments_bytes),
            sliceConstPtr(Bytes48, proofs_bytes),
            blobs.len,
            &self.inner,
        ));
        return ok;
    }
```

**File:** bindings/zig/src/root.zig (L262-264)
```text
fn sliceConstPtr(comptime T: type, slice: []const T) [*c]const T {
    return if (slice.len == 0) null else slice.ptr;
}
```
