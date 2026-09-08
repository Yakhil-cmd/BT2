### Title
Integer overflow in C# binding's length validation allows out-of-bounds native buffer access in `VerifyBlobKzgProofBatch` - (File: bindings/csharp/Ckzg.Bindings/Ckzg.cs)

### Summary
The C# binding computes the expected buffer size for the batch verification arrays using an unchecked `int` multiplication (`BytesPerBlob * count`, etc.). Because C# integer arithmetic is unchecked by default, a sufficiently large `count` silently wraps around to a small value, causing the length-validation check to pass for undersized buffers while the wrapped-around/oversized `count` is still forwarded to the native `verify_blob_kzg_proof_batch` C function, which then reads `count` blobs/commitments/proofs from buffers that are far too small.

### Finding Description
`VerifyBlobKzgProofBatch` validates its inputs like this: [1](#0-0) 

The checks call `ThrowOnInvalidLength(blobs, nameof(blobs), BytesPerBlob * count)` (and similarly for `commitments`/`proofs`) where `BytesPerBlob = 4096 * 32 = 131072` is an `int` constant and `count` is a caller-supplied `int`. In C#, arithmetic on `int` operands is unchecked by default (no `checked` block or compiler `/checked+` flag is used anywhere in this file), so `BytesPerBlob * count` silently overflows and wraps modulo 2^32 once `count` is large enough (e.g. `count ≈ 32768` makes `131072 * 32768 = 2^32 ≡ 0`). If the wrapped product ends up smaller than or equal to the actual span length, the length check spuriously passes, while `count` — cast to `UInt64` unchanged — is still passed straight through to the native function: [2](#0-1) 

`verify_blob_kzg_proof_batch` in the C core then iterates `for (size_t i = 0; i < n; i++)` over the caller-provided `n` (here the huge, unwrapped `count`) and dereferences `blobs[i]`, `commitments_bytes[i]`, `proofs_bytes[i]` for every index up to `n`, without any bound derived from the actual buffer size: [3](#0-2) 

The function's own contract explicitly states it trusts the caller to supply arrays that truly contain `n` elements: [4](#0-3) 

The C# binding is the layer responsible for enforcing that contract, and its overflowed size check breaks it — the "verified" invariant `len(blobs) == BytesPerBlob * count` no longer holds once the multiplication wraps, yet the mismatched `count` still reaches the C function.

### Impact Explanation
This breaks the equality the length check is meant to guarantee (`buffer length == count × element size`) via an unchecked-arithmetic overflow, closely mirroring the reported bug class (an unchecked multiplication used in an equation bypassing a safety check). The consequence here is an out-of-bounds read across `blobsPtr`, `commitmentsPtr`, and `proofsPtr` inside pinned memory, which can crash the hosting process (segfault/abort) or read adjacent heap/stack memory into the pairing computation, producing a verification outcome derived from attacker-uncontrolled memory rather than the intended inputs. A crash reachable via a single malformed batch-verification call on any node using this binding aligns with the High-impact class ("one blob or sidecar crashes or aborts every node running this library").

### Likelihood Explanation
Exploitability depends on how the embedding client derives `count` versus the actual byte-span lengths passed into this API. If any C# consumer of `Ckzg.VerifyBlobKzgProofBatch` derives `count` from an attacker-influenced field (e.g., a declared sidecar/blob count in a network message) independently of the actual buffer length it allocates, a malicious peer could trigger the overflow deliberately. This requires `count` to be large (≥ ~16384) to trigger the wrap, which is a specific but not unreasonable value to smuggle into a length field.

### Recommendation
Perform the size computation using 64-bit/checked arithmetic (e.g., `(long)BytesPerBlob * count` or wrap the multiplication in a `checked` block) before comparing against the actual span length, and reject negative or absurdly large `count` values prior to computing the expected length. Apply the same fix to all `ThrowOnInvalidLength(..., BytesPerX * count)` call sites in this file.

### Proof of Concept
1. Call `Ckzg.VerifyBlobKzgProofBatch(blobs, commitments, proofs, count: 32768, ckzgSetup)` where `blobs`, `commitments`, and `proofs` are each a zero-length (or minimally sized) `Span<byte>`.
2. `BytesPerBlob * count` = `131072 * 32768` = `2^32`, which wraps to `0` as a 32-bit `int`.
3. `ThrowOnInvalidLength(blobs, "blobs", 0)` passes because the supplied span length (0) matches the wrapped expected length (0).
4. `VerifyBlobKzgProofBatch(out result, blobsPtr, commitmentsPtr, proofsPtr, (UInt64)32768, ckzgSetup)` is invoked, and the native `verify_blob_kzg_proof_batch` loop reads 32768 `Blob`/`Bytes48` entries from buffers that contain zero elements, causing an out-of-bounds read/crash. [1](#0-0)

### Citations

**File:** bindings/csharp/Ckzg.Bindings/Ckzg.cs (L186-201)
```csharp
    public static unsafe bool VerifyBlobKzgProofBatch(ReadOnlySpan<byte> blobs, ReadOnlySpan<byte> commitments,
        ReadOnlySpan<byte> proofs, int count, IntPtr ckzgSetup)
    {
        ThrowOnUninitializedTrustedSetup(ckzgSetup);
        ThrowOnInvalidLength(blobs, nameof(blobs), BytesPerBlob * count);
        ThrowOnInvalidLength(commitments, nameof(commitments), BytesPerCommitment * count);
        ThrowOnInvalidLength(proofs, nameof(proofs), BytesPerProof * count);

        fixed (byte* blobsPtr = blobs, commitmentsPtr = commitments, proofsPtr = proofs)
        {
            KzgResult kzgResult =
                VerifyBlobKzgProofBatch(out var result, blobsPtr, commitmentsPtr, proofsPtr, (UInt64)count, ckzgSetup);
            ThrowOnError(kzgResult);
            return result;
        }
    }
```

**File:** bindings/csharp/Ckzg.Bindings/Ckzg.Bindings.cs (L59-61)
```csharp
    [DllImport("ckzg", EntryPoint = "verify_blob_kzg_proof_batch", CallingConvention = CallingConvention.Cdecl)]
    private static extern unsafe KzgResult VerifyBlobKzgProofBatch(out bool result, byte* blobs, byte* commitments,
        byte* proofs, UInt64 count, IntPtr ts);
```

**File:** src/eip4844/eip4844.c (L768-774)
```c
 * @param[in]   n                   The number of blobs/commitments/proofs
 * @param[in]   s                   The trusted setup
 *
 * @remark This function accepts if called with `n==0`.
 * @remark This function assumes that `n` is trusted and that all input arrays contain `n` elements.
 * `n` should be the actual size of the arrays and not read off a length field in the protocol.
 */
```

**File:** src/eip4844/eip4844.c (L775-831)
```c
C_KZG_RET verify_blob_kzg_proof_batch(
    bool *ok,
    const Blob *blobs,
    const Bytes48 *commitments_bytes,
    const Bytes48 *proofs_bytes,
    uint64_t n,
    const KZGSettings *s
) {
    C_KZG_RET ret;
    g1_t *commitments_g1 = NULL;
    g1_t *proofs_g1 = NULL;
    fr_t *evaluation_challenges_fr = NULL;
    fr_t *ys_fr = NULL;
    fr_t *poly = NULL;

    /* Exit early if we are given zero blobs */
    if (n == 0) {
        *ok = true;
        return C_KZG_OK;
    }

    /* For a single blob, just do a regular single verification */
    if (n == 1) {
        return verify_blob_kzg_proof(ok, &blobs[0], &commitments_bytes[0], &proofs_bytes[0], s);
    }

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
