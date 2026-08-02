No vulnerability found for this question.

**Analysis:**

The premise doesn't hold for two independent reasons.

1. **`any::unpack` is not part of the secondary-signer/transaction-admission path.** Secondary signers in Aptos transactions come directly from `TransactionMetadata::secondary_signers()`, populated from the `MultiAgentAuthenticator`/`FeePayerAuthenticator` fields of a `SignedTransaction`, which are parsed via standard BCS deserialization of the whole transaction (mempool/vm-validator), not via `aptos_std::any::Any` or `unpack<T>`. [1](#0-0) [2](#0-1)  `any::pack`/`unpack` is instead used for generic extensible on-chain resources such as `jwks` and `chunky_dkg_config`, unrelated to signer-set binding.

2. **Even taken on its own terms, `from_bytes<T>` cannot produce an "over-long" vector from a tampered length prefix.** The native deserializer (`native_from_bytes` / `ValueSerDeContext::deserialize`) walks the BCS `Vector` layout by first reading a ULEB128 length via `read_uleb128_len`, then reading exactly `len * elem_size` bytes from the buffer via `read_slice`, which explicitly bounds-checks against the remaining buffer and errors with `RuntimeError::BCSEof` if not enough bytes are present. [3](#0-2) [4](#0-3)  So an attacker cannot make the declared length exceed the actual number of encoded elements without also supplying the extra bytes that make up genuine additional elements — there is no way to get a length prefix "lie" that yields a vector whose length disagrees with its actual content; deserialization either fails (`abort EFROM_BYTES`) or the result vector genuinely contains that many elements taken from the buffer. `any::unpack` itself only checks the type name matches (`ETYPE_MISMATCH`) before delegating to this safe, length-consistent deserializer. [5](#0-4) 

Since the described bypass mechanism doesn't exist in the deserializer and `any::unpack` has no role in secondary-signer binding during transaction admission, there is no admission-boundary impact here.

### Citations

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L283-287)
```rust
        let secondary_auth_keys: Vec<MoveValue> = txn_data
            .secondary_authentication_proofs
            .iter()
            .map(|auth_key| MoveValue::vector_u8(auth_key.optional_auth_key().unwrap_or_default()))
            .collect();
```

**File:** aptos-move/aptos-vm/src/transaction_validation_versioned.rs (L79-84)
```rust
            secondary_signer_addresses: txn_data.secondary_signers(),
            secondary_signer_public_key_hashes: txn_data
                .secondary_authentication_proofs
                .iter()
                .map(|proof| proof.optional_auth_key())
                .collect(),
```

**File:** third_party/move/mono-move/runtime/src/value_utils.rs (L696-723)
```rust
        LayoutKind::Vector {
            elem_id,
            descriptor_id,
        } => {
            let len = read_uleb128_len(bytes, cursor)?;
            if len > bcs::MAX_SEQUENCE_LENGTH as u64 {
                return Err(RuntimeError::BCSSequenceTooLong { len }.into());
            }
            if len == 0 {
                // The empty vector is the null pointer.
                // SAFETY: `dst` has size to write the null pointer as
                // guaranteed by the caller.
                unsafe { write_ptr(dst, 0usize, std::ptr::null()) };
                return Ok(());
            }

            let elem_layout = layouts.layout(*elem_id).ok_or_else(layout_not_found)?;
            let elem_size = elem_layout.size as usize;

            let data_size = (len as usize)
                .checked_mul(elem_size)
                .ok_or(RuntimeError::VecAllocSizeOverflow)?;
            let total_size = data_size
                .checked_add(OBJECT_HEADER_SIZE + VEC_DATA_OFFSET)
                .ok_or(RuntimeError::VecAllocSizeOverflow)?;

            // An OOM here propagates as `AllocationError::OutOfHeapMemory`.
            let vec_ptr = heap_alloc(heap, total_size, *descriptor_id)?;
```

**File:** third_party/move/mono-move/runtime/src/value_utils.rs (L846-856)
```rust
/// Borrows the next `n` bytes, advancing the cursor. Returns an error if
/// there is not enough bytes to read or the size of the slice overflows.
fn read_slice<'b>(bytes: &'b [u8], cursor: &mut usize, n: usize) -> Result<&'b [u8], RuntimeError> {
    let end = cursor.checked_add(n).ok_or(RuntimeError::BCSEof)?;
    if end > bytes.len() {
        return Err(RuntimeError::BCSEof);
    }
    let slice = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}
```

**File:** aptos-move/framework/aptos-stdlib/sources/any.move (L39-42)
```text
    public fun unpack<T>(self: Any): T {
        assert!(type_info::type_name<T>() == self.type_name, error::invalid_argument(ETYPE_MISMATCH));
        from_bytes<T>(self.data)
    }
```
