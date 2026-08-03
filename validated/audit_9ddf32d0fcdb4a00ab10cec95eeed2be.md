[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** third_party/move/move-binary-format/src/deserializer.rs (L998-1012)
```rust
fn load_address_identifier(cursor: &mut VersionedCursor) -> BinaryLoaderResult<AccountAddress> {
    let mut buffer: Vec<u8> = vec![0u8; AccountAddress::LENGTH];
    if !cursor
        .read(&mut buffer)
        .map(|count| count == AccountAddress::LENGTH)
        .unwrap()
    {
        Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Bad Address pool size".to_string()))?
    }
    buffer.try_into().map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Invalid Address format".to_string())
    })
}
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L1021-1044)
```rust
/// Build a metadata entry.
fn load_metadata_entry(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Metadata> {
    let key = load_byte_blob(cursor, load_metadata_key_size)?;
    let value = load_byte_blob(cursor, load_metadata_value_size)?;
    Ok(Metadata { key, value })
}

/// Helper to load a byte blob with specific size loader.
fn load_byte_blob(
    cursor: &mut VersionedCursor,
    size_loader: impl Fn(&mut VersionedCursor) -> BinaryLoaderResult<usize>,
) -> BinaryLoaderResult<Vec<u8>> {
    let size = size_loader(cursor)?;
    let mut data: Vec<u8> = vec![0u8; size];
    let count = cursor.read(&mut data).map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Unexpected end of table".to_string())
    })?;
    if count != size {
        return Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Bad byte blob size".to_string()));
    }
    Ok(data)
}
```
