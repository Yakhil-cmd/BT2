[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** aptos-move/framework/natives/src/account.rs (L37-51)
```rust
    let bytes = safely_pop_arg!(arguments, Vec<u8>);
    let bytes_len = bytes.len();
    let address = AccountAddress::from_bytes(bytes);
    if let Ok(address) = address {
        Ok(smallvec![Value::address(address)])
    } else {
        Err(SafeNativeError::abort_with_message(
            super::status::NFE_UNABLE_TO_PARSE_ADDRESS,
            format!(
                "Unable to create address from bytes, expected {} bytes, got {}",
                AccountAddress::LENGTH,
                bytes_len,
            ),
        ))
    }
```

**File:** third_party/move/move-core/types/src/account_address.rs (L843-847)
```rust
    #[test]
    fn test_address_from_proto_invalid_length() {
        let bytes = vec![1; 123];
        AccountAddress::from_bytes(bytes).unwrap_err();
    }
```

**File:** third_party/move/move-core/types/src/account_address.rs (L889-897)
```rust
        #[test]
        #[allow(clippy::redundant_clone)] // Required to work around prop_assert_eq! limitations
        fn test_address_protobuf_roundtrip(addr in any::<AccountAddress>()) {
            let bytes = addr.to_vec();
            prop_assert_eq!(bytes.clone(), addr.as_ref());
            let addr2 = AccountAddress::try_from(&bytes[..]).unwrap();
            prop_assert_eq!(addr, addr2);
        }
    }
```
