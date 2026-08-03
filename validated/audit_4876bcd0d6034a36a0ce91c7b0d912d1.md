[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** types/src/transaction/webauthn.rs (L536-543)
```rust
        // Generate signing message (returns the concatenation of hash prefix || BCS serialization of transaction)
        let raw_txn_signing_message =
            signing_message(&raw_txn).expect("Unexpected BCS serialization error");
        // then generates the SHA3-256 digest of signing message as the challenge
        let challenge = HashValue::sha3_256_of(raw_txn_signing_message.as_slice()).to_vec();

        (raw_txn, raw_txn_signing_message, challenge)
    }
```

**File:** types/src/transaction/webauthn.rs (L712-713)
```rust
        let verification = paar.verify(&raw_txn, &any_public_key);
        assert!(verification.is_ok());
```

**File:** types/src/transaction/webauthn.rs (L865-866)
```rust
        let verification_result = paar.verify(&raw_txn, &any_public_key);
        assert!(verification_result.is_ok());
```

**File:** types/src/transaction/authenticator.rs (L2317-2321)
```rust
        // Badly-signed TXN
        raw_txn.expiration_timestamp_secs += 1;
        let signed_txn = SignedTransaction::new_single_sender(raw_txn, account_auth);
        assert!(signed_txn.verify_signature().is_err());
    }
```
