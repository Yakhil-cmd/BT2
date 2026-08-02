[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** types/src/transaction/mod.rs (L686-688)
```rust
    pub fn signing_message(&self) -> Result<Vec<u8>, CryptoMaterialError> {
        signing_message(self)
    }
```

**File:** types/src/transaction/mod.rs (L701-711)
```rust
            }) => Cow::Owned(RawTransaction {
                sender: self.sender,
                sequence_number: self.sequence_number,
                payload: TransactionPayload::EncryptedPayload(EncryptedPayload::Encrypted(
                    original.clone(),
                )),
                max_gas_amount: self.max_gas_amount,
                gas_unit_price: self.gas_unit_price,
                expiration_timestamp_secs: self.expiration_timestamp_secs,
                chain_id: self.chain_id,
            }),
```

**File:** types/src/transaction/authenticator.rs (L225-228)
```rust
            Self::MultiEd25519 {
                public_key,
                signature,
            } => signature.verify(&raw_txn_for_signing, public_key),
```
