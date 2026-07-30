[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-core/src/consensus_validator.rs (L120-122)
```rust
                ConsensusTransactionKind::EndOfPublish(_)
                | ConsensusTransactionKind::NewJWKFetched(_, _, _)
                | ConsensusTransactionKind::CapabilityNotificationV2(_) => {}
```

**File:** crates/sui-core/src/consensus_validator.rs (L475-484)
```rust
fn tx_kind_from_bytes(tx: &[u8]) -> Result<ConsensusTransactionKind, ValidationError> {
    bcs::from_bytes::<ConsensusTransaction>(tx)
        .map_err(|e| {
            ValidationError::InvalidTransaction(format!(
                "Failed to parse transaction bytes: {:?}",
                e
            ))
        })
        .map(|tx| tx.kind)
}
```

**File:** crates/sui-core/src/consensus_validator.rs (L486-497)
```rust
impl TransactionVerifier for SuiTxValidator {
    fn verify_batch(&self, batch: &[&[u8]]) -> Result<(), ValidationError> {
        let _scope = monitored_scope("ValidateBatch");

        let txs: Vec<_> = batch
            .iter()
            .map(|tx| tx_kind_from_bytes(tx))
            .collect::<Result<Vec<_>, _>>()?;

        self.validate_transactions(&txs)
            .map_err(|e| ValidationError::InvalidTransaction(e.to_string()))
    }
```
