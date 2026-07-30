[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-bridge/src/sui_syncer.rs (L159-170)
```rust
            let Ok(Ok(records)) = retry_with_max_elapsed_time!(
                sui_client.get_bridge_records_in_range(source_chain_id, start_index, end_index),
                Duration::from_secs(120)
            ) else {
                tracing::error!(
                    source_chain_id,
                    start_index,
                    end_index,
                    "Failed to get records from sui client after retry"
                );
                continue;
            };
```

**File:** crates/sui-bridge/src/sui_syncer.rs (L219-254)
```rust
    fn bridge_record_to_event(
        record: &sui_types::bridge::MoveTypeBridgeRecord,
        source_chain_id: u8,
    ) -> Result<SuiBridgeEvent, crate::error::BridgeError> {
        let action = BridgeAction::try_from_bridge_record(record)?;

        match action {
            BridgeAction::SuiToEthTokenTransfer(transfer) => Ok(
                SuiBridgeEvent::SuiToEthTokenBridgeV1(EmittedSuiToEthTokenBridgeV1 {
                    nonce: transfer.nonce,
                    sui_chain_id: transfer.sui_chain_id,
                    eth_chain_id: transfer.eth_chain_id,
                    sui_address: transfer.sui_address,
                    eth_address: transfer.eth_address,
                    token_id: transfer.token_id,
                    amount_sui_adjusted: transfer.amount_adjusted,
                }),
            ),
            BridgeAction::SuiToEthTokenTransferV2(transfer) => Ok(
                SuiBridgeEvent::SuiToEthTokenBridgeV2(EmittedSuiToEthTokenBridgeV2 {
                    nonce: transfer.nonce,
                    sui_chain_id: transfer.sui_chain_id,
                    eth_chain_id: transfer.eth_chain_id,
                    sui_address: transfer.sui_address,
                    eth_address: transfer.eth_address,
                    token_id: transfer.token_id,
                    amount_sui_adjusted: transfer.amount_adjusted,
                    timestamp_ms: transfer.timestamp_ms,
                }),
            ),
            _ => Err(crate::error::BridgeError::Generic(format!(
                "Unexpected action type for source_chain_id {}: {:?}",
                source_chain_id, action
            ))),
        }
    }
```
