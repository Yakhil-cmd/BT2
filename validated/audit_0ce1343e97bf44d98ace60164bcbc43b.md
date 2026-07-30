[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** crates/sui-bridge/src/sui_syncer.rs (L277-314)
```rust
    fn create_test_bridge_record(
        seq_num: u64,
        source_chain: BridgeChainId,
        target_chain: BridgeChainId,
        amount: u64,
    ) -> MoveTypeBridgeRecord {
        // Create the payload struct matching SuiToEthOnChainBcsPayload
        #[derive(serde::Serialize)]
        struct TestPayload {
            sui_address: Vec<u8>,
            target_chain: u8,
            eth_address: Vec<u8>,
            token_type: u8,
            amount: [u8; 8],
        }

        let payload = TestPayload {
            sui_address: vec![0u8; 32], // 32-byte SuiAddress
            target_chain: target_chain as u8,
            eth_address: vec![0u8; 20], // 20-byte EthAddress
            token_type: 1,              // SUI token
            amount: amount.to_be_bytes(),
        };

        let payload_bytes = bcs::to_bytes(&payload).unwrap();

        MoveTypeBridgeRecord {
            message: MoveTypeBridgeMessage {
                message_type: 0, // TokenTransfer
                message_version: 1,
                seq_num,
                source_chain: source_chain as u8,
                payload: payload_bytes,
            },
            verified_signatures: None,
            claimed: false,
        }
    }
```
