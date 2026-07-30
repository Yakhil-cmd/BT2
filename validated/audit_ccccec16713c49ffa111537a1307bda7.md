[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** crates/sui-bridge/src/action_executor.rs (L552-555)
```rust
        let sig = Signature::new_secure(
            &IntentMessage::new(Intent::sui_transaction(), &tx_data),
            sui_key,
        );
```

**File:** crates/sui-bridge/src/sui_transaction_builder.rs (L20-104)
```rust
pub fn build_sui_transaction(
    client_address: SuiAddress,
    gas_object_ref: &ObjectRef,
    action: VerifiedCertifiedBridgeAction,
    bridge_object_arg: ObjectArg,
    sui_token_type_tags: &HashMap<u8, TypeTag>,
    rgp: u64,
) -> BridgeResult<TransactionData> {
    // TODO: Check chain id?
    match action.data() {
        BridgeAction::EthToSuiBridgeAction(_) | BridgeAction::EthToSuiTokenTransferV2(_) => {
            build_token_bridge_approve_transaction(
                client_address,
                gas_object_ref,
                action,
                true,
                bridge_object_arg,
                sui_token_type_tags,
                rgp,
            )
        }
        BridgeAction::SuiToEthBridgeAction(_) => build_token_bridge_approve_transaction(
            client_address,
            gas_object_ref,
            action,
            false,
            bridge_object_arg,
            sui_token_type_tags,
            rgp,
        ),
        BridgeAction::SuiToEthTokenTransfer(_) | BridgeAction::SuiToEthTokenTransferV2(_) => {
            build_token_bridge_approve_transaction(
                client_address,
                gas_object_ref,
                action,
                false,
                bridge_object_arg,
                sui_token_type_tags,
                rgp,
            )
        }
        BridgeAction::BlocklistCommitteeAction(_) => build_committee_blocklist_approve_transaction(
            client_address,
            gas_object_ref,
            action,
            bridge_object_arg,
            rgp,
        ),
        BridgeAction::EmergencyAction(_) => build_emergency_op_approve_transaction(
            client_address,
            gas_object_ref,
            action,
            bridge_object_arg,
            rgp,
        ),
        BridgeAction::LimitUpdateAction(_) => build_limit_update_approve_transaction(
            client_address,
            gas_object_ref,
            action,
            bridge_object_arg,
            rgp,
        ),
        BridgeAction::AssetPriceUpdateAction(_) => build_asset_price_update_approve_transaction(
            client_address,
            gas_object_ref,
            action,
            bridge_object_arg,
            rgp,
        ),
        BridgeAction::EvmContractUpgradeAction(_) => {
            // It does not need a Sui transaction to execute EVM contract upgrade
            unreachable!()
        }
        BridgeAction::AddTokensOnSuiAction(_) => build_add_tokens_on_sui_transaction(
            client_address,
            gas_object_ref,
            action,
            bridge_object_arg,
            rgp,
        ),
        BridgeAction::AddTokensOnEvmAction(_) => {
            // It does not need a Sui transaction to add tokens on EVM
            unreachable!()
        }
    }
```

**File:** crates/sui-bridge/src/sui_transaction_builder.rs (L116-116)
```rust
    let (bridge_action, sigs) = action.into_inner().into_data_and_sig();
```
