No vulnerability found for this question.

**Rationale:** The premise doesn't hold in this codebase. There is no code path connecting `validator_txn_enabled()` (in `consensus_config.move`) to the fee-payer/gas-payer binding logic in `transaction_validation.move`.

- `validator_txn_enabled()` is only referenced by `aptos_governance.move`, `chunky_dkg_config.move`, and `randomness_config.move` — governance/reconfiguration-related consumers [1](#0-0) . It is never imported or called from `transaction_validation.move`.
- `transaction_validation.move` contains no reference to `consensus_config` at all (confirmed by search), so `prologue_common`, `fee_payer_script_prologue`, `unified_prologue_fee_payer_v2`, and the `versioned_prologue`/`PrologueArgs::V1` path all perform their fee-payer/auth-key binding checks unconditionally, independent of any consensus config or vtxn-enabled state [2](#0-1) [3](#0-2) [4](#0-3) .
- Validator transactions (`ValidatorTransaction`, e.g. DKG/JWK/randomness results) are a structurally distinct payload type handled by consensus's `MixedPayloadClient`/`ValidatorTxnPayloadClient` and are never routed through the user-transaction prologue functions like `fee_payer_prologue` [5](#0-4) . Classification of a transaction as a validator transaction vs. a normal `SignedTransaction` happens at the type/payload level (`Payload::DirectMempool` vs. vtxn list in `Block::new_proposal_ext`), not via a runtime flag checked inside the fee-payer prologue.
- The Rust-side dispatch in `AptosVM` that selects `fee_payer_prologue_name`/`fee_payer_prologue_extended_name` args is driven purely by whether `txn_data.fee_payer()` is set, not by any consensus config or vtxn-enabled state [6](#0-5) .

Since there is no shared gating code, `ConsensusConfig` staleness cannot cause a fee-payer transaction to skip `prologue_common`'s sender/fee-payer binding checks, and the described exploit path does not exist in this codebase.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L70-76)
```text
    public fun validator_txn_enabled(): bool acquires ConsensusConfig {
        let config_bytes = borrow_global<ConsensusConfig>(@aptos_framework).config;
        validator_txn_enabled_internal(config_bytes)
    }

    native fun validator_txn_enabled_internal(config_bytes: vector<u8>): bool;
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L436-472)
```text
    fun fee_payer_script_prologue(
        sender: signer,
        txn_sequence_number: u64,
        txn_sender_public_key: vector<u8>,
        secondary_signer_addresses: vector<address>,
        secondary_signer_public_key_hashes: vector<vector<u8>>,
        fee_payer_address: address,
        fee_payer_public_key_hash: vector<u8>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
    ) {
        // prologue_common and multi_agent_common_prologue with is_simulation set to false behaves identically to the
        // original fee_payer_script_prologue function.
        prologue_common(
            &sender,
            &create_signer::create_signer(fee_payer_address),
            ReplayProtector::SequenceNumber(txn_sequence_number),
            option::some(txn_sender_public_key),
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            false,
            option::none(),
        );
        multi_agent_common_prologue(
            secondary_signer_addresses,
            secondary_signer_public_key_hashes.map(|x| option::some(x)),
            false
        );
        assert!(
            fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
            error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L750-792)
```text
        /// If there is no fee_payer, fee_payer = sender
    fun unified_prologue_fee_payer_v2(
        sender: signer,
        fee_payer: signer,
        txn_sender_public_key: Option<vector<u8>>,
        fee_payer_public_key_hash: Option<vector<u8>>,
        replay_protector: ReplayProtector,
        secondary_signer_addresses: vector<address>,
        secondary_signer_public_key_hashes: vector<Option<vector<u8>>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
    ) {
        prologue_common(
            &sender,
            &fee_payer,
            replay_protector,
            txn_sender_public_key,
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            is_simulation,
            option::none(),
        );
        multi_agent_common_prologue(secondary_signer_addresses, secondary_signer_public_key_hashes, is_simulation);
        if (!skip_auth_key_check(is_simulation, &fee_payer_public_key_hash)) {
            let fee_payer_address = signer::address_of(&fee_payer);
            if (fee_payer_public_key_hash.is_some()) {
                assert!(
                    fee_payer_public_key_hash == option::some(account::get_authentication_key(fee_payer_address)),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            } else {
                assert!(
                    allow_missing_txn_authentication_key(fee_payer_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                )
            };
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L867-920)
```text
    fun versioned_prologue(sender: signer, fee_payer: signer, args: PrologueArgs) {
        match (args) {
            V1 {
                needs_fee_payer_auth_check,
                txn_sender_public_key,
                fee_payer_public_key_hash,
                replay_protector,
                secondary_signer_addresses,
                secondary_signer_public_key_hashes,
                txn_gas_price,
                txn_max_gas_units,
                txn_expiration_time,
                chain_id,
                is_simulation,
                txn_limits_request,
            } => {
                prologue_common(
                    &sender,
                    &fee_payer,
                    replay_protector,
                    txn_sender_public_key,
                    txn_gas_price,
                    txn_max_gas_units,
                    txn_expiration_time,
                    chain_id,
                    is_simulation,
                    txn_limits_request,
                );
                multi_agent_common_prologue(
                    secondary_signer_addresses,
                    secondary_signer_public_key_hashes,
                    is_simulation,
                );

                if (needs_fee_payer_auth_check) {
                    let fee_payer_address = signer::address_of(&fee_payer);
                    if (!skip_auth_key_check(is_simulation, &fee_payer_public_key_hash)) {
                        if (fee_payer_public_key_hash.is_some()) {
                            let fee_payer_public_key_hash = fee_payer_public_key_hash.destroy_some();
                            assert!(
                                fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
                                error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                            );
                        } else {
                            assert!(
                                allow_missing_txn_authentication_key(fee_payer_address),
                                error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                            );
                        };
                    };
                };
            },
        }
    }
```

**File:** consensus/src/payload_client/mixed.rs (L1-21)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    error::QuorumStoreError,
    payload_client::{user::UserPayloadClient, PayloadClient},
};
use aptos_consensus_types::{
    common::Payload, payload_pull_params::PayloadPullParameters, utils::PayloadTxnsSize,
};
use aptos_logger::debug;
use aptos_types::{on_chain_config::ValidatorTxnConfig, validator_txn::ValidatorTransaction};
use aptos_validator_transaction_pool::TransactionFilter;
use fail::fail_point;
use std::{cmp::min, sync::Arc, time::Instant};

pub struct MixedPayloadClient {
    validator_txn_config: ValidatorTxnConfig,
    validator_txn_pool_client: Arc<dyn crate::payload_client::validator::ValidatorTxnPayloadClient>,
    user_payload_client: Arc<dyn UserPayloadClient>,
}
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L288-329)
```rust
        let (prologue_function_name, args) = if let (Some(fee_payer), Some(fee_payer_auth_key)) = (
            txn_data.fee_payer(),
            txn_data
                .fee_payer_authentication_proof
                .as_ref()
                .map(|proof| proof.optional_auth_key()),
        ) {
            if features.is_transaction_simulation_enhancement_enabled() {
                let args = vec![
                    MoveValue::Signer(txn_data.sender),
                    MoveValue::U64(txn_sequence_number),
                    MoveValue::vector_u8(txn_authentication_key.unwrap_or_default()),
                    MoveValue::vector_address(txn_data.secondary_signers()),
                    MoveValue::Vector(secondary_auth_keys),
                    MoveValue::Address(fee_payer),
                    MoveValue::vector_u8(fee_payer_auth_key.unwrap_or_default()),
                    MoveValue::U64(txn_gas_price.into()),
                    MoveValue::U64(txn_max_gas_units.into()),
                    MoveValue::U64(txn_expiration_timestamp_secs),
                    MoveValue::U8(chain_id.id()),
                    MoveValue::Bool(is_simulation),
                ];
                (
                    &APTOS_TRANSACTION_VALIDATION.fee_payer_prologue_extended_name,
                    args,
                )
            } else {
                let args = vec![
                    MoveValue::Signer(txn_data.sender),
                    MoveValue::U64(txn_sequence_number),
                    MoveValue::vector_u8(txn_authentication_key.unwrap_or_default()),
                    MoveValue::vector_address(txn_data.secondary_signers()),
                    MoveValue::Vector(secondary_auth_keys),
                    MoveValue::Address(fee_payer),
                    MoveValue::vector_u8(fee_payer_auth_key.unwrap_or_default()),
                    MoveValue::U64(txn_gas_price.into()),
                    MoveValue::U64(txn_max_gas_units.into()),
                    MoveValue::U64(txn_expiration_timestamp_secs),
                    MoveValue::U8(chain_id.id()),
                ];
                (&APTOS_TRANSACTION_VALIDATION.fee_payer_prologue_name, args)
            }
```
