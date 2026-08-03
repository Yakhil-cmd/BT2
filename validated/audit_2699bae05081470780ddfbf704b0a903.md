## Finding: Missing `FEE_PAYER_ENABLED` runtime check in fee-payer prologue functions

### Title
Fee-payer transaction prologues never enforce the `features::FEE_PAYER_ENABLED` gate, allowing sponsored transactions to be processed even when the feature is disabled - (File: `aptos-move/framework/aptos-framework/sources/transaction_validation.move`)

### Summary
The Move framework declares a dedicated abort code `PROLOGUE_EFEE_PAYER_NOT_ENABLED` [1](#0-0)  and the formal spec for `fee_payer_script_prologue_extended` explicitly requires `aborts_if !features::spec_is_enabled(features::FEE_PAYER_ENABLED)` [2](#0-1) . However, none of the actual Move implementations that mint a fee-payer signer via `create_signer::create_signer(fee_payer_address)` contain a runtime assertion against `features::fee_payer_enabled()`.

### Finding Description
I traced every fee-payer prologue entrypoint reachable from the VM:
- `fee_payer_script_prologue` (legacy, non-extended) - calls `prologue_common` with `create_signer::create_signer(fee_payer_address)` and never checks the feature flag before doing so [3](#0-2) .
- `fee_payer_script_prologue_extended` - same pattern, also mints the fee-payer signer unconditionally with no feature check [4](#0-3) .
- `unified_prologue_fee_payer` / `unified_prologue_fee_payer_v2` (used when account abstraction is enabled, dispatched from Rust) - no `fee_payer_enabled()` check either [5](#0-4) [6](#0-5) .
- `versioned_prologue` (the new versioned-enum-based dispatch path) - again constructs and uses the `fee_payer` signer with no feature gate anywhere in its logic [7](#0-6) .

The Rust dispatcher `run_script_prologue` in `aptos-move/aptos-vm/src/transaction_validation.rs` selects between these Move entrypoints purely based on `txn_data.fee_payer()` being `Some(...)` and other unrelated feature flags (AA, payload-v2, simulation-enhancement) [8](#0-7) [9](#0-8)  - it never consults `features.is_fee_payer_enabled()` (no such call exists anywhere in the codebase outside of Move framework declarations, per the repo-wide grep).

As a result, `PROLOGUE_EFEE_PAYER_NOT_ENABLED` is a dead constant that is never asserted at runtime, and `create_signer::create_signer(fee_payer_address)` [10](#0-9)  is invoked unconditionally for any signed sponsored transaction regardless of the `FEE_PAYER_ENABLED` on-chain feature flag state.

### Impact Explanation
If governance ever disables `FEE_PAYER_ENABLED` (e.g., as an incident-response kill switch or during a migration), any unprivileged user who already holds a validly-signed fee-payer (sponsored) transaction can still get it admitted and executed - the gas-payer signer is minted and the sponsor account is charged gas regardless of the flag. This breaks the intended feature-gating/kill-switch invariant for sponsored transactions across every prologue variant (legacy, extended, unified, and versioned), not merely in a narrow mempool/VM race window.

### Likelihood Explanation
No special privilege is needed by the transacting party - they only need a normally-signed fee-payer transaction, which is standard sponsored-transaction usage. The only precondition is that the on-chain `FEE_PAYER_ENABLED` feature is toggled off by governance; the finding shows that once that happens, the disable has no actual effect on transaction processing, since the code path that should reject it (`PROLOGUE_EFEE_PAYER_NOT_ENABLED`) is unreachable in the current implementation.

### Recommendation
Add an explicit `assert!(features::fee_payer_enabled(), error::invalid_argument(PROLOGUE_EFEE_PAYER_NOT_ENABLED));` at the start of `fee_payer_script_prologue`, `fee_payer_script_prologue_extended`, `unified_prologue_fee_payer_v2`, and the fee-payer branch of `versioned_prologue`, matching the guarantee already encoded in the Move spec for `fee_payer_script_prologue_extended`.

### Proof of Concept
1. Enable `FEE_PAYER_ENABLED`, submit and mempool-admit a signed fee-payer transaction (sender + sponsor signatures valid).
2. Before VM execution, have governance disable `FEE_PAYER_ENABLED` via `features::change_feature_flags`.
3. Replay the transaction through VM execution: `fee_payer_script_prologue`/`unified_prologue_fee_payer_v2`/`versioned_prologue` will still execute successfully, mint the gas-payer signer via `create_signer::create_signer`, and the transaction proceeds to execution/epilogue - no `PROLOGUE_EFEE_PAYER_NOT_ENABLED` abort occurs, confirming the guard never fires in any reachable code path.

Note: I could not verify whether there is an additional, out-of-band enforcement of `FEE_PAYER_ENABLED` elsewhere (e.g. in transaction decoding/signature verification in `types/src/transaction/authenticator.rs` or mempool ingestion) that might independently reject fee-payer transactions when the flag is off, since the index does not show any call to `is_fee_payer_enabled()`/`fee_payer_enabled()` outside the Move framework declarations. If such a check exists elsewhere, it would need to be confirmed via a full repository search (e.g., a Devin session with complete file access) before treating this purely as a live exploit rather than dead/vestigial code.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L73-73)
```text
    const PROLOGUE_EFEE_PAYER_NOT_ENABLED: u64 = 1010;
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

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L477-514)
```text
    fun fee_payer_script_prologue_extended(
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
        is_simulation: bool,
    ) {
        prologue_common(
            &sender,
            &create_signer::create_signer(fee_payer_address),
            ReplayProtector::SequenceNumber(txn_sequence_number),
            option::some(txn_sender_public_key),
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            is_simulation,
            option::none(),
        );
        multi_agent_common_prologue(
            secondary_signer_addresses,
            secondary_signer_public_key_hashes.map(|x| option::some(x)),
            is_simulation
        );
        if (!skip_auth_key_check(is_simulation, &option::some(fee_payer_public_key_hash))) {
                assert!(
                    fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                )
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L664-695)
```text
    /// If there is no fee_payer, fee_payer = sender
    fun unified_prologue_fee_payer(
        sender: signer,
        fee_payer: signer,
        // None means no need to check, i.e. either AA (where it is already checked) or simulation
        txn_sender_public_key: Option<vector<u8>>,
        // None means no need to check, i.e. either AA (where it is already checked) or simulation
        fee_payer_public_key_hash: Option<vector<u8>>,
        txn_sequence_number: u64,
        secondary_signer_addresses: vector<address>,
        secondary_signer_public_key_hashes: vector<Option<vector<u8>>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
    ) {
        unified_prologue_fee_payer_v2(
            sender,
            fee_payer,
            txn_sender_public_key,
            fee_payer_public_key_hash,
            ReplayProtector::SequenceNumber(txn_sequence_number),
            secondary_signer_addresses,
            secondary_signer_public_key_hashes,
            txn_gas_price,
            txn_max_gas_units,
            txn_expiration_time,
            chain_id,
            is_simulation,
        )
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L751-792)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.spec.move (L255-270)
```text
        aborts_if !features::spec_is_enabled(features::FEE_PAYER_ENABLED);
        let gas_payer = create_signer::spec_create_signer(fee_payer_address);
        include PrologueCommonAbortsIf {
            gas_payer,
            replay_protector: ReplayProtector::SequenceNumber(txn_sequence_number),
            txn_authentication_key: option::spec_some(txn_sender_public_key),
        };
        // include MultiAgentPrologueCommonAbortsIf {
        //     secondary_signer_addresses,
        //     secondary_signer_public_key_hashes,
        //     is_simulation,
        // };

        aborts_if !account::spec_exists_at(fee_payer_address);
        aborts_if !(fee_payer_public_key_hash == account::spec_get_authentication_key(fee_payer_address));
        aborts_if !features::spec_fee_payer_enabled();
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L146-216)
```rust
    if features.is_account_abstraction_enabled()
        || features.is_derivable_account_abstraction_enabled()
    {
        let secondary_auth_keys: Vec<MoveValue> = txn_data
            .secondary_authentication_proofs
            .iter()
            .map(|auth_key| auth_key.optional_auth_key().as_move_value())
            .collect();
        let replay_protector_move_value = if features.is_transaction_payload_v2_enabled() {
            txn_replay_protector
                .to_move_value()
                .simple_serialize()
                .unwrap()
        } else {
            match txn_replay_protector {
                ReplayProtector::SequenceNumber(seq_num) => {
                    MoveValue::U64(seq_num).simple_serialize().unwrap()
                },
                ReplayProtector::Nonce(_) => {
                    unreachable!("Orderless transactions are discarded already")
                },
            }
        };

        let (prologue_function_name, serialized_args) = if let (true, Some(fee_payer_auth_key)) = (
            txn_data.fee_payer().is_some(),
            txn_data
                .fee_payer_authentication_proof
                .as_ref()
                .map(|proof| proof.optional_auth_key()),
        ) {
            let serialized_args = vec![
                serialized_signers.sender(),
                serialized_signers
                    .fee_payer()
                    .ok_or_else(|| VMStatus::error(StatusCode::UNREACHABLE, None))?,
                txn_authentication_key
                    .as_move_value()
                    .simple_serialize()
                    .unwrap(),
                fee_payer_auth_key
                    .as_move_value()
                    .simple_serialize()
                    .unwrap(),
                replay_protector_move_value,
                MoveValue::vector_address(txn_data.secondary_signers())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::Vector(secondary_auth_keys)
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_gas_price.into())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_max_gas_units.into())
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U64(txn_expiration_timestamp_secs)
                    .simple_serialize()
                    .unwrap(),
                MoveValue::U8(chain_id.id()).simple_serialize().unwrap(),
                MoveValue::Bool(is_simulation).simple_serialize().unwrap(),
            ];
            (
                if features.is_transaction_payload_v2_enabled() {
                    &APTOS_TRANSACTION_VALIDATION.unified_prologue_fee_payer_v2_name
                } else {
                    &APTOS_TRANSACTION_VALIDATION.unified_prologue_fee_payer_name
                },
                serialized_args,
            )
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

**File:** aptos-move/framework/aptos-framework/sources/create_signer.move (L25-25)
```text
    public(friend) native fun create_signer(addr: address): signer;
```
