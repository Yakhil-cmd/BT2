No vulnerability found for this question.

**Analysis:** Every fee-payer prologue variant in `transaction_validation.move` correctly validates that the fee-payer's authentication key hash matches `account::get_authentication_key(fee_payer_address)` before accepting the sponsored transaction, aborting with `PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY` on mismatch:

- `fee_payer_script_prologue` asserts `fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address)` [1](#0-0) 
- `fee_payer_script_prologue_extended` performs the same check (gated by `skip_auth_key_check` only for simulation/AA cases, not for a forged key on a real sender) [2](#0-1) 
- `unified_prologue_fee_payer_v2` performs the equivalent check [3](#0-2) 
- `versioned_prologue` (the newest enum-based path) performs the same check [4](#0-3) 

On the Rust/VM side, `run_script_prologue` in `transaction_validation.rs` extracts `fee_payer_auth_key` from `txn_data.fee_payer_authentication_proof` and passes it as an explicit argument into these prologue functions — it does not derive or trust an unverified binding; the Move-side assertion is what enforces the check against on-chain state [5](#0-4) .

`skip_auth_key_check` only bypasses this for legitimate simulation mode or when using native/account-abstraction authenticators (where the auth key has already been separately verified) — not for a forged key on a normal fee-payer signer. A forged `fee_payer_auth_key` for a real account with a real on-chain authentication key will always fail the `assert!` and abort the transaction with `PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY`, exactly as the "proof idea" test in the question describes — meaning that test would pass (correctly reject), not reveal a bug.

The cited file in the question (`unsync_code_storage.rs`) is unrelated to fee-payer prologue logic and contains no such check; the actual authentication logic lives in `transaction_validation.move` and `transaction_validation.rs`, both of which correctly bind and validate the fee-payer authentication key before admission.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L468-472)
```text
        assert!(
            fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
            error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L508-513)
```text
        if (!skip_auth_key_check(is_simulation, &option::some(fee_payer_public_key_hash))) {
                assert!(
                    fee_payer_public_key_hash == account::get_authentication_key(fee_payer_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                )
        }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L778-791)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L901-916)
```text
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
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L170-216)
```rust
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
