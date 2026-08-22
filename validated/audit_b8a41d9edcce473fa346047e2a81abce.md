No vulnerability found for this question.

`access_key_storage_usage` in `runtime/runtime/src/access_keys.rs` has no connection to deposit validation for `FunctionCall` actions. Its sole purpose is computing the storage byte cost of persisting an access key entry in the trie — the public key's trie identifier length plus the borsh-serialized size of the `AccessKey` struct plus a fixed per-record overhead — used only when adding (`add_regular_key`) or deleting (`delete_regular_key`) a key to adjust `account.storage_usage()`. [1](#0-0) [2](#0-1) 

The invariant that function-call access keys can never attach a deposit is enforced entirely independently, in `verify_function_call_permission` in `runtime/runtime/src/verifier.rs`, which explicitly checks `function_call.deposit > Balance::ZERO` and returns `InvalidTxError::InvalidAccessKeyError(InvalidAccessKeyError::DepositWithFunctionCall)` before the transaction is even converted into a receipt. [3](#0-2)  The same check is applied for `DelegateAction`s signed by function-call keys in `validate_delegate_action_key` in `runtime/runtime/src/actions.rs`, and for gas keys as well. [4](#0-3) 

Existing unit tests (`test_validate_transaction_deposit_with_function_call`, `test_validate_transaction_deposit_with_function_call_one_yocto`, `test_delegate_action_key_permissions_function_call_deposit`, `test_gas_key_delegate_function_call_deposit`) confirm this path already correctly rejects any non-zero deposit with a function-call-permissioned key, returning the exact `DepositWithFunctionCall` error variant. [5](#0-4) [6](#0-5) 

There is no code path by which `access_key_storage_usage` participates in deposit enforcement, receipt balance accounting, or fund movement, so the premised exploit against this specific function does not exist.

### Citations

**File:** runtime/runtime/src/access_keys.rs (L17-29)
```rust
fn access_key_storage_usage(
    fee_config: &RuntimeFeesConfig,
    public_key: &PublicKey,
    access_key: &AccessKey,
) -> StorageUsage {
    let storage_usage_config = &fee_config.storage_usage_config;
    // Use the on-trie identifier length, not the borsh-serialized pubkey
    // length: ML-DSA-65 access keys live in the trie as a SHA3-256 hash
    // (33 bytes incl. type tag), not as a 1953-byte full pubkey.
    public_key.trie_id_len() as u64
        + borsh::object_length(access_key).unwrap() as u64
        + storage_usage_config.num_extra_bytes_record
}
```

**File:** runtime/runtime/src/access_keys.rs (L230-255)
```rust
fn add_regular_key(
    fee_config: &RuntimeFeesConfig,
    state_update: &mut TrieUpdate,
    account: &mut Account,
    account_id: &AccountId,
    public_key: &PublicKey,
    access_key: &AccessKey,
    block_height: BlockHeight,
) -> Result<(), StorageError> {
    let mut access_key = access_key.clone();
    access_key.nonce = initial_nonce_value(block_height);
    set_access_key(state_update, account_id.clone(), public_key.clone(), &access_key);

    account.set_storage_usage(
        account
            .storage_usage()
            .checked_add(access_key_storage_usage(fee_config, public_key, &access_key))
            .ok_or_else(|| {
                StorageError::StorageInconsistentState(format!(
                    "Storage usage integer overflow for account {}",
                    account_id
                ))
            })?,
    );
    Ok(())
}
```

**File:** runtime/runtime/src/verifier.rs (L166-184)
```rust
fn verify_function_call_permission(
    function_call_permission: &FunctionCallPermission,
    tx: &Transaction,
) -> Result<(), InvalidTxError> {
    if tx.actions().len() != 1 {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::RequiresFullAccess,
        ));
    }
    let Some(Action::FunctionCall(function_call)) = tx.actions().get(0) else {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::RequiresFullAccess,
        ));
    };
    if function_call.deposit > Balance::ZERO {
        return Err(InvalidTxError::InvalidAccessKeyError(
            InvalidAccessKeyError::DepositWithFunctionCall,
        ));
    }
```

**File:** runtime/runtime/src/verifier.rs (L1703-1746)
```rust
    #[test]
    fn test_validate_transaction_deposit_with_function_call() {
        let config = RuntimeConfig::test();
        let (signer, mut state_update, gas_price) = setup_common(
            TESTING_INIT_BALANCE,
            Balance::ZERO,
            Some(AccessKey {
                nonce: 0,
                permission: AccessKeyPermission::FunctionCall(FunctionCallPermission {
                    allowance: None,
                    receiver_id: bob_account().into(),
                    method_names: vec![],
                }),
            }),
        );

        let signed_tx = SignedTransaction::from_actions(
            1,
            alice_account(),
            bob_account(),
            &*signer,
            vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "hello".to_string(),
                args: b"abc".to_vec(),
                gas: Gas::from_gas(100),
                deposit: Balance::from_yoctonear(100),
            }))],
            CryptoHash::default(),
        );

        let err = validate_verify_and_charge_transaction(
            &config,
            &mut state_update,
            signed_tx,
            gas_price,
            None,
            PROTOCOL_VERSION,
        )
        .expect_err("expected an error");
        assert_eq!(
            err,
            InvalidTxError::InvalidAccessKeyError(InvalidAccessKeyError::DepositWithFunctionCall,)
        );
    }
```

**File:** runtime/runtime/src/actions.rs (L626-650)
```rust
    // The restriction of "function call" access keys:
    // the transaction must contain the only `FunctionCall` if "function call" access key is used
    if let Some(function_call_permission) = access_key.permission.function_call_permission() {
        if actions.len() != 1 {
            result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::RequiresFullAccess,
            )
            .into());
            return Ok(());
        }
        if let Some(Action::FunctionCall(function_call)) = actions.get(0) {
            if function_call.deposit > Balance::ZERO {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::DepositWithFunctionCall,
                )
                .into());
                // Before this fix, the missing early return allowed execution
                // to fall through to the receiver_id and method_name checks,
                // which could overwrite this error with a different one.
                if ProtocolFeature::FixDelegateActionDepositWithFunctionCallError
                    .enabled(apply_state.current_protocol_version)
                {
                    return Ok(());
                }
            }
```

**File:** runtime/runtime/src/actions.rs (L1682-1712)
```rust
    #[test]
    fn test_delegate_action_key_permissions_function_call_deposit() {
        let (_, signed_delegate_action) = create_delegate_action_receipt();
        let access_key = AccessKey {
            nonce: 19000000,
            permission: AccessKeyPermission::FunctionCall(FunctionCallPermission {
                allowance: None,
                receiver_id: signed_delegate_action.delegate_action.receiver_id.to_string(),
                method_names: Vec::new(),
            }),
        };

        let mut delegate_action = signed_delegate_action.delegate_action;
        delegate_action.actions =
            vec![non_delegate_action(Action::FunctionCall(Box::new(FunctionCallAction {
                args: Vec::new(),
                deposit: Balance::from_yoctonear(1),
                gas: Gas::from_gas(300),
                method_name: "test_method".parse().unwrap(),
            })))];

        let result = test_delegate_action_key_permissions(&access_key, &delegate_action);

        assert_eq!(
            result.result,
            Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::DepositWithFunctionCall,
            )
            .into())
        );
    }
```
