### Title
Wallet Contract callbacks fail to refund `caller_deposit` when an intermediate cross-contract check fails, causing unauthorized loss of a caller's attached deposit - ([File: runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs])

### Summary
In the `near-wallet-contract` (the EIP-2930/RLP-transaction emulation contract shipped in this nearcore repo and deployed to eth-implicit accounts), an external, unprivileged caller can attach a NEAR deposit to `rlp_execute` (`CallerDeposit`) which is supposed to be refunded if the underlying cross-contract call fails. This refund is correctly implemented in `rlp_execute_callback` [1](#0-0)  but the two intermediate callbacks that precede it, `address_check_callback` and `nep_141_storage_balance_callback`, do **not** refund `caller_deposit` when their own preliminary promise (registrar lookup / `storage_balance_of`) fails, even though they receive `caller_deposit` as a parameter and are architecturally the exact place such handling should occur.

### Finding Description
`rlp_execute` accepts an attached deposit and derives a `caller_deposit` for the predecessor, intended to be refunded on failure of the emulated action [2](#0-1) .

For certain transaction kinds, execution is routed through an intermediate promise before the actual action is dispatched:
- `EOABaseTokenTransfer` with `address_check: Some(_)` → calls the address registrar, then `address_check_callback` [3](#0-2) 
- `ERC20Transfer` → calls `storage_balance_of`, then `nep_141_storage_balance_callback` [4](#0-3) 

In `address_check_callback`, when the registrar lookup's `PromiseResult` is `Failed`, the function returns an error response but never inspects or forwards `caller_deposit` for a refund: [5](#0-4) 

The same pattern exists in `nep_141_storage_balance_callback`: [6](#0-5) 

Compare this to the terminal callback, `rlp_execute_callback`, which correctly issues a refund transfer to `caller_deposit.account_id` when the main action's promise fails: [1](#0-0) 

This is the same bug class as the referenced Sherlock finding: an accounting/entitlement value (`caller_deposit`, analogous to `accountRewardDebt`) is finalized/dropped on a failure path without performing the compensating action (the refund transfer) that the success/refund logic elsewhere in the same state machine performs. The nonce (`self.nonce`) is also already advanced by this point in most paths, so the transaction is treated as "consumed" while the caller's attached deposit is silently forfeited to the wallet contract's balance instead of being returned to the predecessor who supplied it.

### Impact Explanation
An external, unprivileged account (the `predecessor_id` of the receipt calling `rlp_execute`, e.g., a relayer or third party interacting on behalf of a user) that attaches a deposit and triggers either the address-registrar-check path or the NEP-141-storage-check path loses that deposit permanently if the intermediate lookup call fails (e.g., registrar contract missing/paused, temporary network/shard issue causing the lookup receipt to fail, or the token contract's `storage_balance_of` call failing). The deposit is retained by the wallet contract account instead of being refunded, which is an unauthorized balance change from the caller's perspective — funds are taken without the corresponding action ever completing. This matches the "unauthorized state or balance change" acceptance criterion; it is reachable purely through a standard transaction/receipt/contract-call flow with no validator or node-level privilege required.

### Likelihood Explanation
Likelihood is moderate: it only triggers on the two specific sub-flows (`EOABaseTokenTransfer` with a required address check, and `ERC20Transfer`) and only when the first-stage promise (registrar lookup or `storage_balance_of`) itself fails — which can happen due to legitimate operational conditions (e.g., registrar contract paused/removed, gas exhaustion on the lookup, or the token contract call failing) rather than attacker-controlled conditions. However, because the wallet contract is deployed globally for all eth-implicit accounts, this affects a broad set of users whenever any caller-deposit-bearing transaction takes the ERC-20 or address-check path and the preliminary lookup fails.

### Recommendation
In both `address_check_callback` and `nep_141_storage_balance_callback`, on the `PromiseResult::Failed` branch, refund `caller_deposit` exactly as `rlp_execute_callback` does before returning the error `ExecuteResponse`, e.g.:
```rust
PromiseResult::Failed => {
    if let Some(CallerDeposit { account_id, yocto_near }) = caller_deposit {
        let refund_promise = env::promise_batch_create(&account_id);
        env::promise_batch_action_transfer(refund_promise, NearToken::from_yoctonear(yocto_near.into()));
    }
    return PromiseOrValue::Value(ExecuteResponse { .. });
}
```

### Proof of Concept
Not independently executed; based on static code reading of `address_check_callback` [7](#0-6)  and `nep_141_storage_balance_callback` [8](#0-7) , contrasted with the refund logic present only in `rlp_execute_callback` [1](#0-0) . The existing test `test_caller_refunds` [9](#0-8)  only exercises the direct `action_to_promise` path (which does correctly refund), and does not cover the `address_check_callback` / `nep_141_storage_balance_callback` failure branches — confirming the gap is untested. I was not able to fully verify the definition of `CallerDeposit`/`ExecutionContext` (the `types.rs`/`internal.rs` file contents were not retrievable within the available tool budget), so the exact refund amount semantics (e.g., whether `yocto_near` fully represents the original attached deposit in all cases) should be double-checked by a follow-up session with full file access.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L130-192)
```rust
    /// Callback after checking if an address is contained in the registrar.
    /// This check happens when the target is another eth implicit account to
    /// confirm that the relayer really did check for a named account with that address.
    #[private]
    pub fn address_check_callback(
        &mut self,
        target: AccountId,
        action: near_action::Action,
        caller_deposit: Option<CallerDeposit>,
    ) -> PromiseOrValue<ExecuteResponse> {
        self.has_in_flight_tx = false;
        let maybe_account_id: Option<AccountId> = match env::promise_result(0) {
            PromiseResult::Failed => {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Call to Address Registrar contract failed".into()),
                });
            }
            PromiseResult::Successful(value) => match serde_json::from_slice(&value) {
                Ok(x) => x,
                Err(_) => {
                    return PromiseOrValue::Value(ExecuteResponse {
                        success: false,
                        success_value: None,
                        error: Some("Unexpected response from account registrar".into()),
                    });
                }
            },
        };
        let current_account_id = env::current_account_id();
        let promise = if maybe_account_id.is_some() {
            // We intentionally do not increment the nonce in this case because the
            // error is caused by a faulty relayer, not the user. An honest relayer
            // may still be able to successfully send the user's intended transaction.
            if env::signer_account_id() == current_account_id {
                create_ban_relayer_promise(current_account_id)
            } else {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Invalid target: target is address corresponding to existing named account_id".into()),
                });
            }
        } else {
            // We must increment the nonce at this point to prevent replay of the transaction.
            // Recall that the nonce was not incremented in `inner_rlp_execute` in the case that
            // the registrar contract was called (i.e. in the case we end up inside this callback).
            self.nonce = self.nonce.saturating_add(1);
            let ext =
                WalletContract::ext(current_account_id).with_static_gas(RLP_EXECUTE_CALLBACK_GAS);
            match action_to_promise(target, action)
                .map(|p| p.then(ext.rlp_execute_callback(caller_deposit)))
            {
                Ok(p) => p,
                Err(e) => {
                    return PromiseOrValue::Value(e.into());
                }
            }
        };
        self.has_in_flight_tx = true;
        PromiseOrValue::Promise(promise)
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L194-273)
```rust
    #[private]
    pub fn nep_141_storage_balance_callback(
        &mut self,
        token_id: AccountId,
        receiver_id: AccountId,
        action: near_action::Action,
        caller_deposit: Option<CallerDeposit>,
    ) -> PromiseOrValue<ExecuteResponse> {
        self.has_in_flight_tx = false;
        let maybe_storage_balance: Option<StorageBalance> = match env::promise_result(0) {
            PromiseResult::Failed => {
                return PromiseOrValue::Value(ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some(format!("Call to NEP-141 {token_id}::storage_balance_of failed")),
                });
            }
            PromiseResult::Successful(value) => match serde_json::from_slice(&value) {
                Ok(x) => x,
                Err(_) => {
                    return PromiseOrValue::Value(ExecuteResponse {
                        success: false,
                        success_value: None,
                        error: Some("Unexpected response from NEP-141 storage_balance_of".into()),
                    });
                }
            },
        };
        let current_account_id = env::current_account_id();
        let ext = WalletContract::ext(current_account_id).with_static_gas(RLP_EXECUTE_CALLBACK_GAS);
        let promise = match maybe_storage_balance {
            Some(_) => {
                // receiver_id is registered so we can send the transfer
                // without additional actions. Note: in the standard NEP-141
                // implementation it is impossible to have `Some` storage balance,
                // but have it be insufficient to transact.
                match action_to_promise(token_id, action)
                    .map(|p| p.then(ext.rlp_execute_callback(caller_deposit)))
                {
                    Ok(p) => p,
                    Err(e) => {
                        return PromiseOrValue::Value(e.into());
                    }
                }
            }
            None => {
                // receiver_id is not registered so we must call `storage_deposit` first.
                let storage_deposit_args =
                    format!(r#"{{"account_id": "{receiver_id}"}}"#).into_bytes();
                let transfer_function_call = match action {
                    near_action::Action::FunctionCall(x) => x,
                    _ => {
                        return PromiseOrValue::Value(ExecuteResponse {
                            success: false,
                            success_value: None,
                            error: Some(
                                "Expected function call action to perform NEP-141 transfer".into(),
                            ),
                        });
                    }
                };
                Promise::new(token_id)
                    .function_call(
                        "storage_deposit".into(),
                        storage_deposit_args,
                        NEP_141_STORAGE_DEPOSIT_AMOUNT,
                        NEP_141_STORAGE_DEPOSIT_GAS,
                    )
                    .function_call(
                        transfer_function_call.method_name,
                        transfer_function_call.args,
                        transfer_function_call.deposit,
                        transfer_function_call.gas,
                    )
                    .then(ext.rlp_execute_callback(caller_deposit))
            }
        };
        self.has_in_flight_tx = true;
        PromiseOrValue::Promise(promise)
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L296-312)
```rust
        match env::promise_result(0) {
            PromiseResult::Failed => {
                // The cross-contract call failed, refund the caller if needed
                if let Some(CallerDeposit { account_id, yocto_near }) = caller_deposit {
                    let refund_promise = env::promise_batch_create(&account_id);
                    env::promise_batch_action_transfer(
                        refund_promise,
                        NearToken::from_yoctonear(yocto_near.into()),
                    );
                }

                ExecuteResponse {
                    success: false,
                    success_value: None,
                    error: Some("Failed Near promise".into()),
                }
            }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L340-345)
```rust
    let context = ExecutionContext::new(
        current_account_id.clone(),
        predecessor_account_id,
        env::attached_deposit(),
    )?;
    let caller_deposit = CallerDeposit::new(&context);
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L412-432)
```rust
    let promise = match transaction_kind {
        TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
            address_check: Some(address),
            ..
        }) => {
            let callback_gas = ADDRESS_CHECK_CALLBACK_GAS.saturating_add(action.gas());
            let ext = WalletContract::ext(current_account_id).with_static_gas(callback_gas);
            let address_registrar = {
                let account_id = ADDRESS_REGISTRAR_ACCOUNT_ID
                    .trim()
                    .parse()
                    .unwrap_or_else(|_| env::panic_str("Invalid address registrar"));
                ext_registrar::ext(account_id).with_static_gas(REGISTRAR_LOOKUP_GAS)
            };
            let address = format!("0x{}", hex::encode(address));
            address_registrar.lookup(address).then(ext.address_check_callback(
                target,
                action,
                caller_deposit,
            ))
        }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L433-458)
```rust
        TransactionKind::EthEmulation(EthEmulationKind::ERC20Transfer { receiver_id, .. }) => {
            // In the case of the emulated ERC-20 transfer, the receiving account
            // might not be registered with the NEP-141 contract (per the NEP-145)
            // storage standard. Therefore we must create a multi-step promise where
            // first we check if the receiver is registered and then if not call
            // `storage_deposit` in addition to `ft_transfer`.
            let token_id = target;
            let callback_gas = NEP_141_STORAGE_BALANCE_CALLBACK_GAS.saturating_add(action.gas());
            let ext: WalletContractExt =
                WalletContract::ext(current_account_id).with_static_gas(callback_gas);
            let storage_balance_args =
                format!(r#"{{"account_id": "{}"}}"#, receiver_id.as_str()).into_bytes();
            Promise::new(token_id.clone())
                .function_call(
                    "storage_balance_of".into(),
                    storage_balance_args,
                    NearToken::from_yoctonear(0),
                    NEP_141_STORAGE_BALANCE_OF_GAS,
                )
                .then(ext.nep_141_storage_balance_callback(
                    token_id,
                    receiver_id,
                    action,
                    caller_deposit,
                ))
        }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/tests/sanity.rs (L170-229)
```rust
// An external caller gets its deposit back if the cross-contract call fails.
#[tokio::test]
async fn test_caller_refunds() -> anyhow::Result<()> {
    let TestContext { worker, wallet_contract, wallet_sk, address_registrar, .. } =
        TestContext::new().await?;

    let caller = worker.root_account()?;
    let deposit_amount = NearToken::from_near(3);
    let create_tx = |receiver_id: &AccountId, nonce: u64| {
        let method = "register";
        let args = br#"{"account_id": "birchmd.near"}"#;
        let action = Action::FunctionCall {
            receiver_id: receiver_id.to_string(),
            method_name: method.into(),
            args: args.to_vec(),
            gas: Gas::from_tgas(10).as_gas(),
            yocto_near: 0,
        };
        utils::create_signed_transaction(
            nonce,
            receiver_id,
            Wei::new_u128(deposit_amount.as_yoctonear() / (MAX_YOCTO_NEAR as u128)),
            action,
            &wallet_sk,
        )
    };

    // External caller gets a refund when the cross-contract call fails
    let pre_tx_account_balance = caller.view_account().await?.balance;
    let receiver_id: AccountId = "fake.near".parse()?;
    let result = wallet_contract
        .rlp_execute_from(
            &caller,
            receiver_id.as_str(),
            &create_tx(&receiver_id, 0),
            deposit_amount,
        )
        .await?;
    assert!(!result.success);
    let post_tx_account_balance = caller.view_account().await?.balance;
    assert!(
        pre_tx_account_balance.as_yoctonear() - post_tx_account_balance.as_yoctonear()
            < deposit_amount.as_yoctonear()
    );

    // External caller does not get a refund when their tokens are spent
    let pre_tx_account_balance = post_tx_account_balance;
    let receiver_id = address_registrar.id();
    let result = wallet_contract
        .rlp_execute_from(&caller, receiver_id.as_str(), &create_tx(receiver_id, 1), deposit_amount)
        .await?;
    assert!(result.success);
    let post_tx_account_balance = caller.view_account().await?.balance;
    assert!(
        pre_tx_account_balance.as_yoctonear() - post_tx_account_balance.as_yoctonear()
            >= deposit_amount.as_yoctonear()
    );

    Ok(())
}
```
