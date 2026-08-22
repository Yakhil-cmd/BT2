This is a genuine analog. Looking at `inner_rlp_execute` in `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`, the relayer fee refund `Transfer` promise is created and fired **independently of whether the underlying emulated action (base-token transfer or NEP-141 `ft_transfer`) actually succeeds**.

### Title
Relayer fee is paid unconditionally even when the emulated base-token/ERC-20 transfer fails - (File: runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs)

### Summary
In `inner_rlp_execute`, for `EOABaseTokenTransfer` and `ERC20Transfer` eth-emulation kinds, a separate `promise_batch_action_transfer` refund to the relayer (`context.predecessor_account_id`) is scheduled at the moment the transaction is parsed, before the actual transfer/`ft_transfer` promise is even dispatched, and with no callback tying its execution to the outcome of that action. [1](#0-0) 

### Finding Description
The relayer fee is sent via a standalone `Promise::new(predecessor_id).transfer(fee)` batch that is not chained (`.then(...)`) to the main action promise (the base-token `Promise::new(target).transfer(...)` or the NEP-141 `ft_transfer` function call chain built later in the same function). [2](#0-1)  Because the two promises are independent receipts with no result dependency, the fee transfer executes and succeeds regardless of whether the corresponding user transfer (`action_to_promise` at line 469, or the `ft_transfer`/`storage_deposit` chain built in `nep_141_storage_balance_callback`) succeeds or fails. [3](#0-2) [4](#0-3)  The only place where a failed promise result is checked and a refund is issued is `rlp_execute_callback`, but that refund only covers `caller_deposit` (the attached NEAR the caller sent for the action itself), not the relayer fee. [5](#0-4) 

This is directly analogous to the reported bug class: a token-transfer-adjacent operation's success/failure is not checked before crediting/debiting further state — here the relayer is paid its fee without any confirmation that the promised NEP-141 `ft_transfer` (or NEAR transfer) it was compensated for actually completed. If the emulated ERC-20 `ft_transfer` fails (e.g., insufficient balance, paused contract, receiver not registered in ways not caught by the storage-balance pre-check, or the token contract reverting for any reason), the wallet contract's owner still pays the relayer's fee out of their own account balance for a transfer that never happened.

### Impact Explanation
This causes unauthorized/incorrect balance changes: the wallet-contract's owner (an ETH-emulated NEAR account) loses NEAR to the relayer as compensation for work whose supposed outcome (the underlying token transfer) never took effect. A malicious or buggy relayer, or a token contract that unexpectedly fails, results in the user paying a fee for a failed transaction while gaining no corresponding action.

### Likelihood Explanation
Reachable directly from an unprivileged relayer/user submitting an RLP-encoded Ethereum transaction to `rlp_execute` — any account can drive this path (`EOABaseTokenTransfer` and `ERC20Transfer` kinds), it requires no privileged access, and the failure of the downstream cross-contract call (NEP-141 `ft_transfer`) is a normal occurrence (e.g., NEP-141 contract paused, blacklist, insufficient balance) not tied to any validator or node-level condition.

### Recommendation
Chain the fee-refund transfer to the outcome of the underlying action instead of firing it unconditionally: create the relayer-fee transfer as part of the same promise batch/receipt as the action, or move its scheduling into `rlp_execute_callback`/`nep_141_storage_balance_callback` guarded on `PromiseResult::Successful`, mirroring how `caller_deposit` refunds are already conditioned on failure in `rlp_execute_callback`.

### Proof of Concept
1. A relayer submits an RLP transaction representing an `ERC20Transfer` with a non-zero `fee` to `rlp_execute`.
2. `inner_rlp_execute` immediately schedules `promise_batch_action_transfer(refund_promise, fee)` to the relayer at lines 382–384, independent of the subsequent `ft_transfer`/`storage_deposit` promise chain.
3. The NEP-141 token contract's `ft_transfer` fails (e.g., contract paused or receiver blacklisted) — `nep_141_storage_balance_callback`/`rlp_execute_callback` observes `PromiseResult::Failed` and reports failure to the caller, refunding only `caller_deposit` if present. [6](#0-5) 
4. The relayer nonetheless already received the `fee` transfer from step 2, which was never rolled back, since it was an entirely separate receipt with no dependency on the transfer's result.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L230-269)
```rust
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
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L296-317)
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
            PromiseResult::Successful(value) => {
                ExecuteResponse { success: true, success_value: Some(value), error: None }
            }
        }
    }
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L367-385)
```rust
            // If the action is an emulated base token or ERC-20 transfer with a non-zero fee then
            // create a promise to send the refund to the relayer. This allows any relayer
            // to safely serve base token transfers from any wallet without additional
            // on-boarding because the relayer will receive some compensation for sending
            // the transaction. Users should always verify the fee before signing a base token
            // transfer. Relayers should also verify the fee before sending to make sure the
            // user's signed transaction will refund enough to cover the relayer's gas costs.
            if let TransactionKind::EthEmulation(EthEmulationKind::EOABaseTokenTransfer {
                fee,
                ..
            })
            | TransactionKind::EthEmulation(EthEmulationKind::ERC20Transfer { fee, .. }) =
                &transaction_kind
            {
                if !fee.is_zero() && context.predecessor_account_id != context.current_account_id {
                    let refund_promise = env::promise_batch_create(&context.predecessor_account_id);
                    env::promise_batch_action_transfer(refund_promise, *fee);
                }
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
