### Title
Relayer fee is paid unconditionally before the underlying user action executes, allowing fee extraction with no service rendered - (File: `runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs`)

### Summary
The Sherlock report describes a pattern where one leg of a two-sided exchange (debt repayment vs. collateral transfer) is executed without verifying that the other leg actually succeeds, causing one party to pay while the other side of the exchange never completes. The `near-wallet-contract` (the eth-implicit account emulation contract) contains a structurally identical pattern: it fires a promise paying the relayer's fee unconditionally, dispatched separately from — and not gated on the success of — the promise that performs the user's actual intended action (a NEAR transfer or a NEP-141 `ft_transfer`).

### Finding Description
In `inner_rlp_execute`, once an incoming RLP-encoded transaction is parsed into a `TransactionKind::EthEmulation(...)` with a non-zero relayer `fee`, the contract immediately schedules a transfer of that fee to the relayer as an independent promise/receipt: [1](#0-0) 

This `refund_promise` (an `env::promise_batch_create` + `env::promise_batch_action_transfer` pair) is created and dispatched as a side effect of the function, entirely separate from the `promise` variable that later carries out the actual requested action (`EOABaseTokenTransfer`, `ERC20Transfer` via NEP-141 `ft_transfer`, etc.): [2](#0-1) 

For the `ERC20Transfer` case in particular, the actual action requires a multi-step, cross-contract sequence (`storage_balance_of` → possibly `storage_deposit` → `ft_transfer`) that can fail for many reasons (receiver not registered and insufficient attached deposit, insufficient token balance causing `ft_transfer` to panic, the token contract being paused, gas exhaustion, etc.): [3](#0-2) 

When the final action promise fails, the only remediation implemented is refunding the `caller_deposit` (the yoctoNEAR / NEP-141 deposit attached by the user), not the relayer fee that was already sent out at the very start: [4](#0-3) 

Because the fee-refund promise and the main-action promise are two independent, unchained receipts scheduled from the same function call, the runtime does not enforce any ordering/rollback dependency between them — the fee payment to the relayer is not conditioned on the main action succeeding. This mirrors the D3VaultLiquidation bug class: a value transfer that should be conditioned on the success of a paired operation is instead executed unconditionally, so one party can be paid without the other side of the transaction completing.

### Impact Explanation
If the primary action fails after the fee has already been transferred (e.g., the NEP-141 `ft_transfer` step reverts due to insufficient token balance, or the base-token transfer to another eth-implicit account fails), the wallet-contract account has already paid the relayer's fee out of its own NEAR balance for a service that was never rendered. This is a direct, unconditional loss of user funds from the wallet-contract account, matching the "loss of user funds" arm of the referenced report (payer pays but does not receive the corresponding value). Because `near-wallet-contract` is a production component intended to be deployed to eth-implicit accounts and driven by relayers submitting arbitrary RLP transactions, this is reachable from ordinary transaction submission with no privileged access required.

### Likelihood Explanation
The fee refund is fired on every relayed transaction that specifies a non-zero fee for `EOABaseTokenTransfer`/`ERC20Transfer`, which is the expected common case for relayer-driven usage of the wallet contract (the fee is the relayer's compensation mechanism per the code's own comments). Failure modes of the follow-on `ft_transfer`/transfer step (insufficient balance, non-existent/erroring token contract calls, gas exhaustion in the multi-hop NEP-141 path) are realistic and can occur without any malicious actor, making the unconditional loss straightforward to trigger, including by a malicious relayer intentionally submitting a transaction crafted to fail the main action while still collecting the fee.

### Recommendation
Chain the fee-refund transfer to the relayer as part of the same promise pipeline that performs the primary action (via `.then(...)`), or move it to execute only inside the final callback (`rlp_execute_callback`/`nep_141_storage_balance_callback`) after confirming `PromiseResult::Successful` for all necessary legs of the action. Alternatively, hold the fee in an escrow-like promise batch attached to the same receipt so that a failure of the primary action also fails/reverts the fee transfer.

### Proof of Concept
1. A relayer submits an RLP-encoded Ethereum-style transaction to `rlp_execute` targeting a NEP-141 token contract, encoding an ERC-20 `transfer` call, with a non-zero relayer `fee` and the receiver not yet storage-registered on the token contract.
2. `inner_rlp_execute` immediately schedules `refund_promise` sending `fee` yoctoNEAR to the relayer (`predecessor_account_id`). [5](#0-4) 
3. Separately, it schedules the `storage_balance_of` → (optional `storage_deposit`) → `ft_transfer` chain to actually perform the token transfer.
4. If the token contract's `ft_transfer` panics (e.g., attached deposit for `storage_deposit` no longer covers the standard's required amount due to a fee-charging or non-standard token contract, or the sender's token balance is insufficient), the second promise chain fails and only `caller_deposit` (not the relayer fee) is refunded in `rlp_execute_callback`. [6](#0-5) 
5. Result: the relayer has already been paid the fee (step 2) even though the user's intended token transfer never completed — a concrete, unconditional loss of user funds from the wallet-contract account.

### Citations

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L194-269)
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
```

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L275-317)
```rust
    #[private]
    pub fn rlp_execute_callback(
        &mut self,
        caller_deposit: Option<CallerDeposit>,
    ) -> ExecuteResponse {
        self.has_in_flight_tx = false;
        let n = env::promise_results_count();

        if n == 0 {
            // `rlp_execute_callback` is called directly in the case of an emulated self-transfer.
            return ExecuteResponse { success: true, success_value: None, error: None };
        } else if n > 1 {
            return ExecuteResponse {
                success: false,
                success_value: None,
                error: Some(format!(
                    "Invariant violation: this callback comes after a single promise. n={n}"
                )),
            };
        }

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

**File:** runtime/near-wallet-contract/implementation/wallet-contract/src/lib.rs (L412-458)
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
