### Title
`ExitToNear` and `ExitToEthereum` Exit Events Emitted Unconditionally Before NEAR Promise Execution, Causing Permanent Fund Loss on Promise Failure - (File: `engine-precompiles/src/native.rs`)

---

### Summary

Both the `ExitToNear` and `ExitToEthereum` precompiles emit their respective EVM exit events (`ExitToNear` / `ExitToEth`) **unconditionally** as part of the EVM transaction result, before the corresponding NEAR-side promise (`ft_transfer`, `ft_transfer_call`, or `withdraw`) is executed. If the NEAR promise subsequently fails, the exit event has already been finalized in the EVM transaction log, falsely claiming the bridge transfer succeeded. Without the optional `error_refund` compile-time feature, there is no refund path, resulting in permanent loss of the bridged tokens.

---

### Finding Description

In `engine-precompiles/src/native.rs`, both `ExitToNear::run()` and `ExitToEthereum::run()` construct two logs and return them together in `PrecompileOutput`:

1. A **promise log** (empty `topics`) — an internal signal to schedule the NEAR promise.
2. An **exit event log** (non-empty `topics`) — the externally visible `ExitToNear` or `ExitToEth` EVM event.

Both are returned unconditionally:

```rust
Ok(PrecompileOutput {
    logs: vec![promise_log, exit_event_log],
    cost: required_gas,
    output: Vec::new(),
})
``` [1](#0-0) 

In `engine/src/engine.rs`, `filter_promises_from_logs` processes these logs: logs from exit precompile addresses with **empty** topics are consumed internally to schedule the NEAR promise; logs with **non-empty** topics are passed through as external result logs to the caller. [2](#0-1) 

This means the `ExitToNear` / `ExitToEth` event is committed to the EVM transaction result at the time the EVM execution completes — before the NEAR promise runs. The NEAR promise (`ft_transfer`, `ft_transfer_call`, or `withdraw`) executes asynchronously in a subsequent NEAR receipt. If that promise fails (e.g., recipient account not registered with the NEP-141 contract, insufficient gas, contract panic), the EVM exit event has already been finalized and cannot be reverted.

For `ExitToNear`, a `error_refund` compile-time feature exists that, when enabled, attaches a callback (`exit_to_near_precompile_callback`) to mint tokens back on failure: [3](#0-2) 

However, `error_refund` is **not** a default feature (it does not appear in any `Cargo.toml` `[features]` default list), and the test suite explicitly documents the no-refund behavior when it is absent: [4](#0-3) 

For `ExitToEthereum`, **no refund mechanism exists at all** — the `withdraw` promise is always scheduled as `PromiseArgs::Create` with no callback: [5](#0-4) 

The `exit_to_near_precompile_callback` in `engine/src/contract_methods/connector.rs` confirms: only when `error_refund` is compiled in and the promise fails does a refund occur; otherwise the failure is silently ignored. [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing/theft of funds.**

When a user calls `ExitToNear` (ERC-20 or ETH exit) or `ExitToEthereum`:

1. Tokens are burned/deducted from the EVM side (state committed).
2. The `ExitToNear` / `ExitToEth` event is emitted, claiming the bridge transfer occurred.
3. The NEAR promise fails (e.g., unregistered recipient, gas exhaustion).
4. Without `error_refund`: no EVM-side refund is issued. Tokens are permanently lost — burned from EVM, never received on NEAR/Ethereum.
5. Off-chain indexers and bridge monitors that consume the `ExitToNear`/`ExitToEth` event log treat the transfer as successful, producing incorrect bridge accounting state.

This is a direct analog to the THORChain H-02 finding: an event claiming a transfer succeeded is emitted even when the actual cross-chain transfer fails, and the off-chain system updates state based on the misleading event.

---

### Likelihood Explanation

**High.** The failure condition is easily triggered by any unprivileged user:

- Calling `ExitToNear` with a recipient NEAR account that has not registered storage with the NEP-141 contract causes `ft_transfer` to fail. This is a standard NEP-141 requirement and a common user mistake.
- The `ExitToEthereum` `withdraw` call can fail if the ETH connector contract is paused, has insufficient balance, or the call panics for any reason.
- No special privileges are required; any EVM user can trigger this by calling the exit precompile with a valid-looking but unregistered recipient.

---

### Recommendation

1. **Primary fix (analogous to THORChain recommendation #1):** Make the `error_refund` feature the **default** (or unconditional) behavior for `ExitToNear`. Attach a refund callback for all exit paths, not just when the feature flag is set.

2. **For `ExitToEthereum`:** Add a callback to the `withdraw` promise that detects failure and mints back the equivalent ERC-20 tokens (or ETH) to the original sender on the EVM side.

3. **Alternatively:** Emit the exit event log **only inside the callback**, after confirming the NEAR promise succeeded. This requires restructuring the log emission to occur in `exit_to_near_precompile_callback` rather than in the precompile's `run()` method.

4. **Minimum mitigation:** Document and enforce that the `error_refund` feature must be enabled in all production builds, and add a compile-time assertion or build check to prevent deployment without it.

---

### Proof of Concept

1. Deploy an ERC-20 token on Aurora that is bridged to a NEP-141 contract.
2. Call `ExitToNear` from an EVM address, specifying a NEAR recipient account that has **not** registered storage with the NEP-141 contract (e.g., a freshly created account).
3. Observe: the EVM transaction succeeds, ERC-20 tokens are burned, and the `ExitToNear` event is emitted in the transaction receipt.
4. Observe: the NEAR `ft_transfer` receipt fails with a storage registration error.
5. Without `error_refund`: the ERC-20 tokens are permanently gone — burned from EVM, not received on NEAR. The `ExitToNear` event in the EVM receipt falsely indicates a successful bridge transfer.

The existing test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` (lines 623–665) already demonstrates this exact scenario and explicitly confirms that without `error_refund`, `FT_EXIT_AMOUNT` tokens are permanently lost. [7](#0-6)

### Citations

**File:** engine-precompiles/src/native.rs (L449-483)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
        let attached_gas = if method == "ft_transfer_call" {
            costs::FT_TRANSFER_CALL_GAS
        } else {
            costs::FT_TRANSFER_GAS
        };

        let transfer_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method,
            args: args.into_bytes(),
            attached_balance: Yocto::new(1),
            attached_gas,
        };

        let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
            PromiseArgs::Create(transfer_promise)
        } else {
            PromiseArgs::Callback(PromiseWithCallbackArgs {
                base: transfer_promise,
                callback: PromiseCreateArgs {
                    target_account_id: self.current_account_id.clone(),
                    method: "exit_to_near_precompile_callback".to_string(),
                    args: borsh::to_vec(&callback_args).unwrap(),
                    attached_balance: Yocto::new(0),
                    attached_gas: costs::EXIT_TO_NEAR_CALLBACK_GAS,
                },
            })
        };
```

**File:** engine-precompiles/src/native.rs (L484-500)
```rust
        let promise_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: Vec::new(),
            data: borsh::to_vec(&promise).unwrap(),
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
            cost: required_gas,
            output: Vec::new(),
        })
```

**File:** engine-precompiles/src/native.rs (L977-999)
```rust
        let withdraw_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method: "withdraw".to_string(),
            args: serialized_args,
            attached_balance: Yocto::new(1),
            attached_gas: costs::WITHDRAWAL_GAS,
        };

        let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
        let promise_log = Log {
            address: exit_to_ethereum::ADDRESS.raw(),
            topics: Vec::new(),
            data: promise,
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_ethereum::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
```

**File:** engine/src/engine.rs (L1648-1691)
```rust
            if log.address == exit_to_near::ADDRESS.raw()
                || log.address == exit_to_ethereum::ADDRESS.raw()
            {
                if log.topics.is_empty() {
                    if let Ok(promise) = PromiseArgs::try_from_slice(&log.data) {
                        match promise {
                            PromiseArgs::Create(promise) => {
                                // Safety: this promise creation is safe because it does not come from
                                // users directly. The exit precompile only create promises which we
                                // are able to execute without violating any security invariants.
                                let id = match previous_promise {
                                    Some(base_id) => {
                                        schedule_promise_callback(handler, base_id, &promise)
                                    }
                                    None => schedule_promise(handler, &promise),
                                };
                                previous_promise = Some(id);
                            }
                            PromiseArgs::Callback(promise) => {
                                // Safety: This is safe because the promise data comes from our own
                                // exit precompiles. See note above.
                                let base_id = match previous_promise {
                                    Some(base_id) => {
                                        schedule_promise_callback(handler, base_id, &promise.base)
                                    }
                                    None => schedule_promise(handler, &promise.base),
                                };
                                let id =
                                    schedule_promise_callback(handler, base_id, &promise.callback);
                                previous_promise = Some(id);
                            }
                            PromiseArgs::Recursive(_) => {
                                unreachable!("Exit precompiles do not produce recursive promises")
                            }
                        }
                    }
                    // do not pass on these "internal logs" to the caller
                    None
                } else {
                    // The exit precompile does produce externally consumable logs in
                    // addition to the promises. The external logs have a non-empty
                    // `topics` field.
                    Some(evm_log_to_result_log(log))
                }
```

**File:** engine-tests/src/tests/erc20_connector.rs (L623-665)
```rust
    #[tokio::test]
    async fn test_exit_to_near_refund() {
        // Deploy Aurora; deploy NEP-141; bridge NEP-141 to ERC-20 on Aurora
        let TestExitToNearContext {
            ft_owner,
            ft_owner_address,
            nep_141,
            erc20,
            aurora,
            ..
        } = test_exit_to_near_common().await.unwrap();

        // Call exit on ERC-20; ft_transfer promise fails; expect refund on Aurora;
        exit_to_near(
            &ft_owner,
            // The ft_transfer will fail because this account is not registered with the NEP-141
            "unregistered.near",
            FT_EXIT_AMOUNT,
            &erc20,
            &aurora,
        )
        .await
        .unwrap();

        assert_eq!(
            nep_141_balance_of(&nep_141, &ft_owner.id()).await,
            FT_TOTAL_SUPPLY - FT_TRANSFER_AMOUNT
        );
        assert_eq!(
            nep_141_balance_of(&nep_141, &aurora.id()).await,
            FT_TRANSFER_AMOUNT
        );

        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();

        assert_eq!(
            erc20_balance(&erc20, ft_owner_address, &aurora).await,
            balance
        );
```

**File:** engine/src/contract_methods/connector.rs (L214-242)
```rust
        let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
            if let Some(args) = args.transfer_near {
                let action = PromiseAction::Transfer {
                    amount: Yocto::new(args.amount),
                };
                let promise = PromiseBatchAction {
                    target_account_id: args.target_account_id,
                    actions: vec![action],
                };

                // Safety: this call is safe because it comes from the exit to near precompile, not users.
                // The call is to transfer the unwrapped wNEAR tokens.
                let promise_id = handler.promise_create_batch(&promise);
                handler.promise_return(promise_id);
            }

            None
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
        } else {
            None
        };
```
