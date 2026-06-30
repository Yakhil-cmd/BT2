### Title
wNEAR Unwrap Exit: Permanent NEAR Freeze When Target Account Does Not Exist - (`engine-precompiles/src/native.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

The `exitToNear` precompile's wNEAR unwrap path is a two-step cross-contract process. Step 1 (`near_withdraw`) burns the user's ERC-20 wNEAR and NEP-141 wNEAR, crediting raw NEAR to the Aurora engine contract. Step 2 (`exit_to_near_precompile_callback`) transfers that NEAR to the user-supplied `target_account_id`. No validation is performed on `target_account_id` existence before step 1 commits, and no failure-recovery callback is attached to the step-2 transfer promise. If the NEAR transfer fails (e.g., target account does not exist), the NEAR is permanently frozen inside the Aurora engine contract with no rescue path.

---

### Finding Description

The wNEAR unwrap flow is initiated when a user calls the `exitToNear` precompile (address `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) with flag `0x1` (ERC-20 exit) and a recipient string containing the `:unwrap` suffix.

**Step 1 — Commitment (irreversible):**

In `exit_erc20_token_to_near`, when `Message::UnwrapWnear` is matched, the function schedules `near_withdraw` on the wNEAR NEP-141 contract. This burns the user's ERC-20 wNEAR on Aurora and burns the corresponding NEP-141 wNEAR, crediting raw NEAR yocto to the Aurora engine account. The `target_account_id` is stored in `TransferNearArgs` without any existence check. [1](#0-0) 

**Step 2 — Completion (no failure recovery):**

`exit_to_near_precompile_callback` is the callback for `near_withdraw`. When `near_withdraw` succeeds, it schedules a `PromiseBatchAction` with a plain `Transfer` action to `args.target_account_id`. Critically, **no callback is attached to this transfer promise**. If the transfer fails (e.g., the target account does not exist on NEAR), the NEAR stays in the Aurora engine contract and there is no code path to refund or recover it. [2](#0-1) 

The existing `refund` branch only fires when `near_withdraw` itself fails — it does not cover the case where `near_withdraw` succeeds but the subsequent NEAR transfer fails: [3](#0-2) 

There is no admin rescue function in the engine contract for stuck NEAR. A search of `engine/src/` confirms no `rescue`, `recover`, or equivalent method exists.

---

### Impact Explanation

When the NEAR transfer in step 2 fails:
- The user's ERC-20 wNEAR is permanently burned (EVM state committed in the original `submit` call).
- The NEP-141 wNEAR is permanently burned (`near_withdraw` succeeded).
- The raw NEAR yocto credited to the Aurora engine contract is permanently inaccessible to the user.

This is a **permanent freezing of funds** with no recovery path for the affected user.

---

### Likelihood Explanation

The `target_account_id` is fully user-controlled input parsed from the precompile calldata. Any of the following realistic scenarios triggers the freeze:

1. A user makes a typo in the recipient NEAR account name (e.g., `alice.nea` instead of `alice.near`).
2. A Solidity contract calls the precompile with a programmatically constructed recipient that does not yet exist on NEAR.
3. A target account is deleted between the time the EVM transaction is submitted and the time the NEAR transfer receipt executes (NEAR accounts can be deleted).

The precompile is reachable by any unprivileged EVM user or contract. No special role is required.

---

### Recommendation

1. **Attach a failure callback to the NEAR transfer promise** in `exit_to_near_precompile_callback`. If the transfer fails, the callback should re-mint the equivalent wNEAR ERC-20 tokens to the original sender (analogous to the existing `refund_on_error` path used when `near_withdraw` fails).

2. **Alternatively**, validate that `target_account_id` exists on NEAR before initiating the exit. This can be done by adding a view-call check in the precompile or by requiring the user to pre-register the recipient.

---

### Proof of Concept

1. User holds wNEAR ERC-20 on Aurora (e.g., 1 NEAR worth).
2. User calls the `exitToNear` precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` with input: `[0x01][amount_32_bytes][nonexistent.near:unwrap]`.
3. Aurora EVM burns the wNEAR ERC-20 balance (EVM state committed).
4. NEAR runtime executes `near_withdraw` on the wNEAR NEP-141 contract — succeeds, 1 NEAR credited to Aurora engine.
5. NEAR runtime executes `exit_to_near_precompile_callback` — `near_withdraw` result is `Successful`, so a `Transfer` of 1 NEAR to `nonexistent.near` is scheduled.
6. NEAR runtime executes the transfer — fails because `nonexistent.near` does not exist. NEAR stays in Aurora engine.
7. No callback on the transfer promise fires. No refund is issued. User's 1 NEAR is permanently frozen. [4](#0-3) [5](#0-4)

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

**File:** engine-precompiles/src/native.rs (L585-609)
```rust
    let (nep141_account_id, args, method, transfer_near_args, event) = match exit_params.message {
        // wNEAR address should be set via the `factory_set_wnear_address` transaction first.
        Some(Message::UnwrapWnear) if erc20_address == get_wnear_address(io).raw() =>
        // The flow is following here:
        // 1. We call `near_withdraw` on wNEAR account id on `aurora` behalf.
        // In such way we unwrap wNEAR to NEAR.
        // 2. After that, we call callback `exit_to_near_precompile_callback` on the `aurora`
        // in which make transfer of unwrapped NEAR to the `target_account_id`.
        {
            (
                nep141_account_id,
                format!(r#"{{"amount":"{}"}}"#, exit_params.amount.as_u128()),
                "near_withdraw",
                Some(TransferNearArgs {
                    target_account_id: exit_params.receiver_account_id.clone(),
                    amount: exit_params.amount.as_u128(),
                }),
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
```

**File:** engine/src/contract_methods/connector.rs (L214-244)
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

        Ok(maybe_result)
```
