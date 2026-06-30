### Title
Permanent Fund Loss When `ExitToNear` Promise Fails Without `error_refund` Feature - (`engine-precompiles/src/native.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

When a user calls the `ExitToNear` precompile to bridge tokens from Aurora EVM to NEAR, the ERC-20 tokens are burned (or ETH is transferred to the precompile address) before the outbound `ft_transfer` promise is dispatched. If that promise fails and the `error_refund` compile-time feature is not enabled, no refund callback is ever executed and the burned/transferred funds are permanently lost. This is the direct analog of the Astaria "no-bidder auction" bug: a process ends with no successful recipient, and the rightful owner (the user) receives nothing back.

---

### Finding Description

The `ExitToNear` precompile constructs a `ExitToNearPrecompileCallbackArgs` struct whose `refund` field is unconditionally set to `None` when the `error_refund` Cargo feature is absent: [1](#0-0) 

The `contract` production feature does **not** include `error_refund`: [2](#0-1) 

Because `refund` is `None` and `transfer_near` is also `None` for a plain ERC-20 or ETH exit, `callback_args` equals `ExitToNearPrecompileCallbackArgs::default()`, so the branch at line 470 emits a bare `PromiseArgs::Create` — **no callback is attached at all**: [3](#0-2) 

For the wNEAR-unwrap path (`transfer_near` is `Some`), a callback *is* attached, but `exit_to_near_precompile_callback` falls into the `else { None }` arm when the promise fails because `args.refund` is `None`: [4](#0-3) 

In both paths the ERC-20 tokens have already been burned (or ETH transferred to `exit_to_near::ADDRESS`) before the promise is dispatched, so a failed `ft_transfer` leaves the funds with no owner and no recovery path.

The test suite explicitly acknowledges this behavior: [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

- For ERC-20 exits: tokens are burned on Aurora before the outbound promise. A failed `ft_transfer` (e.g., unregistered recipient, paused NEP-141 contract, out-of-gas) leaves the supply permanently reduced with no corresponding NEP-141 balance anywhere.
- For ETH exits: ETH is moved to `exit_to_near::ADDRESS` before the promise. A failed `ft_transfer` leaves that ETH locked in the precompile address with no mechanism to recover it. [6](#0-5) 

---

### Likelihood Explanation

Any unprivileged EVM user who calls the `ExitToNear` precompile with a NEAR recipient that is not registered with the target NEP-141 contract will trigger this path. The test `test_exit_to_near_refund` demonstrates exactly this scenario (recipient `"unregistered.near"`). The `ft_transfer` call can also fail due to contract-side pausing or gas exhaustion, all of which are realistic on-chain conditions. [7](#0-6) 

---

### Recommendation

Enable the `error_refund` feature unconditionally in the production `contract` feature set, or restructure the refund logic so it does not depend on a compile-time flag. The `refund_call_args` helper already exists and correctly captures the recipient address and amount; it should always be included in `ExitToNearPrecompileCallbackArgs` so that `exit_to_near_precompile_callback` can always issue a refund on failure. [8](#0-7) 

---

### Proof of Concept

1. User holds ERC-20 tokens on Aurora backed by a NEP-141.
2. User calls the `ExitToNear` precompile (flag `0x01`) specifying an unregistered NEAR account as recipient.
3. The precompile burns the ERC-20 tokens and emits a `PromiseArgs::Create` log (no callback, because `error_refund` is off and `transfer_near` is `None`).
4. `filter_promises_from_logs` schedules the bare `ft_transfer` promise.
5. The NEP-141 contract rejects the transfer (recipient not registered).
6. No callback fires; no refund is issued.
7. The ERC-20 tokens are permanently burned; the NEP-141 balance remains with the Aurora contract; the user has lost their funds with no recourse. [9](#0-8) [10](#0-9)

### Citations

**File:** engine-precompiles/src/native.rs (L449-484)
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
        let promise_log = Log {
```

**File:** engine-precompiles/src/native.rs (L699-725)
```rust
#[cfg(feature = "error_refund")]
#[allow(clippy::unnecessary_wraps)]
fn refund_call_args(
    params: &ExitToNearParams,
    event: &events::ExitToNear,
) -> Option<RefundCallArgs> {
    Some(RefundCallArgs {
        recipient_address: match params {
            ExitToNearParams::BaseToken(params) => params.refund_address,
            ExitToNearParams::Erc20TokenParams(params) => params.refund_address,
        },
        erc20_address: match params {
            ExitToNearParams::BaseToken(_) => None,
            ExitToNearParams::Erc20TokenParams(_) => {
                let erc20_address = match event {
                    events::ExitToNear::Legacy(legacy) => legacy.erc20_address,
                    events::ExitToNear::Omni(omni) => omni.erc20_address,
                };
                Some(erc20_address)
            }
        },
        amount: types::u256_to_arr(&match event {
            events::ExitToNear::Legacy(legacy) => legacy.amount,
            events::ExitToNear::Omni(omni) => omni.amount,
        }),
    })
}
```

**File:** engine/Cargo.toml (L45-48)
```text
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
```

**File:** engine/src/contract_methods/connector.rs (L231-242)
```rust
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

**File:** engine-tests/src/tests/erc20_connector.rs (L635-645)
```rust
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
```

**File:** engine-tests/src/tests/erc20_connector.rs (L656-665)
```rust
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

**File:** engine/src/engine.rs (L1204-1224)
```rust
    } else {
        // ETH exit; transfer ETH back from precompile address
        let exit_address = exit_to_near::ADDRESS;
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, exit_address, current_account_id, io, env);
        let refund_address = args.recipient_address;
        let amount = Wei::new(U256::from_big_endian(&args.amount));
        engine.call(
            &exit_address,
            &refund_address,
            amount,
            Vec::new(),
            u64::MAX,
            vec![
                (exit_address.raw(), Vec::new()),
                (refund_address.raw(), Vec::new()),
            ],
            Vec::new(),
            handler,
        )
    }
```

**File:** engine/src/engine.rs (L1634-1685)
```rust
fn filter_promises_from_logs<I, T, P>(
    io: &I,
    handler: &mut P,
    logs: T,
    current_account_id: &AccountId,
) -> Vec<ResultLog>
where
    T: IntoIterator<Item = Log>,
    P: PromiseHandler,
    I: IO + Copy,
{
    let mut previous_promise: Option<PromiseId> = None;
    logs.into_iter()
        .filter_map(|log| {
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
```
