Let me look at a few more details to complete the analysis.

### Title
Pause-Racing Leaves wNEAR Stranded in Engine's Implicit EVM Address — (`engine/src/contract_methods/xcc.rs`)

### Summary

When a user initiates an XCC call that requires wNEAR withdrawal, the XCC precompile atomically transfers wNEAR from the user's EVM address to the engine's implicit EVM address in the original EVM transaction. A subsequent `pause_contract` call before the `withdraw_wnear_to_router` NEAR callback executes causes that callback to panic at `require_running`, leaving the wNEAR stranded in the engine's implicit address with no automatic recovery path.

### Finding Description

**Step 1 — Original EVM transaction (XCC precompile):**

In `engine-precompiles/src/xcc.rs`, when `required_near != ZERO_YOCTO`, the precompile executes an EVM-internal `transferFrom` call on the wNEAR ERC-20 contract, moving wNEAR from the user's EVM address to the engine's implicit EVM address: [1](#0-0) 

This `transferFrom` is committed to Aurora EVM state as part of the original EVM transaction. After EVM execution, `handle_precompile_promise` schedules `withdraw_wnear_to_router` as a NEAR callback: [2](#0-1) 

**Step 2 — Owner calls `pause_contract`:**

`pause_contract` sets `state.is_paused = true` and commits it to NEAR storage: [3](#0-2) 

**Step 3 — NEAR delivers `withdraw_wnear_to_router` receipt:**

The callback reads the now-paused state and hits `require_running` at line 31: [4](#0-3) 

`require_running` returns `Err(ERR_PAUSED)`: [5](#0-4) 

This error propagates to `sdk_unwrap()` in `lib.rs`, which calls `panic_utf8`, causing the NEAR receipt to panic: [6](#0-5) 

**Step 4 — State divergence:**

NEAR's promise model only reverts state changes from the panicking receipt. The `transferFrom` that moved wNEAR from the user to the engine's implicit address was committed in a prior, already-finalized NEAR transaction. It is not rolled back. The wNEAR sits in the engine's implicit EVM address with no automatic refund or retry mechanism.

The `withdraw_wnear_to_router` function in `engine/src/xcc.rs` — which would have called `withdrawToNear` to burn the wNEAR and send NEAR to the router — never executes: [7](#0-6) 

### Impact Explanation

The user's wNEAR is debited from their EVM address and transferred to the engine's implicit EVM address during the original EVM transaction. When `withdraw_wnear_to_router` panics, the wNEAR remains in the engine's implicit address — an address not controlled by any private key and not directly accessible by the user. There is no on-chain retry or refund mechanism. Recovery requires the engine owner to manually identify affected users and transfer wNEAR back, which is operationally complex and error-prone. This constitutes **temporary freezing of funds** for the duration of the pause and the manual recovery period.

### Likelihood Explanation

The window between the original EVM transaction finalizing and the `withdraw_wnear_to_router` callback executing is narrow but real. Emergency pauses are precisely the scenario where this window is most likely to be hit: an operator pausing the engine in response to a security incident may not know that XCC callbacks are in-flight. The `pause_contract` function is owner-only but requires no malicious intent — a good-faith emergency pause is sufficient to trigger this.

### Recommendation

Remove the `require_running` guard from `withdraw_wnear_to_router`, or replace it with a refund path: if the engine is paused when the callback fires, transfer the wNEAR back to the originating user's EVM address rather than panicking. The callback already checks `handler.promise_result_check()` for upstream failures; a similar branch for the paused state should credit the wNEAR back to `args.target`.

Alternatively, the `handle_precompile_promise` chain could attach an error-handling callback that refunds the wNEAR to the user if `withdraw_wnear_to_router` fails for any reason, mirroring the pattern used in `exit_to_near_precompile_callback`: [8](#0-7) 

### Proof of Concept

```
1. Deploy Aurora engine locally with wNEAR bridged.
2. User submits EVM tx calling the XCC precompile with required_near > 0.
   - Confirm wNEAR transferFrom moves tokens from user to engine implicit address.
   - Confirm withdraw_wnear_to_router is scheduled as a NEAR callback.
3. Before delivering the withdraw_wnear_to_router receipt, call pause_contract
   as the engine owner (state.is_paused = true committed to storage).
4. Deliver the withdraw_wnear_to_router receipt.
   - Observe panic with ERR_PAUSED at require_running (xcc.rs:31).
5. Assert:
   - User's wNEAR balance in EVM = original - amount (not restored).
   - Engine implicit address wNEAR balance = amount (stranded).
   - Router sub-account received 0 NEAR.
   - No refund promise was created.
```

### Citations

**File:** engine-precompiles/src/xcc.rs (L184-216)
```rust
        if required_near != ZERO_YOCTO {
            let engine_implicit_address = aurora_engine_sdk::types::near_account_to_evm_address(
                self.engine_account_id.as_bytes(),
            );
            let tx_data = transfer_from_args(
                sender.0.into(),
                engine_implicit_address.raw().0.into(),
                required_near.as_u128().into(),
            );
            let wnear_address = state::get_wnear_address(&self.io);
            let context = aurora_evm::Context {
                address: wnear_address.raw(),
                caller: cross_contract_call::ADDRESS.raw(),
                apparent_value: U256::zero(),
            };
            let (exit_reason, return_value) =
                handle.call(wnear_address.raw(), None, tx_data, None, false, &context);
            match exit_reason {
                // Transfer successful, nothing to do
                aurora_evm::ExitReason::Succeed(_) => (),
                aurora_evm::ExitReason::Revert(r) => {
                    return Err(PrecompileFailure::Revert {
                        exit_status: r,
                        output: return_value,
                    });
                }
                aurora_evm::ExitReason::Error(e) => {
                    return Err(PrecompileFailure::Error { exit_status: e });
                }
                aurora_evm::ExitReason::Fatal(f) => {
                    return Err(PrecompileFailure::Fatal { exit_status: f });
                }
            }
```

**File:** engine/src/xcc.rs (L289-311)
```rust
    let withdraw_id = if required_near == ZERO_YOCTO {
        setup_id
    } else {
        let withdraw_call_args = WithdrawWnearToRouterArgs {
            target: sender,
            amount: required_near,
        };
        let withdraw_call = PromiseCreateArgs {
            target_account_id: current_account_id.clone(),
            method: "withdraw_wnear_to_router".into(),
            args: borsh::to_vec(&withdraw_call_args).unwrap(),
            attached_balance: ZERO_YOCTO,
            attached_gas: WITHDRAW_GAS,
        };
        // Safety: This promise is safe. Even though this is a call from the engine account to
        // itself invoking the `call` method (which could be dangerous), the argument to `call`
        // is controlled entirely by us (not any user). This call will only execute the wnear
        // exit precompile, and only for the necessary amount. Note that this amount will always
        // be present, otherwise the user's call to the xcc precompile would have failed.
        let id = match setup_id {
            None => handler.promise_create_call(&withdraw_call),
            Some(setup_id) => handler.promise_attach_callback(setup_id, &withdraw_call),
        };
```

**File:** engine/src/xcc.rs (L382-393)
```rust
pub fn withdraw_wnear_to_router<I: IO + Copy, E: Env, M: ModExpAlgorithm, H: PromiseHandler>(
    recipient: &AccountId,
    amount: Yocto,
    wnear_address: Address,
    engine: &mut Engine<I, E, M>,
    handler: &mut H,
) -> EngineResult<(SubmitResult, Vec<PromiseId>)> {
    let mut interceptor = PromiseInterceptor::new(handler);
    let withdraw_call_args = withdraw_wnear_call_args(recipient, amount, wnear_address);
    let result = engine.call_with_args(withdraw_call_args, &mut interceptor)?;
    Ok((result, interceptor.promises))
}
```

**File:** engine/src/contract_methods/admin.rs (L251-259)
```rust
pub fn pause_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_running(&state)?;
        state.is_paused = true;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
```

**File:** engine/src/contract_methods/xcc.rs (L29-35)
```rust
    with_logs_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
```

**File:** engine/src/contract_methods/mod.rs (L65-70)
```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
```

**File:** engine/src/lib.rs (L366-373)
```rust
    pub extern "C" fn withdraw_wnear_to_router() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::xcc::withdraw_wnear_to_router(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
