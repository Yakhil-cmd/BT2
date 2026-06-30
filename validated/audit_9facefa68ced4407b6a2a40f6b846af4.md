### Title
`exit_to_near_precompile_callback` Refund Path Blocked by Contract Pause Causes Permanent ERC-20 Token Loss — (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

When the Aurora Engine contract is paused via `pause_contract`, the `exit_to_near_precompile_callback` function fails at its `require_running` guard before it can execute the refund path. If a user's `EXIT_TO_NEAR` precompile call was already in-flight when the contract was paused, and the underlying NEP-141 `ft_transfer`/`ft_transfer_call` promise fails, the ERC-20 tokens that were already burned in the EVM are never re-minted. The user permanently loses their tokens. This is structurally identical to the reported issue: a user-protective operation (refund on failed exit) is blocked by a pause while the user-harmful operation (token burn) already completed.

---

### Finding Description

The `EXIT_TO_NEAR` precompile flow works as follows:

1. A user submits an EVM transaction that calls the `EXIT_TO_NEAR` precompile.
2. The precompile burns the user's ERC-20 tokens inside the EVM and schedules a NEAR promise (`ft_transfer` or `ft_transfer_call`) to the NEP-141 contract.
3. A NEAR callback `exit_to_near_precompile_callback` is scheduled to handle the result.

The callback is the only place where a failed exit can be recovered. If the `ft_transfer` fails, the callback's refund branch calls `engine::refund_on_error` to re-mint the burned tokens:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
```

However, the callback unconditionally checks `require_running` **before** reaching the refund branch:

```rust
pub fn exit_to_near_precompile_callback<...>(...) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;   // ← blocks the entire callback when paused
        env.assert_private_call()?;
        ...
    })
}
``` [1](#0-0) 

If the contract is paused between step 2 and step 3, the callback panics at `require_running`. NEAR receipts are independent: the token burn from step 2 is already committed to state, but the refund from step 3 is reverted. The user's ERC-20 tokens are permanently destroyed.

The developers already recognized this exact pattern for `ft_resolve_transfer` and explicitly removed the `require_running` guard from it:

> "The `ft_resolve_transfer` callback doesn't require running the contract to finish the `ft_transfer_call` correctly" — CHANGES.md, v3.6.2 [2](#0-1) 

The same fix was never applied to `exit_to_near_precompile_callback`.

The `require_running` guard is defined as:

```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
``` [3](#0-2) 

And `pause_contract` sets `is_paused = true`: [4](#0-3) 

The refund path inside the callback calls `engine::refund_on_error`, which re-mints burned ERC-20 tokens or returns ETH: [5](#0-4) 

The refund is only triggered when the `error_refund` feature is enabled (which is the production configuration for the full engine build): [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

A user's ERC-20 tokens are burned in the EVM at the time the `EXIT_TO_NEAR` precompile executes. If the subsequent NEP-141 transfer fails and the contract is paused before the callback runs, the refund is permanently blocked. The user receives neither the NEP-141 tokens nor a refund of their ERC-20 tokens. There is no recovery path once the callback fails.

---

### Likelihood Explanation

**Low-medium.** Three conditions must coincide:

1. The `error_refund` feature is enabled (true in production).
2. A user has an in-flight `EXIT_TO_NEAR` operation whose NEP-141 `ft_transfer` fails (e.g., the NEP-141 contract is independently paused, the recipient has no storage registered, or the NEP-141 contract rejects the transfer for any reason).
3. The Aurora Engine owner calls `pause_contract` in the window between the original EVM execution and the NEAR callback receipt.

The owner pausing the contract is a legitimate administrative action. The vulnerability is that the pause has an unintended side effect of permanently destroying user funds for any exit that was in-flight at the time of the pause and whose underlying transfer fails.

---

### Recommendation

Remove the `require_running` guard from the refund branch of `exit_to_near_precompile_callback`, consistent with the fix already applied to `ft_resolve_transfer`. The refund is a user-protective operation that must complete regardless of the contract's pause state. The simplest fix is to check `require_running` only for the success path (NEAR token transfer), not for the refund path:

```rust
pub fn exit_to_near_precompile_callback<...>(...) {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        env.assert_private_call()?;
        if handler.promise_results_count() != 1 {
            return Err(errors::ERR_PROMISE_COUNT.into());
        }
        let args: ExitToNearPrecompileCallbackArgs = io.read_input_borsh()?;
        let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
            require_running(&state)?;  // only guard the success/transfer path
            ...
        } else if let Some(args) = args.refund {
            // refund path: no require_running check
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
            ...
        };
        Ok(maybe_result)
    })
}
```

---

### Proof of Concept

1. User holds ERC-20 tokens (e.g., a bridged NEP-141) on Aurora and calls an EVM contract that invokes the `EXIT_TO_NEAR` precompile to exit them.
2. The precompile burns the ERC-20 tokens in the EVM and schedules `ft_transfer` to the NEP-141 contract + the `exit_to_near_precompile_callback` callback.
3. The Aurora Engine owner calls `pause_contract` (e.g., for an emergency upgrade). `state.is_paused` is set to `true`.
4. The NEP-141 `ft_transfer` fails (e.g., the NEP-141 contract is independently paused via its own admin, or the recipient has no storage deposit).
5. The NEAR runtime executes `exit_to_near_precompile_callback` as the callback receipt.
6. `require_running(&state)?` returns `Err(ERR_PAUSED)` → the callback panics.
7. The refund (`engine::refund_on_error` re-minting ERC-20 tokens) never executes.
8. The user's ERC-20 tokens are permanently burned. They received no NEP-141 tokens and no refund. [7](#0-6) [8](#0-7)

### Citations

**File:** engine/src/contract_methods/connector.rs (L195-246)
```rust
#[named]
pub fn exit_to_near_precompile_callback<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;

        // This function should only be called as the callback of
        // exactly one promise.
        if handler.promise_results_count() != 1 {
            return Err(errors::ERR_PROMISE_COUNT.into());
        }

        let args: ExitToNearPrecompileCallbackArgs = io.read_input_borsh()?;

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
    })
}
```

**File:** CHANGES.md (L209-210)
```markdown
- The `ft_resolve_transfer` callback doesn't require running the contract to finish the `ft_transfer_call` correctly
  by [@aleksuss]. ([#906])
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

**File:** engine/src/engine.rs (L1176-1224)
```rust
pub fn refund_on_error<I: IO + Copy, E: Env, P: PromiseHandler>(
    io: I,
    env: &E,
    state: EngineState,
    args: &RefundCallArgs,
    handler: &mut P,
) -> EngineResult<SubmitResult> {
    let current_account_id = env.current_account_id();
    if let Some(erc20_address) = args.erc20_address {
        // ERC-20 exit; re-mint burned tokens
        let erc20_admin_address = current_address(&current_account_id);
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, erc20_admin_address, current_account_id, io, env);

        let refund_address = args.recipient_address;
        let amount = U256::from_big_endian(&args.amount);
        let input = setup_refund_on_error_input(amount, refund_address);

        engine.call(
            &erc20_admin_address,
            &erc20_address,
            Wei::zero(),
            input,
            u64::MAX,
            Vec::new(),
            Vec::new(),
            handler,
        )
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

**File:** engine-precompiles/src/native.rs (L449-455)
```rust
        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
```

**File:** engine/src/lib.rs (L647-655)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn exit_to_near_precompile_callback() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::exit_to_near_precompile_callback(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```
