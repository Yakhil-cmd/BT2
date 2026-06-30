### Title
`exit_to_near_precompile_callback` Incorrectly Enforces Running Engine State, Permanently Freezing User Funds When Engine Is Paused - (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

`exit_to_near_precompile_callback` enforces `require_running` before executing its refund path. Because ERC-20 tokens are burned in the original EVM transaction (a separate NEAR receipt), a pause of the engine between that receipt and the callback receipt causes the refund to be permanently blocked, freezing the user's funds with no recovery path.

---

### Finding Description

The `ExitToNear` precompile burns a user's ERC-20 tokens and schedules a NEP-141 transfer promise. The engine attaches `exit_to_near_precompile_callback` as the callback to that promise. The callback handles two branches:

1. **Success branch** – the NEP-141 transfer succeeded; optionally transfer unwrapped NEAR.
2. **Failure branch** – the NEP-141 transfer failed; call `engine::refund_on_error` to re-mint the burned ERC-20 tokens.

The callback begins with:

```rust
let state = state::get_state(&io)?;
require_running(&state)?;   // ← blocks the entire callback when engine is paused
``` [1](#0-0) 

`require_running` is defined as:

```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
``` [2](#0-1) 

When the callback returns an error, `sdk_unwrap()` in `lib.rs` causes a panic, reverting only the callback's own state changes. The ERC-20 burn that occurred in the original EVM receipt is **not** reverted, because it belongs to a prior, already-committed NEAR receipt. The refund promise is never created, so the user's tokens are permanently lost.

The refund branch that is blocked:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
``` [3](#0-2) 

---

### Impact Explanation

**Critical – Permanent freezing of funds.**

When the engine is paused between the original `ExitToNear` EVM transaction and the execution of `exit_to_near_precompile_callback`, and the underlying NEP-141 transfer fails (e.g., the recipient is not registered in the NEP-141 contract), the refund path is unreachable. The user's ERC-20 tokens are already burned and cannot be recovered. There is no alternative recovery mechanism exposed to the user.

---

### Likelihood Explanation

**Low.** Two conditions must coincide:

1. The engine owner pauses the engine (a legitimate administrative action, e.g., for an upgrade or security incident) in the narrow window between the original EVM receipt and the callback receipt.
2. The NEP-141 transfer in the base promise fails (e.g., the target account is not registered in the NEP-141 contract, which is a realistic condition for new users).

Neither condition requires attacker privilege; the user only needs to call the `ExitToNear` precompile. The pause is a normal owner operation, not a compromise.

---

### Recommendation

Remove `require_running` from `exit_to_near_precompile_callback`, or restructure the callback so that the **refund branch executes unconditionally regardless of engine pause state**. The callback is a settlement of an already-committed state change (the ERC-20 burn); it must be able to complete its refund logic in all engine states, analogous to how IBC timeout functions must be executable regardless of channel state. [4](#0-3) 

---

### Proof of Concept

1. User calls the `ExitToNear` precompile from an EVM contract. The engine burns the user's ERC-20 tokens and schedules a NEP-141 `ft_transfer` promise with `exit_to_near_precompile_callback` as the callback.
2. The NEP-141 `ft_transfer` fails (e.g., the recipient account is not registered).
3. The engine owner calls `pause_contract` — a routine administrative action. [5](#0-4) 
4. NEAR runtime executes `exit_to_near_precompile_callback`. The function reads engine state, hits `require_running`, and returns `ERR_PAUSED`. `sdk_unwrap()` panics.
5. The callback's state changes are reverted. The refund promise (`engine::refund_on_error`) is never created.
6. The user's ERC-20 tokens remain burned. No NEP-141 tokens were received. No refund is possible. Funds are permanently frozen.

### Citations

**File:** engine/src/contract_methods/connector.rs (L196-246)
```rust
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
