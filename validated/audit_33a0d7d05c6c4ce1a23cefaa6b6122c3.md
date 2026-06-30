### Title
ETH Permanently Frozen at `exit_to_near::ADDRESS` When Exit Promise Fails Without `error_refund` Feature — (File: `engine-precompiles/src/native.rs`)

---

### Summary

When a user calls the `ExitToNear` precompile to bridge ETH from Aurora to NEAR, the ETH is moved to `exit_to_near::ADDRESS` in the EVM *before* the NEP-141 `ft_transfer` promise is confirmed. The refund mechanism that re-credits the ETH on failure is gated behind the `error_refund` compile-time feature flag. When that flag is absent, a failed `ft_transfer` leaves the ETH permanently frozen at the precompile address with no recovery path, creating a permanent divergence between the EVM balance accounting and the NEP-141 total supply.

---

### Finding Description

**Step 1 — ETH is moved to the precompile address during exit.**

In `ExitToNear::run()`, when a user sends ETH value to the precompile, the EVM deducts it from the caller's balance and credits `exit_to_near::ADDRESS`. A promise is then scheduled to call `ft_transfer` on the EthConnector.

**Step 2 — The refund args are conditionally compiled.** [1](#0-0) 

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
```

When `error_refund` is absent, `callback_args.refund` is always `None`.

**Step 3 — When the promise fails, the callback silently does nothing.** [2](#0-1) 

```rust
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    // success — optionally unwrap wNEAR
    None
} else if let Some(args) = args.refund {
    // refund path — only reachable when error_refund is compiled in
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None   // ← silent no-op; ETH stays at exit_to_near::ADDRESS forever
}
```

**Step 4 — The refund path itself transfers ETH back from the precompile address.** [3](#0-2) 

```rust
} else {
    // ETH exit; transfer ETH back from precompile address
    let exit_address = exit_to_near::ADDRESS;
    engine.call(&exit_address, &refund_address, amount, ...)
}
```

Without `error_refund`, this call is never made. There is no admin escape hatch or other mechanism to drain `exit_to_near::ADDRESS`.

**Step 5 — The accounting diverges.**

The NEP-141 total supply (tracked by the EthConnector) is unchanged because the `ft_transfer` failed and the tokens were never sent. The EVM ETH supply is reduced because the ETH is now at `exit_to_near::ADDRESS` rather than in any user's balance. The two layers are permanently out of sync — exactly the "funds outside the vault" scenario from the reference report.

The test suite explicitly documents both outcomes: [4](#0-3) 

```rust
#[cfg(feature = "error_refund")]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
// If the refund feature is not enabled, then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```

---

### Impact Explanation

- ETH is permanently frozen at `exit_to_near::ADDRESS` with no recovery path.
- The NEP-141 total supply exceeds the sum of all EVM balances by the frozen amount.
- The user's ETH is irrecoverably lost.
- **Impact: Permanent freezing of funds (Critical).**

---

### Likelihood Explanation

- The `ft_transfer` promise fails whenever the recipient NEAR account is not registered with the NEP-141 contract — a common, user-triggerable condition.
- Any EVM user can call the `ExitToNear` precompile; no privilege is required.
- The `error_refund` feature is an optional compile-time flag; the test suite is written to pass with or without it, confirming it is not unconditionally enabled.
- **Likelihood: Low** (requires a failed promise), but the trigger is fully user-controlled and requires no special access.

---

### Recommendation

1. Make the refund mechanism unconditional — remove the `#[cfg(feature = "error_refund")]` guard and always populate `callback_args.refund` for ETH exits.
2. If the feature flag must be retained for other reasons, enforce at the build level that `error_refund` is always enabled for any production WASM artifact.
3. Add an invariant check (or monitoring) that asserts `exit_to_near::ADDRESS` balance remains zero after each block, alerting operators to any divergence.

---

### Proof of Concept

1. User holds ETH on Aurora.
2. User calls the `ExitToNear` precompile (`engine-precompiles/src/native.rs`, `ExitToNear::run`) with ETH value and a NEAR recipient that is **not registered** with the EthConnector NEP-141 contract.
3. The EVM deducts ETH from the user's balance and credits `exit_to_near::ADDRESS`.
4. A `ft_transfer` promise is scheduled on the EthConnector.
5. The promise fails (unregistered recipient).
6. `exit_to_near_precompile_callback` is invoked; `args.refund` is `None` (no `error_refund` feature); the `else { None }` branch executes silently.
7. ETH remains at `exit_to_near::ADDRESS` permanently. NEP-141 total supply is unchanged. EVM ETH supply is reduced. The user's funds are frozen with no recovery path.

### Citations

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

**File:** engine-tests/src/tests/erc20_connector.rs (L771-780)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);

        assert_eq!(
            eth_balance_of(signer_address, &aurora).await,
            expected_balance
        );
```
