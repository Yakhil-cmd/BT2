### Title
Permanent Loss of User Funds When `ExitToNear` Transfer Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

---

### Summary

When the `error_refund` Cargo feature is not compiled into the Aurora Engine, the `ExitToNear` precompile burns a user's ERC-20 tokens (or deducts ETH) from their EVM balance and schedules a NEP-141 `ft_transfer` to the NEAR recipient. If that transfer fails — a realistic scenario since NEAR accounts must explicitly register with NEP-141 contracts via `storage_deposit` — no refund callback is scheduled and the tokens are permanently destroyed with no recovery path.

---

### Finding Description

The `ExitToNear` precompile in `engine-precompiles/src/native.rs` constructs a `ExitToNearPrecompileCallbackArgs` struct whose `refund` field is conditionally compiled:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

When `error_refund` is absent, `refund` is `None`. For a standard ERC-20 exit (no wNEAR unwrap), `transfer_near` is also `None`, making `callback_args` equal to `ExitToNearPrecompileCallbackArgs::default()`. The next branch then skips attaching any callback promise entirely:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // <-- no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [2](#0-1) 

The result is a bare `ft_transfer` promise with no failure handler. If the NEP-141 transfer fails, the engine's `exit_to_near_precompile_callback` is never invoked, so the `refund_on_error` path in `engine/src/contract_methods/connector.rs` is never reached:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None   // <-- reached when error_refund is disabled and transfer fails
}
``` [3](#0-2) 

The `refund_on_error` function in `engine/src/engine.rs` is the only mechanism that re-mints burned ERC-20 tokens or returns ETH from the precompile address back to the user: [4](#0-3) 

The test suite explicitly acknowledges this behavior:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

When `error_refund` is not compiled in:
1. The user's ERC-20 tokens are burned in the EVM (or ETH is transferred to the precompile address).
2. The NEP-141 `ft_transfer` to the NEAR recipient fails.
3. No callback is scheduled; no re-mint or ETH refund occurs.
4. The tokens are permanently destroyed. There is no admin function, no recovery path, and no withdrawal mechanism for the lost value.

This is a direct analog to the `ReachFactory` report: funds enter the system (via the exit precompile) but cannot exit when the downstream transfer fails, because the withdrawal/refund mechanism is conditionally compiled out.

---

### Likelihood Explanation

**High.** NEAR's NEP-141 standard requires accounts to call `storage_deposit` before they can receive tokens. Any user who calls `exitToNear` targeting a NEAR account that has not registered with the specific NEP-141 contract will trigger a failed `ft_transfer`. This is a common mistake (e.g., sending to a freshly created NEAR account, a DAO account, or any account that has not explicitly opted in). The failure condition is entirely user-reachable with no special privileges required — only a standard EVM transaction calling the `ExitToNear` precompile. [6](#0-5) 

---

### Recommendation

1. **Enable `error_refund` by default** in the production build, or make it a non-optional part of the exit precompile logic. The feature flag should not be the sole guard against permanent fund loss.
2. **Always attach a failure callback** to the `ft_transfer` promise in `ExitToNear`, regardless of feature flags, so that a failed transfer always triggers a refund path.
3. **Document clearly** which build configurations are safe for production use, and add a compile-time or runtime assertion that prevents deployment without the refund mechanism.

---

### Proof of Concept

1. Deploy Aurora Engine **without** the `error_refund` feature flag.
2. Bridge a NEP-141 token to Aurora, receiving ERC-20 tokens at address `victim`.
3. From `victim`, call the ERC-20 `withdraw` function targeting a NEAR account `unregistered.near` that has never called `storage_deposit` on the NEP-141 contract.
4. The `ExitToNear` precompile fires: ERC-20 tokens are burned; `ft_transfer("unregistered.near", amount)` is scheduled with no callback.
5. The `ft_transfer` fails on the NEAR side (unregistered account).
6. No `exit_to_near_precompile_callback` is invoked; `refund_on_error` is never called.
7. Observe: `victim`'s ERC-20 balance is zero; `unregistered.near`'s NEP-141 balance is zero; tokens are permanently lost.

This matches the behavior explicitly confirmed by the test at: [7](#0-6)

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

**File:** engine-precompiles/src/native.rs (L470-483)
```rust
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

**File:** engine-precompiles/src/native.rs (L572-580)
```rust
    // In case of withdrawing ERC-20 tokens, the `apparent_value` should be zero. In opposite way
    // the funds will be locked in the address of the precompile without any possibility
    // to withdraw them in the future. So, in case if the `apparent_value` is not zero, the error
    // will be returned to prevent that.
    if context.apparent_value != U256::zero() {
        return Err(ExitError::Other(Cow::from(
            "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
        )));
    }
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
