### Title
Permanent ERC-20 Token Loss When `ft_transfer` Fails Without Refund Args in `exit_to_near_precompile_callback` — (`engine/src/contract_methods/connector.rs`)

---

### Summary

The `exit_to_near_precompile_callback` function contains a silent `else { None }` branch that is reached when the `ft_transfer` promise fails **and** `args.refund` is `None`. In this case, ERC-20 tokens already burned from the user's EVM balance are permanently unrecoverable. This is the direct analog of the Salty.IO M-21 finding: a multi-step operation where the second step can fail, leaving tokens in a state the contract cannot handle.

---

### Finding Description

In `engine/src/contract_methods/connector.rs`, the `exit_to_near_precompile_callback` function handles the result of the `ft_transfer` NEAR promise that is scheduled when a user exits ERC-20 tokens to NEAR:

```rust
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    if let Some(args) = args.transfer_near {
        // ... schedule NEAR transfer with NO failure callback
        let promise_id = handler.promise_create_batch(&promise);
        handler.promise_return(promise_id);
    }
    None
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
    Some(refund_result)
} else {
    None   // ← Promise failed, refund is None → tokens permanently lost
};
``` [1](#0-0) 

The `else { None }` branch at the end is reached when:
1. The `ft_transfer` promise did **not** succeed (failed or unavailable), AND
2. `args.refund` is `None`.

The `ExitToNearPrecompileCallbackArgs` struct has both fields as `Option`, defaulting to `None`: [2](#0-1) 

The `error_refund` compile-time feature controls whether `args.refund` is populated. When this feature is **not** enabled, `args.refund` is always `None`, so any `ft_transfer` failure unconditionally hits the `else { None }` branch. The engine test suite explicitly acknowledges this behavior: [3](#0-2) 

**Second sub-issue (runtime, feature-independent):** Even when `error_refund` is enabled, the success branch that handles wNEAR exits creates a NEAR `Transfer` promise with **no failure callback**: [4](#0-3) 

If this NEAR transfer fails (e.g., the target NEAR account does not exist), the NEAR is returned to the engine's NEAR balance by the NEAR runtime, but the user's wNEAR ERC-20 tokens are already burned in the EVM with no recovery path. The engine has no mechanism to detect this failure and re-mint the tokens.

The `refund_on_error` function that would re-mint tokens is only invoked in the `else if let Some(args) = args.refund` branch, which is never reached in the success path: [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

- In the `error_refund`-disabled case: any user who calls `exit_to_near` and whose `ft_transfer` fails (e.g., recipient not registered with the NEP-141 contract) permanently loses their ERC-20 tokens. The tokens are burned from the EVM state; the NEAR-side transfer never completes; no refund is issued.
- In the NEAR transfer failure sub-case: a user who specifies a non-existent NEAR account as the exit recipient has their wNEAR ERC-20 tokens permanently burned, while the NEAR accumulates silently in the engine's NEAR balance with no EVM-side credit.

In both cases the loss is irreversible: there is no admin function, no recovery callback, and no on-chain mechanism to re-mint or return the burned tokens.

---

### Likelihood Explanation

- **`error_refund` disabled path**: Likelihood depends on whether the production binary is compiled with the feature. Because it is a non-default optional feature (evidenced by the `#[cfg(feature = "error_refund")]` guards throughout the codebase), any deployment compiled without it is fully exposed. The triggering condition — a failed `ft_transfer` — is realistic: it occurs whenever the recipient is not registered with the NEP-141 contract.
- **NEAR transfer failure sub-case**: Likelihood is lower but non-zero. A user who mistypes a NEAR account ID, or whose target account was deleted between transaction submission and execution, triggers the loss. No validation of account existence is performed before burning the ERC-20 tokens.

---

### Recommendation

1. **Always populate `args.refund`** in the precompile when ERC-20 tokens are burned, regardless of the `error_refund` feature flag. The refund path should be unconditional.
2. **Attach a failure callback** to the NEAR `Transfer` promise in the `transfer_near` branch. On failure, the callback should re-mint the burned ERC-20 tokens to the original sender via `refund_on_error`.
3. **Remove the silent `else { None }` branch** or replace it with an explicit error that causes the NEAR transaction to panic and revert any state changes made in the callback scope, preventing silent token loss.

---

### Proof of Concept

1. User holds wNEAR ERC-20 tokens on Aurora and calls the `exit_to_near` precompile targeting a NEAR account that is not registered with the wNEAR NEP-141 contract (or does not exist).
2. The precompile burns the user's wNEAR ERC-20 balance in the EVM.
3. The engine schedules `ft_transfer` on the wNEAR NEP-141 contract.
4. `ft_transfer` fails (unregistered recipient).
5. `exit_to_near_precompile_callback` is invoked. `handler.promise_result(0)` is not `Successful`.
6. Without `error_refund`: `args.refund` is `None` → `else { None }` branch → function returns `Ok(None)` → no re-mint, no refund.
7. With `error_refund` but targeting a non-existent NEAR account in the wNEAR unwrap path: `ft_transfer` to the intermediate account succeeds, the callback creates a bare `Transfer` promise to the non-existent account with no failure callback → NEAR returned to engine balance → ERC-20 tokens permanently burned.

The test at `engine-tests/src/tests/erc20_connector.rs:624-665` (`test_exit_to_near_refund`) directly demonstrates the token loss when `error_refund` is not compiled in, confirming the reachable code path. [6](#0-5)

### Citations

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

**File:** engine-types/src/parameters/connector.rs (L129-134)
```rust
/// Arguments for callback used in the `exit_to_near` precompile.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Default)]
pub struct ExitToNearPrecompileCallbackArgs {
    pub refund: Option<RefundCallArgs>,
    pub transfer_near: Option<TransferNearArgs>,
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
