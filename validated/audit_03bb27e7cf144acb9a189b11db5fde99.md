### Title
Permanent ERC-20 Token Loss in `ExitToNear` Precompile When `ft_transfer` Promise Fails Without `error_refund` Feature - (File: engine-precompiles/src/native.rs, engine/src/contract_methods/connector.rs)

### Summary

When the `error_refund` compile-time feature is absent, the `ExitToNear` precompile burns a user's ERC-20 tokens in the EVM and schedules a `ft_transfer` promise on the NEAR side, but provides no refund path if that promise fails. The tokens are permanently destroyed with no recovery mechanism.

### Finding Description

The `ExitToNear` precompile's `run` method constructs `ExitToNearPrecompileCallbackArgs` with `refund` conditionally set only when the `error_refund` feature is compiled in:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

When `error_refund` is absent, `refund` is always `None`. The callback `exit_to_near_precompile_callback` then handles the promise result as follows:

```rust
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    // success path
} else if let Some(args) = args.refund {
    // refund path — unreachable when error_refund is disabled
} else {
    None  // silent no-op: tokens already burned, no refund issued
};
``` [2](#0-1) 

The ERC-20 burn happens inside the EVM before the promise is ever dispatched. If the NEAR-side `ft_transfer` or `near_withdraw` promise fails (e.g., recipient account not registered with the NEP-141 contract), the callback falls into the `else { None }` branch. No re-mint of the burned ERC-20 tokens occurs, and no NEAR-side transfer completes. The tokens are gone.

The test suite explicitly documents this behavior:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [3](#0-2) 

The `refund_on_error` function that would re-mint the burned tokens is only reachable through the `args.refund` branch: [4](#0-3) 

### Impact Explanation

**Critical — Permanent freezing/destruction of user funds.**

Any EVM user who calls `withdrawToNear` (via `EvmErc20.withdrawToNear`) to a NEAR account that is not registered with the NEP-141 contract will have their ERC-20 tokens permanently burned with no recovery. The ERC-20 balance is reduced in the EVM state before the NEAR promise executes. If the promise fails, the `ExitToNearPrecompileCallbackArgs.refund` field is `None` (when `error_refund` is absent), so `exit_to_near_precompile_callback` silently returns `Ok(None)` without re-minting. The tokens are irrecoverably lost. [5](#0-4) 

### Likelihood Explanation

**Medium.** The `ft_transfer` promise fails whenever the recipient NEAR account has not called `storage_deposit` on the NEP-141 contract. This is a common user error — EVM users are not accustomed to NEAR storage registration requirements. Additionally, NEP-141 contracts can be paused or have other restrictions that cause `ft_transfer` to fail. The entry path requires only a standard EVM transaction with no special privileges.

### Recommendation

Ensure the `error_refund` feature is always compiled into production builds, or unconditionally populate `refund` in `ExitToNearPrecompileCallbackArgs` regardless of the feature flag. The refund path in `exit_to_near_precompile_callback` should always be available when a promise fails and tokens have been burned. The feature flag should gate only the input parsing of the refund address, not the existence of the refund mechanism itself.

### Proof of Concept

1. Deploy an ERC-20 token bridged from a NEP-141 contract on Aurora (without `error_refund` compiled in).
2. Call `EvmErc20.withdrawToNear(recipient_bytes, amount)` where `recipient_bytes` encodes a NEAR account that has **not** called `storage_deposit` on the NEP-141 contract.
3. The EVM burns `amount` of ERC-20 tokens from the caller's balance.
4. The `ExitToNear` precompile schedules a `ft_transfer` promise to the NEP-141 contract.
5. The `ft_transfer` promise fails (recipient not registered).
6. `exit_to_near_precompile_callback` is invoked with `args.refund == None`.
7. The callback returns `Ok(None)` — no re-mint, no transfer.
8. The caller's ERC-20 balance is permanently reduced; no NEP-141 tokens are received.

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` at line 623 demonstrates this exact scenario and confirms the token loss when `error_refund` is absent. [6](#0-5)

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

**File:** engine/src/engine.rs (L1176-1204)
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
```

**File:** engine-types/src/parameters/connector.rs (L130-134)
```rust
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Default)]
pub struct ExitToNearPrecompileCallbackArgs {
    pub refund: Option<RefundCallArgs>,
    pub transfer_near: Option<TransferNearArgs>,
}
```
