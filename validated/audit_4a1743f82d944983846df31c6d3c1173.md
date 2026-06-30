### Title
ERC-20 and ETH Tokens Permanently Locked in Aurora Engine When `ExitToNear` Promise Fails Without `error_refund` Feature - (File: `engine-precompiles/src/native.rs`)

### Summary

When the Aurora Engine is compiled without the `error_refund` feature flag, ERC-20 tokens (or ETH) burned in the EVM via the `ExitToNear` precompile are permanently lost if the subsequent NEAR-side `ft_transfer` promise fails. The corresponding NEP-141 tokens remain locked in the Aurora Engine's account with no recovery path for the user.

### Finding Description

The `ExitToNear` precompile in `engine-precompiles/src/native.rs` handles the exit of ERC-20 tokens or ETH from the Aurora EVM to NEAR. The flow is:

1. ERC-20 tokens are burned from the user's EVM balance (or ETH is deducted via `context.apparent_value`).
2. A `ft_transfer` (or `near_withdraw`) promise is created to transfer NEP-141 tokens to the recipient.
3. A callback (`exit_to_near_precompile_callback`) is attached **only if** `callback_args != ExitToNearPrecompileCallbackArgs::default()`.

The critical branching is in the precompile's `run` method:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None when feature is absent
    transfer_near: transfer_near_args,
};

let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no failure callback
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [1](#0-0) 

For a standard ERC-20 exit (not wNEAR unwrap), `transfer_near_args` is `None`. When `error_refund` is absent, both fields of `callback_args` are `None`, making it equal to `default()`. Therefore **no callback is attached** to the promise. If `ft_transfer` fails (e.g., the recipient is not registered with the NEP-141 contract), the ERC-20 tokens are already burned from the EVM state, the NEP-141 tokens remain in the Aurora Engine's NEP-141 account, and there is no code path to refund the user.

The `exit_to_near_precompile_callback` function confirms this: the refund branch is only entered when `args.refund` is `Some(...)`, which is never the case without `error_refund`:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None   // ← no refund, tokens are gone
}
``` [2](#0-1) 

The same applies to the ETH (base token) exit path via `exit_base_token_to_near`.

### Impact Explanation

**Critical — Permanent freezing of user funds.**

Any user who calls the `ExitToNear` precompile (directly or via an ERC-20 burn function) and whose `ft_transfer` promise fails will permanently lose their tokens. The NEP-141 tokens accumulate in the Aurora Engine's account with no mechanism for the user to recover them. This is directly analogous to the reported pattern: value is locked in a contract (the Aurora Engine's NEP-141 balance) with no claim mechanism for the affected users.

### Likelihood Explanation

**Medium.** The `ft_transfer` promise can fail for common, user-triggered reasons:
- The recipient NEAR account is not registered with the NEP-141 contract (requires a prior `storage_deposit`).
- The recipient account does not exist.
- The NEP-141 contract is paused.

The `error_refund` feature is a compile-time opt-in, not a default. Any Aurora Engine deployment compiled without it is permanently vulnerable to this loss for all users who exit tokens to an invalid or unregistered recipient.

The test suite explicitly acknowledges this behavior:

```rust
#[cfg(feature = "error_refund")]
let balance = FT_TRANSFER_AMOUNT.into();
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [3](#0-2) 

### Recommendation

1. Make the refund mechanism unconditional — remove the `#[cfg(feature = "error_refund")]` / `#[cfg(not(feature = "error_refund"))]` gating so that `refund_call_args` is always populated and a failure callback is always attached.
2. If the feature flag must remain, enforce it as a mandatory feature in the production `Cargo.toml` (e.g., via `required-features`) so that a build without it is rejected at compile time.
3. Add a runtime invariant check or documentation warning that makes the consequence of omitting `error_refund` explicit to deployers.

### Proof of Concept

1. Compile Aurora Engine **without** the `error_refund` feature.
2. Bridge a NEP-141 token to an ERC-20 on Aurora.
3. From an EVM account holding ERC-20 tokens, call the `ExitToNear` precompile targeting a NEAR account that has **not** called `storage_deposit` on the NEP-141 contract.
4. Observe: the ERC-20 tokens are burned from the EVM (user's EVM balance decreases), the `ft_transfer` promise fails on NEAR (recipient not registered), no callback fires, no refund is issued.
5. The user's ERC-20 tokens are gone; the NEP-141 tokens remain in the Aurora Engine's account indefinitely.

Root cause: [4](#0-3) 
Callback absence: [5](#0-4) 
No-refund branch: [2](#0-1)

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
