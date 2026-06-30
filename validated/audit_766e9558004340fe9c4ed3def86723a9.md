### Title
Permanent ERC-20 Token Loss When `exit_to_near` NEP-141 Transfer Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile burns a user's ERC-20 tokens on the EVM side before the corresponding NEAR-side `ft_transfer` promise is confirmed. When the binary is compiled without the `error_refund` feature flag, no refund callback is attached to the outgoing promise. If the NEAR-side transfer fails for any reason, the burned tokens are permanently destroyed with no recovery path. This is a direct structural analog to H-31: state is committed on one side of the asynchronous boundary before the other side's result is known, and the absence of a fallback/refund mechanism causes permanent fund loss.

---

### Finding Description

**Step 1 — ERC-20 tokens are burned before the NEAR promise resolves.**

Inside `ExitToNear::run`, the precompile emits a log that causes the engine to burn the caller's ERC-20 balance and schedule a NEAR `ft_transfer` (or `near_withdraw`) promise. The burn is irrevocable at EVM execution time.

**Step 2 — The refund field is conditionally `None`.**

The callback arguments are constructed with a compile-time conditional:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

When `error_refund` is not compiled in, `refund` is always `None`.

**Step 3 — No callback is attached for a plain ERC-20 exit.**

For a regular ERC-20 exit (not wNEAR unwrap), `transfer_near` is also `None`, making `callback_args` equal to `default()`. The engine then schedules a bare `Create` promise with no callback at all:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [2](#0-1) 

**Step 4 — Even when a callback exists (wNEAR path), failure is silently ignored.**

For the wNEAR unwrap path, `transfer_near` is `Some`, so a callback is attached. However, inside `exit_to_near_precompile_callback`, the failure branch only refunds when `args.refund` is `Some`:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(...)?;
    ...
} else {
    None   // ← promise failed, refund is None → tokens silently lost
};
``` [3](#0-2) 

Without `error_refund`, `args.refund` is always `None`, so this `else` branch is always taken on failure — doing nothing.

**Root cause summary:** The EVM-side state (token burn) is committed atomically during `submit`, but the NEAR-side promise result is asynchronous. Without `error_refund`, there is no mechanism to detect a failed NEAR transfer and restore the burned tokens. This is structurally identical to H-31's `executionHistory` being set to `true` before the branch-side fallback is confirmed.

---

### Impact Explanation

**Critical — Permanent destruction of user funds.**

Any user who calls `exit_to_near` under conditions where the NEAR-side `ft_transfer` fails will have their ERC-20 tokens permanently burned with no recovery. The EVM state is final; there is no `retrieveDeposit`-equivalent function in Aurora Engine.

---

### Likelihood Explanation

**Medium.** The NEAR-side transfer can fail for multiple realistic reasons reachable by an ordinary user:

- The recipient NEAR account is not registered with the NEP-141 token contract (a common requirement).
- The NEP-141 contract is paused or has access controls.
- Insufficient gas is forwarded to the `ft_transfer` call.
- The NEP-141 contract itself reverts for any internal reason.

The attacker-controlled entry path is simply calling the `exit_to_near` precompile (address `0x...exitToNear`) from any EVM contract or EOA with a recipient that will cause the NEAR transfer to fail. No special privileges are required.

---

### Recommendation

1. **Always enable `error_refund` in production builds**, or remove the feature flag and make the refund logic unconditional.
2. Ensure the callback is always attached (even for plain ERC-20 exits) so that a failed NEAR promise is always detected.
3. In the callback, always attempt to refund the burned tokens when the base promise fails, regardless of whether `refund` args were populated.

---

### Proof of Concept

The existing test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` explicitly documents the fund-loss behavior:

```rust
#[cfg(feature = "error_refund")]
let balance = FT_TRANSFER_AMOUNT.into();
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [4](#0-3) 

When `error_refund` is absent, the user's ERC-20 balance after a failed exit is `FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT` — the exit amount is gone. The NEP-141 balance on the NEAR side is unchanged (the transfer never completed), confirming the tokens are destroyed on the EVM side with no corresponding credit anywhere.

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
