### Title
Permanent Token Loss in `exitToNear` When `ft_transfer` Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

---

### Summary

When a user calls the `exitToNear` precompile to bridge ERC-20 tokens or ETH to NEAR, their tokens are burned/deducted first. If the subsequent `ft_transfer` NEAR promise fails and the `error_refund` compile-time feature is not enabled, the `refund` field in `ExitToNearPrecompileCallbackArgs` is hardcoded to `None`. The callback's refund branch is silently skipped, and the user's tokens are permanently lost with no recovery path.

---

### Finding Description

**Step 1 — Callback args construction (`engine-precompiles/src/native.rs`):**

When the `exitToNear` precompile runs, it constructs callback arguments:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None when feature is absent
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

When `error_refund` is not compiled in, `refund` is unconditionally `None`.

**Step 2 — No callback attached for regular ERC-20 exits:**

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback at all
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [2](#0-1) 

For a regular ERC-20 exit (non-wNEAR), `transfer_near` is also `None`, so `callback_args == default()`. No callback is attached. If `ft_transfer` fails, there is no handler at all — the burned tokens are gone.

**Step 3 — Refund branch silently skipped in callback (`engine/src/contract_methods/connector.rs`):**

For wNEAR exits where `transfer_near` is `Some`, a callback IS attached, but:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None   // ← silently taken when refund is None
};
``` [3](#0-2) 

Because `args.refund` is `None` (feature disabled), the `else { None }` branch is taken and no refund is issued.

**Step 4 — `error_refund` is not a default feature:**

Neither `engine/Cargo.toml` nor `engine-precompiles/Cargo.toml` lists `error_refund` in `default`:

```toml
[features]
default = ["std"]
...
error_refund = ["aurora-engine-precompiles/error_refund"]
``` [4](#0-3) [5](#0-4) 

If the production WASM is compiled without this feature, the refund path is dead code.

---

### Impact Explanation

A user who calls `exitToNear` has their ERC-20 tokens burned (or ETH deducted) inside the EVM before the NEAR-side `ft_transfer` is attempted. If `ft_transfer` fails for any reason (e.g., recipient account not registered with the NEP-141 contract), and `error_refund` is not compiled in, the user's tokens are permanently destroyed with no recovery. This is a **permanent loss of user funds**.

The test suite explicitly documents this behavior:

```rust
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
// If the refund feature is not enabled, then there is no refund in the EVM
``` [6](#0-5) 

---

### Likelihood Explanation

The `error_refund` feature is opt-in and not default. Any production deployment compiled without it exposes all users to permanent fund loss on any failed `exitToNear` call. The failure condition (recipient not registered, NEP-141 contract paused, insufficient gas on NEAR side) is realistic and user-triggerable without any special privileges.

---

### Recommendation

Make `error_refund` a default feature, or unconditionally populate the `refund` field in `ExitToNearPrecompileCallbackArgs` without gating it behind a compile-time flag. The refund logic in `refund_on_error` already exists and is correct — it simply needs to always be reachable.

---

### Proof of Concept

1. User calls `exitToNear` with ERC-20 tokens (non-wNEAR).
2. ERC-20 tokens are burned inside the EVM.
3. `callback_args.refund = None` (feature disabled), `callback_args.transfer_near = None` (not wNEAR).
4. `callback_args == ExitToNearPrecompileCallbackArgs::default()` → `true`.
5. Promise is created as `PromiseArgs::Create(transfer_promise)` — **no callback attached**.
6. `ft_transfer` on the NEP-141 contract fails (e.g., recipient not registered).
7. No callback fires. No refund occurs. User's ERC-20 tokens are permanently lost.

For the wNEAR case: steps 3–5 differ (callback IS attached because `transfer_near` is `Some`), but in the callback, `args.refund` is `None`, so the `else { None }` branch is taken and no refund is issued — same permanent loss outcome.

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

**File:** engine/Cargo.toml (L43-48)
```text
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
```

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
```

**File:** engine-tests/src/tests/erc20_connector.rs (L773-775)
```rust
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```
