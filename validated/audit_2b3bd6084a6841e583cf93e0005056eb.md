### Title
Permanent ERC-20 Token Freeze When `ft_transfer` Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile burns ERC-20 tokens before dispatching an async `ft_transfer` promise to the NEP-141 contract. When the `error_refund` compile-time feature is **not** enabled, no callback is attached to that promise. If `ft_transfer` fails for any reason — including the recipient being blacklisted or unregistered on the NEP-141 side — the burned ERC-20 tokens are permanently unrecoverable. There is no mechanism to re-mint or return them.

---

### Finding Description

The `ExitToNear::run` precompile in `engine-precompiles/src/native.rs` constructs a `callback_args` struct and decides whether to attach a callback promise:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};

let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [1](#0-0) 

For a standard ERC-20 exit (flag `0x01`, no wNEAR unwrap), `transfer_near_args` is `None`. When `error_refund` is not enabled, `refund` is also `None`. Both fields being `None` makes `callback_args` equal to `ExitToNearPrecompileCallbackArgs::default()`, so the branch takes `PromiseArgs::Create(transfer_promise)` — **a fire-and-forget promise with no callback**. [2](#0-1) 

The ERC-20 tokens are burned by `EvmErc20.sol`'s `withdrawToNear` **before** the precompile is called:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    ...
    // calls ExitToNear precompile
}
``` [3](#0-2) 

If the downstream `ft_transfer` call on the NEP-141 contract fails — because the recipient is not storage-registered, is blacklisted by the NEP-141 contract, or the contract is paused — there is no callback to detect the failure. The `exit_to_near_precompile_callback` is never invoked, so the `else if let Some(args) = args.refund` branch that calls `engine::refund_on_error` is never reached:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None   // ← silent no-op when refund is None
};
``` [4](#0-3) 

The engine's own test suite documents this loss explicitly:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

The `error_refund` feature is a compile-time opt-in defined in `engine-precompiles/Cargo.toml` and `engine/Cargo.toml` — it is **not** a default feature. Any production build that omits it is permanently vulnerable. [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

ERC-20 tokens are burned from the user's Aurora balance at the moment `withdrawToNear` is called. If the subsequent `ft_transfer` on the NEP-141 side fails and `error_refund` is not compiled in, those tokens are destroyed with no on-chain path to recovery. The user loses the full withdrawn amount permanently.

---

### Likelihood Explanation

**Medium.**

The `error_refund` feature is not a default Cargo feature, so any deployment built without it is affected. `ft_transfer` failures are realistic:

- The recipient NEAR account has not paid the NEP-141 storage deposit (common for new accounts).
- The NEP-141 contract implements a blocklist (e.g., a regulated stablecoin) and the recipient address is added to it after the ERC-20 burn but before the promise resolves — exactly the M-08 blacklisting scenario.
- The NEP-141 contract is paused by its owner.

All three scenarios are reachable by an unprivileged user or by external state changes outside the user's control.

---

### Recommendation

1. **Make `error_refund` a default feature** in `engine-precompiles/Cargo.toml` and `engine/Cargo.toml`, or unconditionally attach a failure-handling callback for every ERC-20 exit.
2. Alternatively, restructure the flow so that the ERC-20 burn only becomes final after the `ft_transfer` promise succeeds (i.e., burn inside the callback on success, not before the promise is dispatched).
3. If the fire-and-forget design must be kept for gas reasons, document clearly that `error_refund` **must** be enabled in any production build and add a compile-time assertion or runtime guard to prevent silent deployment without it.

---

### Proof of Concept

**Step-by-step:**

1. Deploy Aurora without the `error_refund` feature (`cargo build --release`, no `--features error_refund`).
2. Bridge a NEP-141 token (e.g., a stablecoin with a blocklist) to Aurora; user receives ERC-20 tokens.
3. User calls `EvmErc20.withdrawToNear(recipient_bytes, amount)`.
   - `_burn(msg.sender, amount)` executes — ERC-20 balance is reduced immediately.
   - The `ExitToNear` precompile fires `PromiseArgs::Create(ft_transfer_promise)` with **no callback**.
4. Before the promise resolves, the NEP-141 contract owner adds `recipient` to the blocklist (or `recipient` was never storage-registered).
5. `ft_transfer` reverts on the NEAR side.
6. No callback fires. `exit_to_near_precompile_callback` is never called.
7. User's ERC-20 balance is zero; NEP-141 balance of `recipient` is unchanged. Tokens are gone.

The existing test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` already demonstrates this outcome under the `#[cfg(not(feature = "error_refund"))]` branch, confirming the token loss is a known, untreated code path. [7](#0-6)

### Citations

**File:** engine-precompiles/src/native.rs (L36-39)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
```

**File:** engine-precompiles/src/native.rs (L449-483)
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
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
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

**File:** engine-tests/src/tests/erc20_connector.rs (L623-666)
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
    }
```
