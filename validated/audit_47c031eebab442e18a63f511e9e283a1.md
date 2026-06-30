### Title
Permanent ERC-20 Fund Freeze When `ExitToNear` Promise Fails Without Refund Callback — (`engine-precompiles/src/native.rs`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

When a user calls `withdrawToNear` on an `EvmErc20V2` ERC-20 contract, tokens are burned from the EVM before the NEAR `ft_transfer` promise is dispatched. If the NEAR-side promise fails (e.g., recipient not registered for storage), and the `error_refund` compile-time feature is absent, no refund callback is ever scheduled. The burned ERC-20 tokens are permanently unrecoverable, and the corresponding NEP-141 tokens remain locked in Aurora's account.

---

### Finding Description

**Step 1 — ERC-20 burns tokens before calling the precompile (unchecked return value)**

In `EvmErc20V2.sol`, `withdrawToNear` burns the caller's tokens first, then calls the `ExitToNear` precompile via inline assembly. The return value `res` of the `call` opcode is never checked:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    address sender = _msgSender();
    _burn(sender, amount);          // ← tokens burned here, irreversibly

    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
    uint input_size = 1 + 20 + 32 + recipient.length;

    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        // res is never checked
    }
}
``` [1](#0-0) 

In the EVM, a failed `call` to a precompile returns `0` without reverting the caller. Since `res` is ignored, the burn is committed even if the precompile fails.

**Step 2 — The precompile conditionally omits the refund callback**

In `engine-precompiles/src/native.rs`, the `ExitToNear` precompile constructs a `callback_args` struct. When the `error_refund` feature is **not** compiled in, `refund` is hardcoded to `None`:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [2](#0-1) 

For a standard (non-wNEAR) ERC-20 exit, `transfer_near` is also `None`. This makes `callback_args` equal to `default()`, so the promise is constructed **without any callback**:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback scheduled
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [3](#0-2) 

**Step 3 — The callback that would refund is never invoked**

`exit_to_near_precompile_callback` handles the refund path only when `args.refund` is `Some`:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
``` [4](#0-3) 

Without `error_refund`, `args.refund` is always `None`, and no callback is even scheduled. If the NEAR `ft_transfer` fails, there is no mechanism to restore the burned ERC-20 tokens.

**The missing intermediate step (analog to `unbond()`):**

| Original (Stakelink) | Aurora Engine |
|---|---|
| `unbond()` must be called before `unstakeRemovedPrincipal()` | Refund callback must be scheduled before `ft_transfer` can fail |
| Removed-operator code path skips `unbond()` | Non-`error_refund` build skips the callback entirely |
| `unstakeRemovedPrincipal()` always reverts → funds locked | `ft_transfer` failure → no refund → tokens permanently burned |

The test suite explicitly documents this behavior:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

When `ft_transfer` fails on the NEAR side (e.g., recipient account not registered for storage with the NEP-141 contract), the ERC-20 tokens are already burned from the EVM and cannot be recovered. The corresponding NEP-141 tokens remain locked in Aurora's account. Neither the user nor any protocol actor can recover them without a contract upgrade.

---

### Likelihood Explanation

**Medium.** Any user calling `withdrawToNear` with a recipient NEAR account that has not performed a `storage_deposit` on the NEP-141 contract will trigger this. This is a common mistake (the NEAR storage registration requirement is non-obvious to EVM users). The condition is reachable by any unprivileged EVM token holder with no special access required. The vulnerability is active whenever the production binary is compiled without the `error_refund` feature.

---

### Recommendation

1. **In `EvmErc20V2.sol`**: Check the return value of the precompile `call` and revert if it fails, so the `_burn` is rolled back:
   ```solidity
   assembly {
       let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
       if iszero(res) { revert(0, 0) }
   }
   ```

2. **In `engine-precompiles/src/native.rs`**: Always schedule the refund callback for ERC-20 exits, regardless of the `error_refund` feature flag. The callback is the only mechanism to restore tokens when the NEAR-side promise fails.

3. Ensure the production binary is always compiled with `error_refund` enabled, or make the refund path unconditional.

---

### Proof of Concept

1. Deploy an ERC-20 backed by a NEP-141 token on Aurora (via `deploy_erc20_token`).
2. Bridge NEP-141 tokens into Aurora via `ft_transfer_call` → ERC-20 minted to user.
3. User calls `withdrawToNear(recipient_bytes, amount)` where `recipient` is a NEAR account **not registered** for storage with the NEP-141 contract.
4. `_burn(sender, amount)` executes — ERC-20 balance reduced.
5. Precompile schedules `ft_transfer` on the NEP-141 contract.
6. NEAR executes `ft_transfer` → fails with "account not registered".
7. Without `error_refund`: no callback fires, no refund issued.
8. **Result**: ERC-20 tokens are permanently burned; NEP-141 tokens remain locked in Aurora's account. User has lost their funds with no recovery path. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

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

**File:** engine-tests/src/tests/erc20_connector.rs (L656-660)
```rust
        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
```
