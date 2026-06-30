### Title
ERC-20 Tokens Permanently Lost When `ft_transfer` Fails in `ExitToNear` Precompile Without `error_refund` Feature - (File: `engine-precompiles/src/native.rs`)

### Summary
When the `error_refund` compile-time feature is not enabled, ERC-20 tokens burned during a `withdrawToNear` call are permanently destroyed if the downstream `ft_transfer` NEAR promise fails. No callback is scheduled to re-mint the burned tokens on failure, resulting in irreversible fund loss for the user.

### Finding Description
The `ExitToNear` precompile handles ERC-20-to-NEP-141 bridge exits. The flow is:

1. The ERC-20 contract (`EvmErc20.sol`) burns the user's tokens first, then calls the precompile.
2. The precompile schedules an `ft_transfer` (or `ft_transfer_call`) promise to the NEP-141 contract.
3. A callback (`exit_to_near_precompile_callback`) is only attached when `callback_args != ExitToNearPrecompileCallbackArgs::default()`.

The critical gate is in `ExitToNear::run()`:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None when feature is disabled
    transfer_near: transfer_near_args,
};
```

For a standard ERC-20 exit (not wNEAR unwrap), `transfer_near` is also `None` (returned by `exit_erc20_token_to_near`). This means `callback_args == ExitToNearPrecompileCallbackArgs::default()` evaluates to `true`, and the promise is created without any callback:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback, no refund on failure
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
```

If the `ft_transfer` promise fails (e.g., recipient NEAR account not registered with the NEP-141 token, NEP-141 contract paused, or the NEP-141 contract enforces an access-control list), there is no callback to re-mint the already-burned ERC-20 tokens. The user's funds are permanently destroyed.

The `EvmErc20.sol` contract burns tokens **before** calling the precompile:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);   // tokens destroyed first
    ...
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, ...)
    }
}
```

The codebase's own test explicitly acknowledges this loss:

```rust
#[cfg(feature = "error_refund")]
let balance = FT_TRANSFER_AMOUNT.into();
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
```

### Impact Explanation
**Critical — Permanent freezing/destruction of funds.** A user who calls `withdrawToNear` on any bridged ERC-20 token loses their tokens permanently if the `ft_transfer` promise fails. The ERC-20 tokens are burned on the Aurora side, the NEP-141 tokens are never delivered, and no re-mint occurs. The loss is irreversible with no admin recovery path.

### Likelihood Explanation
**Medium.** The `ft_transfer` promise fails in realistic, non-adversarial conditions:
- The recipient NEAR account is not registered (storage deposit not paid) with the NEP-141 token — a common user mistake.
- The NEP-141 contract is paused or has an access-control list (analogous to USDC blacklisting in the original report).
- The recipient account ID does not exist on NEAR.

Any of these conditions, which are entirely within normal operational range, trigger the permanent loss.

### Recommendation
1. **Enable `error_refund` unconditionally** in all production builds, or promote it from an optional feature to a mandatory code path.
2. **Migrate all deployed ERC-20 contracts to `EvmErc20V2.sol`**, which encodes the refund address (`sender`) in the precompile input, making the refund mechanism functional when `error_refund` is enabled.
3. As a defense-in-depth measure, consider inverting the control flow: schedule the callback unconditionally and only skip the re-mint if the promise succeeded, rather than skipping the callback entirely when `error_refund` is absent.

### Proof of Concept
**Entry path (unprivileged EVM user):**

1. User holds 100 units of a bridged NEP-141 token as ERC-20 on Aurora.
2. User calls `EvmErc20.withdrawToNear("unregistered.near", 100)`.
3. `_burn(msg.sender, 100)` executes — ERC-20 balance drops to 0.
4. The `ExitToNear` precompile schedules `ft_transfer({"receiver_id":"unregistered.near","amount":"100"})` on the NEP-141 contract with no callback (because `error_refund` is disabled and `transfer_near` is `None`).
5. The NEP-141 `ft_transfer` fails because `unregistered.near` has no storage deposit.
6. No callback fires. No re-mint occurs.
7. User has 0 ERC-20 tokens and 0 NEP-141 tokens. Funds are permanently lost.

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` reproduces this exact scenario and confirms the balance discrepancy under `#[cfg(not(feature = "error_refund"))]`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** engine-precompiles/src/native.rs (L36-39)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
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

**File:** engine-precompiles/src/native.rs (L699-725)
```rust
#[cfg(feature = "error_refund")]
#[allow(clippy::unnecessary_wraps)]
fn refund_call_args(
    params: &ExitToNearParams,
    event: &events::ExitToNear,
) -> Option<RefundCallArgs> {
    Some(RefundCallArgs {
        recipient_address: match params {
            ExitToNearParams::BaseToken(params) => params.refund_address,
            ExitToNearParams::Erc20TokenParams(params) => params.refund_address,
        },
        erc20_address: match params {
            ExitToNearParams::BaseToken(_) => None,
            ExitToNearParams::Erc20TokenParams(_) => {
                let erc20_address = match event {
                    events::ExitToNear::Legacy(legacy) => legacy.erc20_address,
                    events::ExitToNear::Omni(omni) => omni.erc20_address,
                };
                Some(erc20_address)
            }
        },
        amount: types::u256_to_arr(&match event {
            events::ExitToNear::Legacy(legacy) => legacy.amount,
            events::ExitToNear::Omni(omni) => omni.amount,
        }),
    })
}
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-60)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
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
