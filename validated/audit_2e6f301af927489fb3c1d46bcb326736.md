### Title
Permanent Fund Freeze When `ExitToNear` Promise Fails Without `error_refund` Feature - (`engine-precompiles/src/native.rs`)

### Summary

When the `error_refund` Cargo feature is not enabled (the default), a failed `ft_transfer` or `ft_transfer_call` NEAR promise triggered by the `ExitToNear` precompile results in the permanent loss of the user's ETH or ERC-20 tokens. There is no retry mechanism and no refund path.

### Finding Description

The `ExitToNear` precompile in `engine-precompiles/src/native.rs` constructs a `ExitToNearPrecompileCallbackArgs` struct that conditionally includes refund information based on the `error_refund` compile-time feature flag: [1](#0-0) 

When `error_refund` is **not** enabled (the default, since it is absent from `[features] default` in both `engine/Cargo.toml` and `engine-precompiles/Cargo.toml`), `refund` is hardcoded to `None`: [2](#0-1) [3](#0-2) 

For the common ETH and ERC-20 exit paths (where `transfer_near` is also `None`), `callback_args` equals the default value, so **no callback promise is attached at all** — only a bare `PromiseArgs::Create` is scheduled: [4](#0-3) 

If the downstream `ft_transfer` or `ft_transfer_call` NEAR promise fails (e.g., recipient account not registered with the NEP-141 contract, connector paused, out of gas), there is no callback to detect the failure and no refund is issued.

For the wNEAR unwrap path (where `transfer_near` is `Some`), a callback **is** attached, but in `exit_to_near_precompile_callback` the failure branch falls through to `else { None }` because `args.refund` is `None`: [5](#0-4) 

The tests explicitly document this behavior: [6](#0-5) [7](#0-6) 

### Impact Explanation

- **ETH exits**: The user's ETH is deducted from their EVM balance and credited to the `exit_to_near` precompile address before the NEAR promise is dispatched. If the promise fails, the ETH is permanently locked in the precompile address with no recovery path.
- **ERC-20 exits**: The ERC-20 tokens are burned from the user's balance before the NEAR `ft_transfer` promise is dispatched. If the promise fails, the tokens are permanently destroyed.

This is a **critical permanent freezing of funds**.

### Likelihood Explanation

The `ft_transfer` NEAR promise can fail for multiple realistic reasons reachable by any unprivileged user:
1. The recipient NEAR account is not registered with the NEP-141 contract (no storage deposit).
2. The eth-connector is paused.
3. Insufficient gas forwarded to the promise.

The `error_refund` feature is not in the `default` feature set of either `aurora-engine` or `aurora-engine-precompiles`, meaning any build that does not explicitly pass `--features error_refund` is vulnerable.

### Recommendation

Enable the `error_refund` feature in the production WASM build, or promote it into the `default` feature set so that the refund callback args are always populated and the `exit_to_near_precompile_callback` can always recover funds on promise failure.

### Proof of Concept

1. User holds ETH on Aurora and calls the `ExitToNear` precompile (flag `0x00`) targeting a NEAR account that has no storage deposit with the eth-connector NEP-141.
2. The EVM deducts ETH from the user's balance.
3. A bare `PromiseArgs::Create` (no callback) is scheduled to call `ft_transfer` on the connector.
4. The `ft_transfer` call fails because the recipient is unregistered.
5. No callback fires; `refund: None` means `exit_to_near_precompile_callback` is never invoked.
6. The ETH is permanently locked in the `exit_to_near` precompile address (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`).
7. The user has no mechanism to recover the funds. [8](#0-7) [9](#0-8)

### Citations

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

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
```

**File:** engine/Cargo.toml (L42-49)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
integration-test = ["log"]
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

**File:** engine-tests/src/tests/erc20_connector.rs (L771-775)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```
