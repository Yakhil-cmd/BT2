### Title
ETH Permanently Frozen at Precompile Address When `ft_transfer` Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

### Summary

When the `error_refund` compile-time feature is disabled (the default), an unprivileged EVM caller who sends ETH value to the `ExitToNear` precompile (flag `0x0`) will have their ETH permanently frozen at the precompile address if the downstream `ft_transfer` NEAR promise fails. No callback is attached to handle the failure, and no refund path exists.

### Finding Description

The `ExitToNear::run` function constructs `callback_args` as follows: [1](#0-0) 

When `error_refund` is not enabled, `refund` is hardcoded to `None`. For the base token path (`flag=0x0`), `exit_base_token_to_near` always returns `transfer_near_args = None`: [2](#0-1) 

`ExitToNearPrecompileCallbackArgs` derives `Default` with both fields as `None`: [3](#0-2) 

Because `callback_args == ExitToNearPrecompileCallbackArgs::default()` evaluates to `true`, the promise is created **without a callback**: [4](#0-3) 

If the `ft_transfer` promise fails (e.g., receiver account not registered with the eth-connector), there is no `exit_to_near_precompile_callback` invocation, no `refund_on_error` call, and no EVM balance restoration. The ETH transferred by the EVM's value mechanism from the caller to the precompile address is permanently frozen there.

The `error_refund` feature is **not in the default feature set** of either crate: [5](#0-4) [6](#0-5) 

### Impact Explanation

The ETH is deducted from the caller's EVM balance and credited to the precompile address (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) by the EVM's value transfer mechanism before the precompile runs. If `ft_transfer` fails and no callback exists, the ETH is permanently frozen at the precompile address with no recovery mechanism. This is **Critical — Permanent freezing of funds**.

The test suite explicitly acknowledges this behavior: [7](#0-6) 

### Likelihood Explanation

- Any unprivileged EVM caller can invoke `ExitToNear` with ETH value and flag `0x0`.
- `ft_transfer` fails in a realistic, non-adversarial scenario: if the NEAR receiver account has not registered storage with the eth-connector, the NEP-141 `ft_transfer` will be rejected.
- The `error_refund` feature is not enabled by default, so any production build compiled without it is affected.
- No admin compromise or special privilege is required.

### Recommendation

1. **Enable `error_refund` in all production builds** of the engine WASM contract. This feature already implements the correct callback-based refund path via `exit_to_near_precompile_callback` → `refund_on_error`.
2. Alternatively, unconditionally attach the callback for the base token path regardless of the feature flag, since the cost of an extra callback on success is negligible compared to the risk of permanent fund loss.
3. Consider making `error_refund` a default feature or removing the conditional compilation entirely.

### Proof of Concept

1. Deploy Aurora engine **without** the `error_refund` feature.
2. Create a NEAR account `victim.near` that has **not** registered storage with the eth-connector (so `ft_transfer` to it will fail).
3. From an EVM account with balance `B`, submit an EVM transaction calling `ExitToNear` at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` with:
   - `value = V` (nonzero ETH)
   - `input = [0x00] ++ b"victim.near"` (flag=0x0, base token path)
4. Observe that the EVM transaction succeeds and a `PromiseArgs::Create(ft_transfer)` promise is scheduled with no callback.
5. The `ft_transfer` promise fails (receiver not registered).
6. Assert: caller's EVM balance = `B - V` (ETH deducted, not refunded).
7. Assert: `victim.near` NEP-141 balance = 0 (transfer never completed).
8. Assert: precompile address EVM balance = `V` (ETH frozen, irrecoverable). [8](#0-7) [9](#0-8)

### Citations

**File:** engine-precompiles/src/native.rs (L430-433)
```rust
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
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

**File:** engine-precompiles/src/native.rs (L536-553)
```rust
        None => Ok((
            eth_connector_account_id,
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            format!(
                r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                exit_params.receiver_account_id,
                context.apparent_value.as_u128()
            ),
            events::ExitToNear::Legacy(ExitToNearLegacy {
                sender: Address::new(context.caller),
                erc20_address: events::ETH_ADDRESS,
                dest: exit_params.receiver_account_id.to_string(),
                amount: context.apparent_value,
            }),
            "ft_transfer".to_string(),
            None,
        )),
```

**File:** engine-types/src/parameters/connector.rs (L130-134)
```rust
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Default)]
pub struct ExitToNearPrecompileCallbackArgs {
    pub refund: Option<RefundCallArgs>,
    pub transfer_near: Option<TransferNearArgs>,
}
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

**File:** engine/Cargo.toml (L42-48)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
```

**File:** engine-tests/src/tests/erc20_connector.rs (L771-775)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```
