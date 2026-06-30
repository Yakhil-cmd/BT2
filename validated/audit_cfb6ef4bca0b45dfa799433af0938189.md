Based on my analysis of the code, here is my assessment:

---

### Title
Permanent Freezing of Funds via `withdrawToNear` When NEP-141 `ft_transfer` Fails Without `error_refund` Feature — (`etc/eth-contracts/contracts/EvmErc20.sol`, `engine-precompiles/src/native.rs`)

### Summary

When the Aurora Engine is compiled without the `error_refund` feature (which is **not** a default feature), a user calling `withdrawToNear` on an `EvmErc20` contract will have their ERC-20 tokens permanently burned with no refund if the downstream NEP-141 `ft_transfer` promise fails on the NEAR side.

### Finding Description

**Step 1 — ERC-20 burn happens unconditionally before the precompile call.**

In `EvmErc20.sol`, `_burn` is called first, then the precompile is invoked via inline assembly. The return value of the `call` opcode is stored in `res` but never checked: [1](#0-0) 

**Step 2 — The precompile schedules a plain `ft_transfer` promise with no callback when `error_refund` is disabled.**

In `native.rs`, the `callback_args` struct is built with `refund: None` when the feature is absent: [2](#0-1) 

Then the promise type is decided by comparing `callback_args` to its default. For the standard ERC-20 `ft_transfer` path (no `:unwrap`, no omni message), `transfer_near_args` is also `None`, so `callback_args == ExitToNearPrecompileCallbackArgs::default()` is true, and only a bare `PromiseArgs::Create` is emitted — **no callback is attached**: [3](#0-2) 

**Step 3 — `error_refund` is not a default feature.**

In `engine-precompiles/Cargo.toml`, the default features are `["std"]` only: [4](#0-3) 

In `engine/Cargo.toml`, the `contract` feature (the standard WASM build target) does **not** include `error_refund`: [5](#0-4) 

**Step 4 — The `exit_erc20_token_to_near` function confirms no refund path exists in the non-`error_refund` branch.**

The function returns `ft_transfer` as the method and `None` for `transfer_near_args` in the standard ERC-20 withdrawal case: [6](#0-5) 

**Step 5 — The `refund_call_args` function is entirely gated behind `#[cfg(feature = "error_refund")]`.** [7](#0-6) 

### Impact Explanation

When `ft_transfer` is rejected by the NEP-141 contract (e.g., receiver account not registered for storage deposit, or any other NEP-141 rejection), the NEAR promise executor silently discards the failure. Because no callback is scheduled, the engine never learns of the failure and never mints back the burned ERC-20 tokens. The result:

- ERC-20 `totalSupply` is permanently reduced.
- The NEP-141 balance of the intended receiver is unchanged.
- No refund event is emitted.
- The tokens are irrecoverably destroyed.

This directly satisfies **Critical — Permanent freezing of funds**.

### Likelihood Explanation

- Any unprivileged EVM user can call `withdrawToNear` on any `EvmErc20` contract.
- NEAR storage registration failures are a routine operational condition (NEP-145 requires receivers to be registered before receiving tokens).
- The attacker does not need to be the victim; a user can accidentally destroy their own funds by specifying an unregistered receiver account.
- The engine compiled without `error_refund` (the default build) is affected.

### Recommendation

1. **Enable `error_refund` by default** in the `contract` feature of `engine/Cargo.toml`:
   ```toml
   contract = ["log", "error_refund", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
   ```
2. **Check the precompile return value** in `EvmErc20.sol`'s `withdrawToNear` and revert if the precompile call fails, so the burn is rolled back atomically.
3. **Alternatively**, restructure the flow so the burn only occurs inside the callback after `ft_transfer` succeeds (i.e., move the burn to the NEAR-side callback, not the EVM side).

### Proof of Concept

1. Deploy a NEP-141 token contract that requires storage registration.
2. Deploy the corresponding `EvmErc20` mirror on Aurora (without `error_refund` feature compiled in).
3. Mint ERC-20 tokens to `alice.evm`.
4. Have `alice.evm` call `withdrawToNear(unregistered_near_account, amount)`.
5. Observe:
   - ERC-20 `balanceOf(alice.evm)` decreases by `amount`.
   - ERC-20 `totalSupply()` decreases by `amount`.
   - NEP-141 `ft_balance_of(unregistered_near_account)` remains `0`.
   - No refund ERC-20 mint event is emitted.
   - Tokens are permanently destroyed. [1](#0-0) [8](#0-7)

### Citations

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

**File:** engine-precompiles/src/native.rs (L627-647)
```rust
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
    };
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
