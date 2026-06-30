### Title
Hardcoded `FT_TRANSFER_GAS` Stipend in `ExitToNear` Precompile May Cause Permanent Freezing of Bridged ERC-20 Token Funds - (File: `engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile attaches a hardcoded, fixed NEAR gas amount (`FT_TRANSFER_GAS = 10 TGas`) to the `ft_transfer` / `ft_transfer_call` cross-contract promise dispatched to the NEP-141 token contract during an ERC-20 exit. This is the direct analog of Ethereum's `payable(*).transfer(uint)` 2,300-gas stipend: a fixed, non-configurable gas budget that may be insufficient for some NEP-141 token implementations. If the promise fails due to gas exhaustion and the `error_refund` compile-time feature is not enabled, the ERC-20 tokens are already burned in the EVM but the NEP-141 tokens are never transferred, permanently freezing user funds in Aurora's account.

---

### Finding Description

In `engine-precompiles/src/native.rs`, the `costs` module defines fixed NEAR gas constants for all outbound token-transfer promises:

```rust
pub(super) const FT_TRANSFER_GAS: NearGas = NearGas::new(10_000_000_000_000);   // 10 TGas
pub(super) const FT_TRANSFER_CALL_GAS: NearGas = NearGas::new(70_000_000_000_000); // 70 TGas
pub(super) const EXIT_TO_NEAR_CALLBACK_GAS: NearGas = NearGas::new(10_000_000_000_000); // 10 TGas
``` [1](#0-0) 

When a user calls the `ExitToNear` precompile (e.g., from an ERC-20 `burn`+exit function), the precompile constructs a `PromiseCreateArgs` with `attached_gas` set to one of these fixed constants:

```rust
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
``` [2](#0-1) 

The ERC-20 tokens are burned inside the EVM *before* this promise is dispatched. If the NEP-141 contract's `ft_transfer` requires more than 10 TGas (e.g., due to complex internal accounting, hooks, or storage operations), the NEAR promise fails.

The refund path is gated behind the `error_refund` compile-time feature:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [3](#0-2) 

When `error_refund` is not enabled, `refund` is `None`. In `exit_to_near_precompile_callback`, the failure branch only executes if `args.refund` is `Some`:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None
};
``` [4](#0-3) 

Without `error_refund`, a failed `ft_transfer` promise produces no refund: the ERC-20 tokens are permanently burned and the NEP-141 tokens remain locked in Aurora's account with no recovery path.

Even with `error_refund` enabled, the callback itself is allocated only `EXIT_TO_NEAR_CALLBACK_GAS = 10 TGas`. If the callback's own execution (which calls `engine::refund_on_error` and re-mints ERC-20 tokens via an EVM call) exhausts this budget, the refund also fails silently.

---

### Impact Explanation

**Impact: Permanent freezing of funds.**

The ERC-20 tokens are burned in the EVM at the point the precompile runs. If the downstream `ft_transfer` NEAR promise fails due to the fixed gas stipend being insufficient, and the `error_refund` feature is absent or its callback also runs out of gas, the user's tokens are permanently lost: the ERC-20 balance is zero and the NEP-141 tokens remain in Aurora's custody with no mechanism to reclaim them.

---

### Likelihood Explanation

**Likelihood: Low-to-Medium.**

Standard NEP-141 `ft_transfer` implementations (e.g., the reference near-contract-standards implementation) consume well under 10 TGas. However:

1. Any NEP-141 token can be permissionlessly registered on Aurora via `deploy_erc20_token`. A token with a non-trivial `ft_transfer` (e.g., one that performs additional cross-contract calls, complex storage operations, or fee-on-transfer logic) could exceed 10 TGas.
2. NEAR gas costs can change across protocol upgrades, making a previously-sufficient stipend insufficient in the future.
3. The codebase itself acknowledges uncertainty about gas amounts — `EXIT_TO_NEAR_GAS` and `EXIT_TO_ETHEREUM_GAS` are both `EthGas::new(0)` with `TODO(#483)` markers, indicating gas calibration is an open concern. [5](#0-4) 

---

### Recommendation

Replace the hardcoded `FT_TRANSFER_GAS` constant with a dynamic gas forwarding approach: forward all remaining prepaid NEAR gas (minus a small reservation for the callback) to the `ft_transfer` promise, analogous to using `.call{gas: gasleft()}(...)` in Solidity instead of `.transfer()`. Alternatively, expose the gas amount as a configurable parameter so it can be updated without a contract upgrade. Ensure the `error_refund` feature is always enabled in production builds, and allocate sufficient gas to the refund callback to guarantee it can complete.

---

### Proof of Concept

1. Deploy a NEP-141 token contract whose `ft_transfer` method performs expensive storage operations or internal cross-contract calls, consuming >10 TGas.
2. Register this token on Aurora via `deploy_erc20_token`, creating a corresponding ERC-20 mirror.
3. Bridge tokens into Aurora (via `ft_transfer_call` to Aurora), receiving ERC-20 tokens.
4. From an EVM contract or EOA, call the ERC-20's `withdrawToNear` function (which calls the `ExitToNear` precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`).
5. The precompile burns the ERC-20 tokens and dispatches a `ft_transfer` NEAR promise with `attached_gas = 10 TGas`.
6. The NEP-141 `ft_transfer` runs out of gas and fails.
7. Without `error_refund`, no refund callback fires. The ERC-20 tokens are gone and the NEP-141 tokens remain in Aurora's account — permanently frozen.

The fixed gas constant is at: [6](#0-5) 

The promise construction using it is at: [7](#0-6)

### Citations

**File:** engine-precompiles/src/native.rs (L42-62)
```rust
mod costs {
    use crate::prelude::types::{EthGas, NearGas};

    // TODO(#483): Determine the correct amount of gas
    pub(super) const EXIT_TO_NEAR_GAS: EthGas = EthGas::new(0);

    // TODO(#483): Determine the correct amount of gas
    pub(super) const EXIT_TO_ETHEREUM_GAS: EthGas = EthGas::new(0);

    /// Value determined experimentally based on tests and mainnet data. Example:
    /// `https://explorer.mainnet.near.org/transactions/5CD7NrqWpK3H8MAAU4mYEPuuWz9AqR9uJkkZJzw5b8PM#D1b5NVRrAsJKUX2ZGs3poKViu1Rgt4RJZXtTfMgdxH4S`
    pub(super) const FT_TRANSFER_GAS: NearGas = NearGas::new(10_000_000_000_000);

    pub(super) const FT_TRANSFER_CALL_GAS: NearGas = NearGas::new(70_000_000_000_000);

    /// Value determined experimentally based on tests.
    pub(super) const EXIT_TO_NEAR_CALLBACK_GAS: NearGas = NearGas::new(10_000_000_000_000);

    // TODO(#332): Determine the correct amount of gas
    pub(super) const WITHDRAWAL_GAS: NearGas = NearGas::new(100_000_000_000_000);
}
```

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

**File:** engine-precompiles/src/native.rs (L456-468)
```rust
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
