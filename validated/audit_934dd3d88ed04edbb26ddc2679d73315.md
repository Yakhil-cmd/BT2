### Title
Hardcoded `FT_TRANSFER_GAS` Stipend in `ExitToNear` Precompile Causes Permanent Token Loss When Promise Fails Without `error_refund` Feature - (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile attaches a hardcoded `FT_TRANSFER_GAS = 10_000_000_000_000` (10 TGas) to the NEAR `ft_transfer` / `ft_transfer_call` promise it schedules. This is the direct Aurora-Engine analog of Solidity's `.send()` / `.transfer()` fixed-2300-gas stipend. If the attached gas is insufficient for the NEP-141 contract's `ft_transfer` execution (due to NEAR protocol gas-cost changes or a complex NEP-141 implementation), the promise fails. When the `error_refund` compile-time feature is **not** enabled (the default), `refund` is hardcoded to `None`, so no callback re-mints the already-burned ERC-20 tokens. The user's funds are permanently destroyed.

---

### Finding Description

In `engine-precompiles/src/native.rs`, the `costs` module defines all NEAR gas amounts as compile-time constants:

```rust
// engine-precompiles/src/native.rs  lines 42-62
mod costs {
    // TODO(#483): Determine the correct amount of gas
    pub(super) const EXIT_TO_NEAR_GAS: EthGas = EthGas::new(0);
    // TODO(#483): Determine the correct amount of gas
    pub(super) const EXIT_TO_ETHEREUM_GAS: EthGas = EthGas::new(0);

    /// Value determined experimentally based on tests and mainnet data.
    pub(super) const FT_TRANSFER_GAS: NearGas = NearGas::new(10_000_000_000_000);
    pub(super) const FT_TRANSFER_CALL_GAS: NearGas = NearGas::new(70_000_000_000_000);
    /// Value determined experimentally based on tests.
    pub(super) const EXIT_TO_NEAR_CALLBACK_GAS: NearGas = NearGas::new(10_000_000_000_000);
    // TODO(#332): Determine the correct amount of gas
    pub(super) const WITHDRAWAL_GAS: NearGas = NearGas::new(100_000_000_000_000);
}
``` [1](#0-0) 

When `ExitToNear::run()` is called, it constructs the outbound NEAR promise with this fixed gas:

```rust
// lines 456-468
let attached_gas = if method == "ft_transfer_call" {
    costs::FT_TRANSFER_CALL_GAS
} else {
    costs::FT_TRANSFER_GAS          // ← hardcoded 10 TGas
};
let transfer_promise = PromiseCreateArgs {
    target_account_id: nep141_address,
    method,
    args: args.into_bytes(),
    attached_balance: Yocto::new(1),
    attached_gas,                   // ← fixed stipend, cannot be overridden by caller
};
``` [2](#0-1) 

The `refund` field of the callback args is conditionally compiled:

```rust
// lines 449-455
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,                   // ← no refund path when feature is absent
    transfer_near: transfer_near_args,
};
``` [3](#0-2) 

When `error_refund` is absent, `callback_args` equals `ExitToNearPrecompileCallbackArgs::default()`, so the promise is scheduled as a bare `PromiseArgs::Create` with **no callback at all**:

```rust
// lines 470-483
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback, no refund
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [4](#0-3) 

The test suite explicitly documents this behavior:

```rust
// engine-tests/src/tests/erc20_connector.rs  lines 656-660
#[cfg(feature = "error_refund")]
let balance = FT_TRANSFER_AMOUNT.into();
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

The same pattern applies to the ETH-exit path in `engine-tests/src/tests/erc20_connector.rs`:

```rust
// lines 771-775
#[cfg(feature = "error_refund")]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
// If the refund feature is not enabled, then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
``` [6](#0-5) 

Historical precedent confirms this class of bug is real in Aurora Engine. `CHANGES.md` records:

> "The gas limit for `deposit` and `ft_on_transfer` were changed as they were not attaching enough gas" (v2.3.0) [7](#0-6) 

---

### Impact Explanation

**Impact: Critical — Permanent freezing / destruction of user funds.**

The exit flow is:
1. ERC-20 tokens are **burned** on Aurora (irreversible EVM state change).
2. A NEAR promise is scheduled to call `ft_transfer` on the NEP-141 contract with exactly 10 TGas.
3. If the promise fails (gas exhausted), and `error_refund` is not compiled in, there is **no callback** and **no re-mint**. The burned ERC-20 tokens are gone; the user never receives NEP-141 tokens on NEAR.

This matches the "Permanent freezing of funds" critical impact category.

---

### Likelihood Explanation

**Likelihood: Medium.**

- The `error_refund` feature is opt-in and not the default build. Any deployment built without it is fully exposed.
- NEAR protocol gas costs have already changed once in Aurora's history, causing exactly this class of failure (see CHANGES.md v2.3.0 above).
- The TODO comments on `EXIT_TO_NEAR_GAS` and `WITHDRAWAL_GAS` explicitly acknowledge the gas values are unresolved.
- Any NEP-141 token whose `ft_transfer` implementation performs additional storage operations or cross-contract calls can exceed 10 TGas.
- An unprivileged EVM user triggers this by simply calling the `ExitToNear` precompile with any bridged ERC-20 token.

---

### Recommendation

1. **Enable `error_refund` unconditionally** in production builds, or make the refund path the default (not feature-gated). The refund callback in `exit_to_near_precompile_callback` already handles re-minting burned ERC-20 tokens and returning ETH.

2. **Do not hardcode gas stipends.** Allow the EVM caller to specify the NEAR gas to attach (bounded by a minimum floor), mirroring how Solidity's `.call{gas: ...}()` replaced `.send()` / `.transfer()`. Alternatively, use `prepaid_gas() - used_gas()` minus a safety margin at promise-creation time.

3. **Audit `EXIT_TO_NEAR_CALLBACK_GAS = 10 TGas`** as well. Even when `error_refund` is enabled, if the callback itself runs out of gas while executing `refund_on_error` (which performs an EVM call to re-mint tokens), the refund silently fails and funds are still lost.

---

### Proof of Concept

**Entry path (unprivileged EVM user):**

1. User holds bridged ERC-20 tokens on Aurora (e.g., `some_nep141.aurora`).
2. User calls the ERC-20's `withdrawToNear("victim.near", amount)` function, which internally calls the `ExitToNear` precompile at address `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`.
3. The precompile burns the ERC-20 tokens and schedules a NEAR `ft_transfer` promise with `attached_gas = 10_000_000_000_000` (10 TGas).
4. The NEP-141 contract's `ft_transfer` requires >10 TGas (e.g., due to a storage-intensive implementation or a NEAR protocol gas repricing).
5. The NEAR promise fails with `GasExceeded`.
6. Because `error_refund` is not compiled in, `refund = None` and no callback is scheduled.
7. The ERC-20 tokens remain burned; the user receives nothing on NEAR. Funds are permanently lost.

**Relevant code path:**
- `ExitToNear::run()` → `engine-precompiles/src/native.rs` lines 387–501
- `filter_promises_from_logs()` → `engine/src/engine.rs` lines 1634–1717 (schedules the promise)
- `exit_to_near_precompile_callback()` → `engine/src/contract_methods/connector.rs` lines 195–246 (never called when no callback is attached) [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** engine-precompiles/src/native.rs (L387-501)
```rust
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        is_static: bool,
    ) -> EvmPrecompileResult {
        // ETH (base) transfer input format: (85 bytes)
        //  - flag (1 byte)
        //  - refund_address (20 bytes), present if the feature "error_refund" is enabled
        //  - recipient_account_id (max MAX_INPUT_SIZE - 20 - 1 bytes)
        // ERC-20 transfer input format: (124 bytes)
        //  - flag (1 byte)
        //  - refund_address (20 bytes), present if the feature "error_refund" is enabled.
        //  - amount (32 bytes)
        //  - recipient_account_id (max MAX_INPUT_SIZE - 1 - (20) - 32 bytes)
        //  - `:unwrap` suffix in a case of wNEAR (7 bytes)
        let required_gas = Self::required_gas(input)?;

        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }

        let exit_to_near_params = ExitToNearParams::try_from(input)?;

        let (nep141_address, args, exit_event, method, transfer_near_args) =
            match exit_to_near_params {
                // ETH(base) token transfer
                //
                // Input slice format:
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 (base) tokens, or also can contain the `:unwrap` suffix in case of
                //  withdrawing wNEAR, or another message of JSON in case of OMNI, or address of
                //  receiver in case of transfer tokens to another engine contract.
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
                // ERC-20 token transfer
                //
                // This precompile branch is expected to be called from the ERC-20 burn function.
                //
                // Input slice format:
                //  amount (U256 big-endian bytes) - the amount that was burned
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 tokens, or also can contain the `:unwrap` suffix in case of withdrawing
                //  wNEAR, or another message of JSON in case of OMNI, or address of receiver in case
                //  of transfer tokens to another engine contract.
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
            };

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
            address: exit_to_near::ADDRESS.raw(),
            topics: Vec::new(),
            data: borsh::to_vec(&promise).unwrap(),
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
            cost: required_gas,
            output: Vec::new(),
        })
    }
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

**File:** CHANGES.md (L674-675)
```markdown
- The gas limit for `deposit` and `ft_on_transfer` were changed as they were not attaching enough
  gas, as changed by [@mrLSD]. ([#389])
```

**File:** engine/src/engine.rs (L1634-1683)
```rust
fn filter_promises_from_logs<I, T, P>(
    io: &I,
    handler: &mut P,
    logs: T,
    current_account_id: &AccountId,
) -> Vec<ResultLog>
where
    T: IntoIterator<Item = Log>,
    P: PromiseHandler,
    I: IO + Copy,
{
    let mut previous_promise: Option<PromiseId> = None;
    logs.into_iter()
        .filter_map(|log| {
            if log.address == exit_to_near::ADDRESS.raw()
                || log.address == exit_to_ethereum::ADDRESS.raw()
            {
                if log.topics.is_empty() {
                    if let Ok(promise) = PromiseArgs::try_from_slice(&log.data) {
                        match promise {
                            PromiseArgs::Create(promise) => {
                                // Safety: this promise creation is safe because it does not come from
                                // users directly. The exit precompile only create promises which we
                                // are able to execute without violating any security invariants.
                                let id = match previous_promise {
                                    Some(base_id) => {
                                        schedule_promise_callback(handler, base_id, &promise)
                                    }
                                    None => schedule_promise(handler, &promise),
                                };
                                previous_promise = Some(id);
                            }
                            PromiseArgs::Callback(promise) => {
                                // Safety: This is safe because the promise data comes from our own
                                // exit precompiles. See note above.
                                let base_id = match previous_promise {
                                    Some(base_id) => {
                                        schedule_promise_callback(handler, base_id, &promise.base)
                                    }
                                    None => schedule_promise(handler, &promise.base),
                                };
                                let id =
                                    schedule_promise_callback(handler, base_id, &promise.callback);
                                previous_promise = Some(id);
                            }
                            PromiseArgs::Recursive(_) => {
                                unreachable!("Exit precompiles do not produce recursive promises")
                            }
                        }
                    }
```

**File:** engine/src/contract_methods/connector.rs (L195-246)
```rust
#[named]
pub fn exit_to_near_precompile_callback<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;

        // This function should only be called as the callback of
        // exactly one promise.
        if handler.promise_results_count() != 1 {
            return Err(errors::ERR_PROMISE_COUNT.into());
        }

        let args: ExitToNearPrecompileCallbackArgs = io.read_input_borsh()?;

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

        Ok(maybe_result)
    })
}
```
