### Title
`ExitToNear` Omni Path Burns Full ERC-20 Balance Without Accounting for Partial `ft_transfer_call` Returns — (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile's Omni message path invokes `ft_transfer_call` on the NEP-141 contract. Under the NEP-141 standard, the receiving contract may return a non-zero unused amount, causing `ft_resolve_transfer` to credit those tokens back to the sender (the eth connector). However, the ERC-20 tokens on the Aurora side are burned for the **full requested amount** before the NEAR promise executes. When `error_refund` is not compiled in, no callback is attached at all. Even when it is compiled in, the refund callback is constructed with the full amount and is designed only for complete failure — not for partial returns. The unused NEP-141 tokens accumulate in the eth connector's balance with no corresponding ERC-20 tokens, permanently freezing the user's funds.

---

### Finding Description

In `engine-precompiles/src/native.rs`, the `ExitToNear::run` function handles the Omni message case by selecting `ft_transfer_call` as the method:

```rust
Some(Message::Omni(msg)) => Ok((
    eth_connector_account_id,
    ft_transfer_call_args(..., context.apparent_value, msg)?,
    ...,
    "ft_transfer_call".to_string(),
    None,   // transfer_near_args is None
)),
``` [1](#0-0) 

The callback arguments are then assembled:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,   // None for Omni
};
``` [2](#0-1) 

The promise is then conditionally wrapped with a callback only when `callback_args` differs from its default value:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [3](#0-2) 

**Path 1 — `error_refund` not enabled:** `refund` is `None` and `transfer_near` is `None`, so `callback_args == default()`. No callback is attached. `ft_transfer_call` fires and any unused tokens returned by the receiving contract are silently credited back to the eth connector's NEP-141 balance. The user's ERC-20 tokens are already burned.

**Path 2 — `error_refund` enabled:** A callback is attached, but `refund_call_args` encodes the **full** original amount as the refund target:

```rust
fn refund_call_args(params: &ExitToNearParams, event: &events::ExitToNear) -> Option<RefundCallArgs> {
    Some(RefundCallArgs {
        ...
        amount: types::u256_to_arr(&match event {
            events::ExitToNear::Legacy(legacy) => legacy.amount,
            events::ExitToNear::Omni(omni) => omni.amount,
        }),
    })
}
``` [4](#0-3) 

This callback is designed to trigger a full refund on complete failure. It does not inspect the actual unused-token return value from `ft_transfer_call` to compute a **partial** refund. A partial return (0 < unused < amount) leaves the difference permanently unaccounted.

---

### Impact Explanation

**Permanent freezing of user funds (Critical).**

The NEP-141 `ft_transfer_call` standard explicitly allows the receiving contract to return unused tokens. When this happens:

- The user's ERC-20 tokens are burned for the full amount on the Aurora EVM side.
- The unused NEP-141 tokens are returned to the eth connector's NEP-141 balance.
- No ERC-20 tokens are re-minted for the user.
- The returned NEP-141 tokens are stranded in the connector with no on-chain mechanism to reclaim them as ERC-20 tokens.

The user suffers a permanent, irrecoverable loss equal to the unused portion.

---

### Likelihood Explanation

**Medium.** Any NEAR contract that implements `ft_on_transfer` and returns a non-zero unused amount triggers this path. This is standard, documented NEP-141 behavior used by DeFi protocols (e.g., AMMs that reject deposits exceeding a pool limit, lending protocols with utilization caps, contracts with per-user deposit ceilings). A user does not need to be malicious — they simply need to target any such contract via the Omni exit path.

---

### Recommendation

1. **Inspect the `ft_transfer_call` result in the callback.** The `exit_to_near_precompile_callback` must read the actual transferred amount returned by `ft_resolve_transfer` and re-mint ERC-20 tokens for the unused portion.
2. **Do not rely on the pre-encoded full-amount refund.** The refund amount must be computed dynamically from the promise result, not from the original input amount.
3. **Ensure the callback is always attached for `ft_transfer_call` paths**, regardless of whether `error_refund` is compiled in, since partial returns are a standard NEP-141 behavior, not an error condition.

---

### Proof of Concept

1. User holds 1000 units of ERC-20 token `T` on Aurora.
2. User calls `ExitToNear` with flag `0x1` (ERC-20), amount = 1000, Omni message targeting a NEAR DeFi contract `defi.near` that has a 600-unit deposit cap.
3. Aurora burns 1000 ERC-20 `T` tokens from the user.
4. `ft_transfer_call("defi.near", "1000", msg)` is dispatched as a NEAR promise.
5. `defi.near::ft_on_transfer` accepts 600 units and returns 400 as unused.
6. `ft_resolve_transfer` credits 400 NEP-141 `T` tokens back to the eth connector account.
7. No callback re-mints 400 ERC-20 `T` tokens for the user.
8. User has lost 400 units permanently; the eth connector holds 400 orphaned NEP-141 tokens. [5](#0-4)

### Citations

**File:** engine-precompiles/src/native.rs (L444-501)
```rust
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

**File:** engine-precompiles/src/native.rs (L519-535)
```rust
        Some(Message::Omni(msg)) => Ok((
            eth_connector_account_id,
            ft_transfer_call_args(
                &exit_params.receiver_account_id,
                context.apparent_value,
                msg,
            )?,
            events::ExitToNear::Omni(ExitToNearOmni {
                sender: Address::new(context.caller),
                erc20_address: events::ETH_ADDRESS,
                dest: exit_params.receiver_account_id.to_string(),
                amount: context.apparent_value,
                msg: msg.to_string(),
            }),
            "ft_transfer_call".to_string(),
            None,
        )),
```

**File:** engine-precompiles/src/native.rs (L700-725)
```rust
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
