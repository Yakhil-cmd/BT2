### Title
`exit_to_near_precompile_callback` Ignores Unused Amount Returned by `ft_transfer_call`, Causing Permanent ERC-20 Token Loss - (File: engine/src/contract_methods/connector.rs)

---

### Summary

When a user calls `withdrawToNear` on an `EvmErc20V2` token using the Omni message path, the `exit_to_near` precompile burns the user's ERC-20 tokens and schedules a `ft_transfer_call` on the backing NEP-141 contract. In the NEP-141 standard, `ft_transfer_call` allows the receiver's `ft_on_transfer` to return a non-zero *unused* amount, which the NEP-141 contract then refunds back to the sender (Aurora). The callback `exit_to_near_precompile_callback` receives this unused amount in its `PromiseResult::Successful` payload but unconditionally ignores it, never re-minting the corresponding ERC-20 tokens. The user's burned ERC-20 tokens are permanently unrecoverable for the unused portion.

---

### Finding Description

The `exit_to_near` precompile in `engine-precompiles/src/native.rs` handles the Omni message path by issuing a `ft_transfer_call` (rather than a plain `ft_transfer`) to the NEP-141 contract:

```rust
Some(Message::Omni(msg)) => (
    nep141_account_id,
    ft_transfer_call_args(&exit_params.receiver_account_id, exit_params.amount, msg)?,
    "ft_transfer_call",
    None,   // transfer_near_args is None for Omni
    events::ExitToNear::Omni(ExitToNearOmni { ... }),
)
``` [1](#0-0) 

A callback `exit_to_near_precompile_callback` is attached to this promise:

```rust
PromiseArgs::Callback(PromiseWithCallbackArgs {
    base: transfer_promise,
    callback: PromiseCreateArgs {
        method: "exit_to_near_precompile_callback".to_string(),
        ...
    },
})
``` [2](#0-1) 

Inside `exit_to_near_precompile_callback`, the success branch is:

```rust
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    if let Some(args) = args.transfer_near {
        // transfer NEAR (wNEAR unwrap path only)
    }
    None   // <-- does nothing for Omni path
} else if let Some(args) = args.refund {
    // refund on full failure only
    ...
};
```

<cite repo="Camomtat/aurora-engine--001" path="engine/src/contract_methods/connector.rs"

### Citations

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

**File:** engine-precompiles/src/native.rs (L611-623)
```rust
        Some(Message::Omni(msg)) => (
            nep141_account_id,
            ft_transfer_call_args(&exit_params.receiver_account_id, exit_params.amount, msg)?,
            "ft_transfer_call",
            None,
            events::ExitToNear::Omni(ExitToNearOmni {
                sender: Address::new(erc20_address),
                erc20_address: Address::new(erc20_address),
                dest: exit_params.receiver_account_id.to_string(),
                amount: exit_params.amount,
                msg: msg.to_string(),
            }),
        ),
```
