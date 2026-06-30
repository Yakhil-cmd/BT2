### Title
Unhandled Partial NEP-141 Token Returns in `ExitToNear` Omni `ft_transfer_call` Path Cause Permanent Loss of User ERC-20 Tokens — (File: `engine-precompiles/src/native.rs`)

---

### Summary

When a user exits ERC-20 tokens via the `ExitToNear` precompile using the Omni `ft_transfer_call` path (e.g., to interact with a DEX on NEAR), the ERC-20 tokens are burned from the user's EVM balance before the asynchronous NEAR-side transfer completes. If the receiver's `ft_on_transfer` returns any tokens as "unused" — for example, because a sandwich attack moved the DEX price — those NEP-141 tokens are silently returned to Aurora's balance via `ft_resolve_transfer`, while the user's ERC-20 tokens remain permanently burned. No minimum-amount-out check exists anywhere in this path to protect users.

---

### Finding Description

**Root cause — `engine-precompiles/src/native.rs`**

The `ExitToNear` precompile's `run()` method dispatches to `exit_erc20_token_to_near()` for ERC-20 exits. When the user supplies an Omni message (any string after `:` that is not `unwrap`), the method selects `ft_transfer_call` as the NEAR method and sets `transfer_near_args = None`: [1](#0-0) 

The callback args are then assembled: [2](#0-1) 

For the Omni ERC-20 path:
- `transfer_near` = `None`
- `refund` = `Some(...)` **only** when the `error_refund` Cargo feature is compiled in; otherwise `None`

The promise is created **without a callback** when both fields are `None` (i.e., when `error_refund` is disabled):

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback at all
} else {
    PromiseArgs::Callback(...)
};
```

Even when `error_refund` **is** enabled, the `exit_to_near_precompile_callback` only handles **complete failure** of the promise: [3](#0-2) 

The branch `if let Some(PromiseResult::Successful(_))` does nothing for the Omni path (because `transfer_near` is `None`). The `else if` branch only fires on failure. **There is no branch that handles a successful `ft_transfer_call` where the receiver returned a non-zero unused amount.**

**What happens to the returned tokens**

In the NEP-141 standard, `ft_transfer_call` calls `ft_on_transfer` on the receiver, which returns `unused_amount`. The NEP-141 contract's `ft_resolve_transfer` then transfers `unused_amount` back to Aurora's NEP-141 balance. Aurora's engine is never notified of this return; it has no `ft_on_transfer` hook for this path. The user's ERC-20 tokens were already burned at EVM execution time and are gone.

**No minimum-amount-out parameter exists**

The `ExitToNearParams::Erc20TokenParams` struct carries only `amount`, `receiver_account_id`, and `message` — no `min_amount_out` field: [4](#0-3) 

The `FtOnTransferArgs` and `FtTransferCallArgs` parameter types similarly carry no slippage bound: [5](#0-4) 

---

### Impact Explanation

**Impact: Critical — Direct theft of user funds**

A user who exits ERC-20 tokens via the Omni path to a DEX/AMM on NEAR has their ERC-20 tokens burned atomically at EVM execution time. If the receiver's `ft_on_transfer` returns any portion of the NEP-141 tokens as "unused" (partial fill, price-impact rejection, or sandwich-induced slippage), those NEP-141 tokens silently accumulate in Aurora's NEP-141 balance. The user's ERC-20 tokens are permanently destroyed with no corresponding output. The discrepancy inflates Aurora's NEP-141 reserve relative to the outstanding ERC-20 supply, effectively transferring value from the user to the protocol's general pool.

---

### Likelihood Explanation

**Likelihood: Medium**

- The Omni `ft_transfer_call` path is the intended mechanism for EVM users to interact with NEAR DeFi protocols (DEXes, lending markets, etc.) from within the EVM.
- NEAR DEXes such as Ref Finance accept `ft_transfer_call` for swaps and can return tokens when liquidity is insufficient or price bounds are exceeded.
- NEAR's transaction ordering, while not as trivially front-runnable as Ethereum's mempool, is observable and can be exploited by validators or sophisticated actors.
- Even without a deliberate sandwich attack, any partial fill by the receiver silently burns the user's ERC-20 tokens with no recourse.

---

### Recommendation

1. **Add a `min_amount_out` field** to `Erc20TokenParams` (and the corresponding calldata encoding) so users can specify the minimum NEP-141 tokens that must be consumed by the receiver.
2. **Handle partial returns in the callback**: extend `exit_to_near_precompile_callback` to inspect the `ft_resolve_transfer` result (available via `promise_result`) and re-mint ERC-20 tokens equal to the returned unused amount back to the original sender.
3. **Ensure `error_refund` is always compiled in** for production builds, or make the refund path unconditional, so that at minimum complete failures are always refunded.

---

### Proof of Concept

**Setup**: User holds 1 000 units of an ERC-20 token on Aurora (backed 1:1 by NEP-141 tokens held by Aurora).

**Attack**:
1. Attacker observes the user's pending `withdrawToNear` Omni call targeting a NEAR DEX.
2. Attacker front-runs: executes a large swap on the DEX, moving the price adversely.
3. User's EVM transaction executes:
   - `exit_erc20_token_to_near` is called; 1 000 ERC-20 tokens are burned from the user's EVM balance (irreversible).
   - A `ft_transfer_call(receiver=DEX, amount=1000, msg=<swap_params>)` promise is scheduled.
4. NEAR runtime executes the promise:
   - NEP-141 transfers 1 000 tokens to the DEX.
   - DEX's `ft_on_transfer` executes at the manipulated price; only 400 tokens are consumed; 600 are returned as `unused`.
   - `ft_resolve_transfer` sends 600 NEP-141 tokens back to Aurora's balance.
5. No callback fires to re-mint 600 ERC-20 tokens for the user.
6. Attacker back-runs: reverses their position, profiting from the price movement.

**Result**: User permanently loses 600 ERC-20 tokens. Aurora's NEP-141 balance is 600 tokens higher than the outstanding ERC-20 supply. The attacker profits from the price manipulation.

The vulnerable code path is: [1](#0-0) [6](#0-5) [7](#0-6)

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

**File:** engine-precompiles/src/native.rs (L610-623)
```rust
        // In this flow, we're just forwarding the `msg` to the `ft_transfer_call` transaction.
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

**File:** engine-precompiles/src/native.rs (L690-697)
```rust
#[cfg_attr(test, derive(Debug, PartialEq))]
struct Erc20TokenParams<'a> {
    #[cfg(feature = "error_refund")]
    refund_address: Address,
    receiver_account_id: AccountId,
    amount: U256,
    message: Option<Message<'a>>,
}
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

**File:** engine-types/src/parameters/connector.rs (L136-143)
```rust
/// Arguments for the `ft_transfer_call` transaction.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Deserialize, Serialize, PartialEq, Eq)]
pub struct FtTransferCallArgs {
    pub receiver_id: AccountId,
    pub amount: NEP141Wei,
    pub memo: Option<String>,
    pub msg: String,
}
```
