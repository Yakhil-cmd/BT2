### Title
Partial NEP-141 Refund from `ft_transfer_call` Omni Path Permanently Freezes Funds — (`engine-precompiles/src/native.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

When an EVM user exits an ERC-20 token to NEAR via the Omni path (`withdrawToNear` with a `:msg` suffix), the engine burns the full ERC-20 amount and issues a `ft_transfer_call` on the NEP-141 contract. If the receiving NEAR contract's `ft_on_transfer` returns a non-zero `unused_amount`, the NEP-141 standard refunds those tokens back to Aurora's NEP-141 balance — but the `exit_to_near_precompile_callback` treats the promise as a success and performs no ERC-20 re-mint. The `unused_amount` of NEP-141 tokens is permanently stranded in Aurora's balance with no corresponding ERC-20 representation and no user-accessible recovery path.

---

### Finding Description

**Step 1 — Entry point (public EVM call).**
Any EVM user calls `withdrawToNear` on an ERC-20 contract with a recipient string of the form `receiver.near:<omni_json_msg>`. The ERC-20 contract burns the full `amount` and calls the `ExitToNear` precompile.

**Step 2 — `exit_erc20_token_to_near`, Omni branch.** [1](#0-0) 

The Omni branch sets `transfer_near_args = None` and `method = "ft_transfer_call"`. No `TransferNearArgs` is produced.

**Step 3 — Callback construction.** [2](#0-1) 

- **Without `error_refund` feature:** `refund = None`, `transfer_near = None` → `callback_args == default()` → the promise is scheduled as `PromiseArgs::Create` with **no callback at all**.
- **With `error_refund` feature:** `refund = Some(RefundCallArgs { erc20_address: Some(...), amount: full_amount, ... })`, `transfer_near = None` → a callback is scheduled. [3](#0-2) 

**Step 4 — `exit_to_near_precompile_callback` logic.** [4](#0-3) 

The callback has two branches:
- `PromiseResult::Successful(_)` → checks `transfer_near` (which is `None` for the Omni ERC-20 path) → **does nothing, returns `None`**.
- `else if Some(args) = args.refund` → triggers `refund_on_error` (ERC-20 re-mint) — but this branch is only reached when the promise **fails**.

**Step 5 — NEP-141 `ft_transfer_call` partial-refund semantics.**
Per the NEP-141 standard, `ft_transfer_call` calls `ft_on_transfer` on the receiver. If the receiver returns `unused_amount > 0`, the NEP-141 contract's internal `ft_resolve_transfer` refunds those tokens back to Aurora's NEP-141 balance. Critically, the `ft_transfer_call` promise result is **`Successful`** (not failed) even when a partial refund occurs. The callback ignores the promise result payload entirely (`Successful(_)` — the `_` discards the returned net-transferred amount).

**The invariant break:**
- ERC-20 burned: `full_amount`
- NEP-141 net transferred out: `full_amount - unused_amount`
- Aurora's NEP-141 balance increase: `+unused_amount`
- ERC-20 re-minted: `0`

The `unused_amount` of NEP-141 tokens is stuck in Aurora's NEP-141 balance with no ERC-20 counterpart and no user-accessible recovery function in the engine.

---

### Impact Explanation

**High — Permanent freezing of funds.**

The `unused_amount` of NEP-141 tokens accumulates in Aurora's NEP-141 balance. There is no on-chain user path to recover them: the normal bridge exit requires burning ERC-20 (which no longer exists for the returned portion), and the normal bridge deposit would mint new ERC-20 against a fresh NEP-141 transfer (not the stuck balance). An operator could theoretically recover them via a direct NEP-141 `ft_transfer` call, making this "temporary" in the best case, but from the user's perspective the funds are unrecoverable without privileged intervention.

---

### Likelihood Explanation

**Medium.** The attacker must:
1. Hold ERC-20 tokens on Aurora (normal user activity).
2. Deploy or use a NEAR contract whose `ft_on_transfer` returns a non-zero `unused_amount` — trivially achievable with a minimal NEAR contract.
3. Call `withdrawToNear` with an Omni message pointing to that contract.

No admin compromise, no key leak, and no external oracle is required. The path is fully reachable through the public EVM interface.

---

### Recommendation

1. **Read the `ft_transfer_call` promise result in the callback.** The NEP-141 standard specifies that `ft_transfer_call` returns the net transferred amount (i.e., `amount - unused_amount`). Parse `PromiseResult::Successful(bytes)` to extract the net amount and compute `unused_amount = original_amount - net_amount`.

2. **Re-mint ERC-20 for the `unused_amount` on partial success.** If `unused_amount > 0`, call `refund_on_error` (or an equivalent mint path) for the `unused_amount` back to the original sender's ERC-20 address, mirroring the existing full-failure refund logic.

3. **Ensure the `error_refund` feature is always enabled in production** or restructure the callback so it is always scheduled for `ft_transfer_call` exits regardless of feature flags.

---

### Proof of Concept

```
1. Deploy a NEAR contract `mock_receiver.near` whose `ft_on_transfer` always returns
   half the received amount as `unused_amount`.

2. On Aurora, hold 1000 units of ERC-20 token backed by `token.near` NEP-141.

3. Call withdrawToNear with:
     recipient = "mock_receiver.near:<omni_json>"
     amount    = 1000

4. Observe:
   - ERC-20 balance of caller: decreases by 1000 (fully burned)
   - NEP-141 balance of mock_receiver.near: increases by 500
   - NEP-141 balance of aurora: increases by 500 (refunded by ft_resolve_transfer)
   - ERC-20 re-minted to caller: 0

5. Assert: Aurora's NEP-141 balance holds 500 tokens with no corresponding ERC-20,
   and the caller has permanently lost 500 units of value with no recovery path.
```

### Citations

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
