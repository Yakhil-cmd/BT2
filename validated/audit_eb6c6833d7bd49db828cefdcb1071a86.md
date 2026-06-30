### Title
Missing Failure Callback on NEAR Transfer After Successful `near_withdraw` Permanently Freezes Unwrapped NEAR — (`engine-precompiles/src/native.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

When a wNEAR ERC-20 holder exits via the `:unwrap` path, the engine schedules `near_withdraw` followed by a callback (`exit_to_near_precompile_callback`) that issues a bare `Transfer` batch action to the user-supplied `target_account_id`. If that account does not exist on NEAR, the `Transfer` action fails silently — there is no further callback to detect or recover from this failure. The wNEAR ERC-20 tokens are already burned, and the unwrapped NEAR is permanently stranded in the Aurora engine's account with no on-chain recovery path.

---

### Finding Description

**Step 1 — ERC-20 burn and precompile invocation**

The wNEAR ERC-20 contract burns the caller's tokens and calls the `ExitToNear` precompile. Inside `exit_erc20_token_to_near`, when the `:unwrap` suffix is detected and the caller is the registered wNEAR ERC-20 address, the engine builds:

- Base promise: `near_withdraw` on the wNEAR NEP-141 contract
- Callback: `exit_to_near_precompile_callback` carrying `TransferNearArgs { target_account_id, amount }` [1](#0-0) 

The `target_account_id` is taken directly from user-supplied input. `parse_recipient` validates only syntactic correctness (`.parse()` on the string), not on-chain existence. [2](#0-1) 

**Step 2 — `near_withdraw` succeeds**

The wNEAR NEP-141 contract burns the wrapped tokens and credits the Aurora engine's NEAR account with the unwrapped amount. Promise result 0 is `Successful`.

**Step 3 — Callback issues an unguarded `Transfer` batch action**

`exit_to_near_precompile_callback` sees a successful promise result and creates a `PromiseBatchAction` with a single `Transfer` action targeting `args.target_account_id`: [3](#0-2) 

`handler.promise_create_batch` is called and `handler.promise_return` is called on the resulting `PromiseId`. **No callback is attached to this batch promise.** There is no `promise_attach_batch_callback` or `promise_attach_callback` call after line 226.

**Step 4 — Transfer fails, NEAR is stuck**

In NEAR Protocol, a `Transfer` action to a non-existent named account (e.g., `nonexistent.near`) fails at the runtime level. Because no callback was registered on the transfer promise, the failure is unobservable to the engine. The N yoctoNEAR credited to the engine's account in Step 2 remains there permanently.

**Step 5 — The `error_refund` path does not cover this case**

The `else if let Some(args) = args.refund` branch at line 231 is only reachable when `handler.promise_result(0)` is **not** `Successful` — i.e., when `near_withdraw` itself fails. It is structurally unreachable in the scenario where `near_withdraw` succeeds but the subsequent transfer fails. [4](#0-3) 

---

### Impact Explanation

- The user's wNEAR ERC-20 balance is zero (burned before the precompile ran).
- The equivalent NEAR is permanently locked in the Aurora engine's account.
- There is no admin function, no recovery promise, and no re-entry point to reclaim the stuck NEAR for the affected user.
- This satisfies **Critical: Permanent freezing of funds**.

---

### Likelihood Explanation

The trigger requires only that a user (or a contract acting on their behalf) supply a syntactically valid but non-existent named NEAR account as the `:unwrap` target. This can happen:

- Accidentally (typo in account name, account deleted after the call was constructed).
- Intentionally by any wNEAR ERC-20 holder — no special privilege is required.

The wNEAR ERC-20 exit path is a standard, publicly accessible production flow. The `parse_recipient` guard provides no protection against non-existent accounts. [2](#0-1) 

---

### Recommendation

After `handler.promise_create_batch` for the NEAR transfer, attach a second callback (e.g., `near_transfer_callback`) using `handler.promise_attach_batch_callback` or `handler.promise_attach_callback`. That callback should:

1. Check `handler.promise_result(0)`.
2. On failure, re-mint the equivalent wNEAR ERC-20 tokens to the original sender (mirroring the existing `refund_on_error` pattern used for the `near_withdraw` failure case).

Alternatively, validate that `target_account_id` exists on NEAR before proceeding (e.g., via a preflight view call), though the callback approach is more robust. [5](#0-4) 

---

### Proof of Concept

```
1. Deploy Aurora engine locally (NEAR sandbox).
2. Bridge wNEAR: call ft_transfer_call on the wNEAR NEP-141 contract to mint
   wNEAR ERC-20 tokens to address A on Aurora.
3. From address A, call the wNEAR ERC-20 contract's `withdraw(amount,
   "definitely-does-not-exist.near:unwrap")`.
   - The ERC-20 contract burns `amount` wNEAR ERC-20 tokens from A.
   - The ExitToNear precompile schedules:
       near_withdraw({"amount":"<N>"}) → exit_to_near_precompile_callback
4. Observe near_withdraw receipt: succeeds; Aurora engine NEAR balance += N.
5. Observe exit_to_near_precompile_callback receipt: succeeds; schedules
   Transfer(N) → "definitely-does-not-exist.near".
6. Observe Transfer receipt: FAILS (account does not exist).
   No further receipts are generated.
7. Assert:
   - wNEAR ERC-20 balance of A == 0  (burned in step 3)
   - Aurora engine NEAR balance increased by N (never transferred out)
   - "definitely-does-not-exist.near" does not exist and received nothing
   - No refund or recovery receipt was ever scheduled
```

### Citations

**File:** engine-precompiles/src/native.rs (L359-378)
```rust
fn parse_recipient(recipient: &[u8]) -> Result<Recipient<'_>, ExitError> {
    let recipient = str::from_utf8(recipient)
        .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?;
    let (receiver_account_id, message) = recipient.split_once(':').map_or_else(
        || (recipient, None),
        |(recipient, msg)| {
            if msg == UNWRAP_WNEAR_MSG {
                (recipient, Some(Message::UnwrapWnear))
            } else {
                (recipient, Some(Message::Omni(msg)))
            }
        },
    );

    Ok(Recipient {
        receiver_account_id: receiver_account_id
            .parse()
            .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECEIVER_ACCOUNT_ID")))?,
        message,
    })
```

**File:** engine-precompiles/src/native.rs (L587-608)
```rust
        Some(Message::UnwrapWnear) if erc20_address == get_wnear_address(io).raw() =>
        // The flow is following here:
        // 1. We call `near_withdraw` on wNEAR account id on `aurora` behalf.
        // In such way we unwrap wNEAR to NEAR.
        // 2. After that, we call callback `exit_to_near_precompile_callback` on the `aurora`
        // in which make transfer of unwrapped NEAR to the `target_account_id`.
        {
            (
                nep141_account_id,
                format!(r#"{{"amount":"{}"}}"#, exit_params.amount.as_u128()),
                "near_withdraw",
                Some(TransferNearArgs {
                    target_account_id: exit_params.receiver_account_id.clone(),
                    amount: exit_params.amount.as_u128(),
                }),
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
```

**File:** engine/src/contract_methods/connector.rs (L214-230)
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
```

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
