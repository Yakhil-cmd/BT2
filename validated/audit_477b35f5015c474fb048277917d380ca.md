Let me trace the exact code path for this exploit question.

Let me read the key callback function and the refund logic in detail.

Let me check the `refund_call_args` function and the `error_refund` feature flag to understand the full scope of the refund mechanism.

I now have all the information needed to make a determination. Let me trace the complete path:

**Step 1 — EVM entry**: User calls the exit precompile with `Message::UnwrapWnear` on the wNEAR ERC-20 address. The EVM burns the user's wNEAR tokens and emits a promise log.

**Step 2 — Promise construction** (`native.rs:587-608`): `exit_erc20_token_to_near` sets `transfer_near_args = Some(TransferNearArgs { target_account_id, amount })` and method = `"near_withdraw"`. A `PromiseWithCallbackArgs` is built: base = `near_withdraw` on wNEAR contract, callback = `exit_to_near_precompile_callback` on the engine.

**Step 3 — Callback** (`connector.rs:214-228`): When `near_withdraw` returns `PromiseResult::Successful`, the callback dispatches a `Transfer` batch to `args.target_account_id` via `promise_create_batch` + `promise_return`. **No failure callback is attached to this Transfer batch.**

**Step 4 — Transfer failure**: In NEAR Protocol, a `Transfer` action to a non-existent named account fails. The NEAR is refunded to the predecessor (the engine account). There is no further callback to detect this failure.

**Step 5 — No EVM restoration**: The `refund_on_error` path (`connector.rs:231-239`) only triggers when `near_withdraw` itself fails (the `else if` branch). It is structurally unreachable when `near_withdraw` succeeds but the subsequent Transfer fails. The user's wNEAR was already burned in the EVM; there is no mechanism to re-mint it.

The `error_refund` feature flag (`native.rs:450-453`) only controls whether the `refund` field is populated for the `near_withdraw` failure case — it has no bearing on the Transfer failure case.

`promise_attach_batch_callback` is used in `xcc.rs` but is never called after `promise_create_batch` in `exit_to_near_precompile_callback`.

---

### Title
Missing Transfer-failure callback in wNEAR unwrap path leaves NEAR permanently stranded in engine account — (`engine/src/contract_methods/connector.rs`)

### Summary
When a user unwraps wNEAR via the `exit_to_near` precompile (`Message::UnwrapWnear`), the engine burns the ERC-20 balance, calls `near_withdraw` on the wNEAR contract, and — on success — dispatches a bare `Transfer` batch to the user-supplied `target_account_id`. No failure callback is attached to that Transfer. If the Transfer fails (target account non-existent or deleted), NEAR Protocol refunds the NEAR to the engine account, but the engine has no code path to detect this and restore the user's EVM balance. The user's wNEAR is gone and the NEAR is stranded.

### Finding Description
The two-step wNEAR unwrap flow is:

1. `near_withdraw` on the wNEAR NEP-141 contract (burns wNEAR, credits NEAR to the engine account).
2. `exit_to_near_precompile_callback` dispatches a `Transfer` batch to `target_account_id`.

The callback code at `connector.rs:214-228`:

```rust
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    if let Some(args) = args.transfer_near {
        let action = PromiseAction::Transfer { amount: Yocto::new(args.amount) };
        let promise = PromiseBatchAction {
            target_account_id: args.target_account_id,
            actions: vec![action],
        };
        let promise_id = handler.promise_create_batch(&promise);
        handler.promise_return(promise_id);   // ← no batch callback attached
    }
    None
} else if let Some(args) = args.refund {   // ← only reached when near_withdraw FAILED
    ...
```

`promise_create_batch` schedules the Transfer and `promise_return` propagates its result, but there is no `promise_attach_batch_callback` call to handle a Transfer failure. The `refund` branch is only entered when `near_withdraw` itself fails; it is structurally unreachable in the success path.

In NEAR Protocol, a `Transfer` action to a non-existent named account fails and the NEAR is returned to the predecessor (the engine account). The engine has no subsequent receipt to detect this and call `refund_on_error`.

### Impact Explanation
The user's wNEAR ERC-20 balance is burned at EVM execution time. If the Transfer fails, the NEAR sits in the engine account with no on-chain mechanism to credit it back. The user cannot access the funds without out-of-band admin intervention. This constitutes **temporary freezing of funds** (High severity per the allowed impact scope).

### Likelihood Explanation
The trigger condition — a Transfer to a non-existent NEAR account — is reachable through normal user interaction:
- A user who mistypes the target account ID (e.g., `alce.near` instead of `alice.near`) will hit this path.
- A user whose target account is deleted between EVM submission and callback execution (possible within the same or adjacent NEAR blocks) will hit this path.
- No admin compromise or external oracle is required; the attacker only needs to control the target account and delete it in the window between the EVM call and the callback receipt.

### Recommendation
Attach a second-level callback to the Transfer batch using `promise_attach_batch_callback`. In that callback, check the Transfer result; if it failed, call `refund_on_error` (or an equivalent re-mint path) to restore the user's EVM balance. The `ExitToNearPrecompileCallbackArgs` struct already carries the `refund: Option<RefundCallArgs>` field — a parallel `transfer_near_refund` field (or reuse of `refund`) can carry the information needed to re-mint wNEAR to the original sender if the Transfer fails.

### Proof of Concept
1. Deploy Aurora locally with a wNEAR address configured via `factory_set_wnear_address`.
2. Mint wNEAR ERC-20 tokens to a test EVM address.
3. Submit an EVM transaction calling the exit precompile with `Message::UnwrapWnear` and `target_account_id = "nonexistent.near"` (an account that does not exist on the local NEAR sandbox).
4. Allow the `near_withdraw` receipt to execute (it will succeed — wNEAR is burned, NEAR credited to engine).
5. Allow the `exit_to_near_precompile_callback` receipt to execute — it dispatches a Transfer to `nonexistent.near`.
6. Allow the Transfer receipt to execute — it fails; NEAR is refunded to the engine account.
7. Assert: the user's wNEAR ERC-20 balance is 0 (burned, not restored).
8. Assert: the engine account's NEAR balance increased by the unwrapped amount (NEAR is stranded there).
9. Assert: `nonexistent.near` received nothing.

The test confirms that a successful `near_withdraw` followed by a failed Transfer leaves the user with neither wNEAR nor NEAR. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** engine-types/src/parameters/connector.rs (L124-134)
```rust
pub struct TransferNearArgs {
    pub target_account_id: AccountId,
    pub amount: u128,
}

/// Arguments for callback used in the `exit_to_near` precompile.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq, Default)]
pub struct ExitToNearPrecompileCallbackArgs {
    pub refund: Option<RefundCallArgs>,
    pub transfer_near: Option<TransferNearArgs>,
}
```

**File:** engine/src/engine.rs (L1176-1225)
```rust
pub fn refund_on_error<I: IO + Copy, E: Env, P: PromiseHandler>(
    io: I,
    env: &E,
    state: EngineState,
    args: &RefundCallArgs,
    handler: &mut P,
) -> EngineResult<SubmitResult> {
    let current_account_id = env.current_account_id();
    if let Some(erc20_address) = args.erc20_address {
        // ERC-20 exit; re-mint burned tokens
        let erc20_admin_address = current_address(&current_account_id);
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, erc20_admin_address, current_account_id, io, env);

        let refund_address = args.recipient_address;
        let amount = U256::from_big_endian(&args.amount);
        let input = setup_refund_on_error_input(amount, refund_address);

        engine.call(
            &erc20_admin_address,
            &erc20_address,
            Wei::zero(),
            input,
            u64::MAX,
            Vec::new(),
            Vec::new(),
            handler,
        )
    } else {
        // ETH exit; transfer ETH back from precompile address
        let exit_address = exit_to_near::ADDRESS;
        let mut engine: Engine<_, _> =
            Engine::new_with_state(state, exit_address, current_account_id, io, env);
        let refund_address = args.recipient_address;
        let amount = Wei::new(U256::from_big_endian(&args.amount));
        engine.call(
            &exit_address,
            &refund_address,
            amount,
            Vec::new(),
            u64::MAX,
            vec![
                (exit_address.raw(), Vec::new()),
                (refund_address.raw(), Vec::new()),
            ],
            Vec::new(),
            handler,
        )
    }
}
```
