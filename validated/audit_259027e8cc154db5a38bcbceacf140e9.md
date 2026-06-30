Let me look at the `refund_call_args` function and the `error_refund` feature to understand the full refund scope, and also check NEAR protocol behavior for transfers to non-existent accounts.

Now I have a complete picture of the code. Let me trace the full promise chain and assess the vulnerability.

---

### Title
Missing Callback on `transfer_near` Batch Promise in wNEAR Unwrap Flow Causes Permanent Fund Loss - (`engine/src/contract_methods/connector.rs`)

### Summary

When a user exits wNEAR ERC-20 via the `ExitToNear` precompile with the `:unwrap` suffix, the two-step promise chain is: `near_withdraw` → `exit_to_near_precompile_callback` → `transfer_near` (batch). The `transfer_near` batch promise is created with **no further callback**. If the NEAR `Transfer` action fails (e.g., because the target named account does not exist on NEAR), the NEAR is refunded to the aurora engine account, but the user's wNEAR ERC-20 tokens were already burned with no on-chain mechanism to re-mint them.

### Finding Description

**Step 1 — Precompile constructs the promise chain.**

In `exit_erc20_token_to_near` (`engine-precompiles/src/native.rs`), when the caller is the wNEAR ERC-20 contract and the message is `UnwrapWnear`, the code builds:
- Base promise: `near_withdraw` on the wNEAR NEP-141 account
- `transfer_near_args`: `Some(TransferNearArgs { target_account_id: receiver_account_id, amount })`
- Callback: `exit_to_near_precompile_callback` [1](#0-0) 

The `ExitToNearPrecompileCallbackArgs` carries both a `refund` (for `near_withdraw` failure, gated by `error_refund` feature) and `transfer_near` (for the success path): [2](#0-1) 

**Step 2 — Callback handles `near_withdraw` result.**

In `exit_to_near_precompile_callback` (`engine/src/contract_methods/connector.rs`), when `promise_result(0)` is `Successful`, the code creates a `PromiseBatchAction::Transfer` targeting `args.target_account_id` and calls `promise_return`. **No further callback is attached to this batch promise.** [3](#0-2) 

The `else if` branch (lines 231–239) handles `near_withdraw` failure by calling `refund_on_error` to re-mint the burned ERC-20 tokens. But this branch is **never reached** when `near_withdraw` succeeds — it only covers the base promise failure, not the subsequent `transfer_near` failure. [4](#0-3) 

**Step 3 — `transfer_near` fails silently.**

In NEAR protocol, a `Transfer` action to a non-existent **named** account (e.g., `nonexistent.near`) fails with `AccountDoesNotExist`. The NEAR is refunded to the predecessor (the aurora engine account), but:
- The user's wNEAR ERC-20 tokens were burned in the EVM transaction (irreversible at this point)
- There is no third promise or callback to detect the `transfer_near` failure
- There is no on-chain mechanism to re-mint the wNEAR ERC-20 tokens to the user

The `refund_on_error` path (`engine/src/engine.rs`) re-mints burned ERC-20 tokens, but it is only reachable from the `else if` branch of `exit_to_near_precompile_callback`, which requires `near_withdraw` to have failed: [5](#0-4) 

**The `error_refund` feature does not help here.** Even when enabled, `refund_call_args` populates the `refund` field for the `near_withdraw` failure case only. There is no analogous refund argument for the `transfer_near` failure case. [6](#0-5) 

The existing test `test_exit_to_near_refund` confirms the refund mechanism works for `ft_transfer` failures (regular ERC-20 exit), but there is no analogous test for `transfer_near` failure in the wNEAR unwrap path: [7](#0-6) 

### Impact Explanation

A user who supplies a syntactically valid but non-existent named NEAR account as the receiver in the wNEAR unwrap exit flow will:
1. Have their wNEAR ERC-20 tokens permanently burned on Aurora
2. Have the unwrapped NEAR credited to the aurora engine account (not to them)
3. Have no on-chain path to recover the NEAR or get the wNEAR ERC-20 re-minted

The NEAR is not destroyed — it accumulates in aurora's account — but the user has no on-chain recovery mechanism. This constitutes **High. Temporary freezing of funds** (recovery would require off-chain admin intervention).

### Likelihood Explanation

The preconditions are:
- wNEAR address must be set (normal production state)
- User holds wNEAR ERC-20 (normal user state)
- User supplies a syntactically valid but non-existent named NEAR account

This can occur through user error (typo in account ID) or deliberate self-infliction. The attacker cannot force this on another user without controlling their EVM transaction. Likelihood is **medium** — user error with named account IDs is realistic, and the protocol provides no safety net.

### Recommendation

Attach a third callback to the `transfer_near` batch promise in `exit_to_near_precompile_callback`. This callback should check the result of the `Transfer` action and, if it failed, call `refund_on_error` to re-mint the burned wNEAR ERC-20 tokens to the original sender. The `ExitToNearPrecompileCallbackArgs` already carries the `refund` field with the necessary `erc20_address` and `amount`; a second-level callback can reuse this data.

Alternatively, validate that the target NEAR account exists before proceeding with `near_withdraw` (though this is harder to do atomically in the NEAR promise model).

### Proof of Concept

1. Deploy Aurora with wNEAR address set.
2. Bridge wNEAR to Aurora ERC-20; user holds `N` wNEAR ERC-20.
3. User calls `withdrawToNear("doesnotexist12345.near:unwrap", N)` on the wNEAR ERC-20 contract.
4. EVM executes: wNEAR ERC-20 burns `N` tokens, ExitToNear precompile fires.
5. `near_withdraw(N)` promise executes successfully; NEAR credited to aurora engine.
6. `exit_to_near_precompile_callback` fires; sees `Successful`; creates `PromiseBatchAction::Transfer { target: "doesnotexist12345.near", amount: N }`.
7. `transfer_near` fails (`AccountDoesNotExist`); NEAR refunded to aurora engine account.
8. No further callback fires.
9. Assert: user's wNEAR ERC-20 balance = 0 (burned, not restored). Aurora engine NEAR balance increased by `N`. User has no on-chain recovery path.

The invariant is violated: `near_withdraw` succeeded but `transfer_near` failed, and the unwrapped NEAR is not returned to the user.

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

**File:** engine-precompiles/src/native.rs (L585-609)
```rust
    let (nep141_account_id, args, method, transfer_near_args, event) = match exit_params.message {
        // wNEAR address should be set via the `factory_set_wnear_address` transaction first.
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
        }
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

**File:** engine/src/engine.rs (L1176-1204)
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
```

**File:** engine-tests/src/tests/erc20_connector.rs (L623-665)
```rust
    #[tokio::test]
    async fn test_exit_to_near_refund() {
        // Deploy Aurora; deploy NEP-141; bridge NEP-141 to ERC-20 on Aurora
        let TestExitToNearContext {
            ft_owner,
            ft_owner_address,
            nep_141,
            erc20,
            aurora,
            ..
        } = test_exit_to_near_common().await.unwrap();

        // Call exit on ERC-20; ft_transfer promise fails; expect refund on Aurora;
        exit_to_near(
            &ft_owner,
            // The ft_transfer will fail because this account is not registered with the NEP-141
            "unregistered.near",
            FT_EXIT_AMOUNT,
            &erc20,
            &aurora,
        )
        .await
        .unwrap();

        assert_eq!(
            nep_141_balance_of(&nep_141, &ft_owner.id()).await,
            FT_TOTAL_SUPPLY - FT_TRANSFER_AMOUNT
        );
        assert_eq!(
            nep_141_balance_of(&nep_141, &aurora.id()).await,
            FT_TRANSFER_AMOUNT
        );

        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();

        assert_eq!(
            erc20_balance(&erc20, ft_owner_address, &aurora).await,
            balance
        );
```
