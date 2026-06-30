### Title
Permanent Fund Loss When `ExitToNear` Promise Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

---

### Summary

When a user bridges ERC-20 tokens or ETH from Aurora (EVM) to NEAR via the `ExitToNear` precompile, the EVM-side funds are irrevocably burned/deducted **before** the NEAR-side `ft_transfer` promise executes. If that promise fails (e.g., recipient not registered with the NEP-141 contract, connector paused, etc.) and the contract is compiled **without** the `error_refund` Cargo feature (the default production build), there is no callback, no refund, and no recovery path. User funds are permanently destroyed.

---

### Finding Description

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) handles two exit paths:

1. **ETH (base token)**: deducts ETH from the caller's EVM balance, then schedules a `ft_transfer` promise on the eth-connector NEP-141 contract.
2. **ERC-20 token**: the ERC-20 contract burns the tokens, then schedules a `ft_transfer` promise on the corresponding NEP-141 contract.

The promise construction at lines 462–483 conditionally attaches a failure-handling callback only when `callback_args != ExitToNearPrecompileCallbackArgs::default()`: [1](#0-0) 

The `refund` field of `callback_args` is populated **only** when the `error_refund` Cargo feature is compiled in: [2](#0-1) 

Without `error_refund`, `refund` is always `None`, `transfer_near` is `None` for the standard ERC-20 path, so `callback_args` equals `default()`, and the code takes the `PromiseArgs::Create(transfer_promise)` branch — **no callback is attached**: [3](#0-2) 

The `error_refund` feature is an **opt-in** compile-time flag, not enabled in the standard production build. The `Makefile.toml` standard build task uses only the `contract` feature: [4](#0-3) 

The `error_refund` feature is a separate, non-default task: [5](#0-4) 

The `exit_to_near_precompile_callback` function — which would perform the refund — is only ever invoked when the callback was attached (i.e., only with `error_refund` enabled): [6](#0-5) 

The `refund_on_error` function in `engine/src/engine.rs` re-mints burned ERC-20 tokens or transfers ETH back from the precompile address, but it is unreachable without the callback: [7](#0-6) 

---

### Impact Explanation

**Critical — Permanent freezing/loss of funds.**

Without `error_refund`, when `ft_transfer` fails:
- ERC-20 tokens are permanently burned in the EVM with no re-mint.
- ETH is permanently deducted from the user's EVM balance with no refund.

There is no cancel mechanism, no expiry, and no way for the user to recover funds. The test suite explicitly documents this behavior: [8](#0-7) [9](#0-8) 

---

### Likelihood Explanation

**Medium.** The `ft_transfer` promise can fail under realistic, non-adversarial conditions:

- The recipient NEAR account is not registered with the NEP-141 contract (a common user error).
- The eth-connector or NEP-141 contract is paused by its admin.
- The Aurora engine's NEP-141 balance is insufficient (e.g., drained by another path).
- The target account does not exist on NEAR.

Any unprivileged EVM user who calls `ExitToNear` (directly or via an ERC-20 `withdrawToNear` call) with a failing recipient triggers this path. No special privilege is required.

---

### Recommendation

Enable the `error_refund` feature in the production build, or unconditionally attach the failure-handling callback in `ExitToNear` so that a failed `ft_transfer` always triggers `exit_to_near_precompile_callback` and refunds the user's EVM-side funds. The refund logic already exists in `refund_on_error`; it simply needs to be reachable by default.

---

### Proof of Concept

1. User holds ERC-20 tokens on Aurora (bridged from a NEP-141).
2. User calls `withdrawToNear("unregistered.near", amount)` on the ERC-20 contract.
3. ERC-20 contract burns `amount` tokens and calls the `ExitToNear` precompile.
4. Precompile schedules `ft_transfer` to `"unregistered.near"` on the NEP-141 contract.
5. `ft_transfer` fails because `"unregistered.near"` is not registered.
6. Without `error_refund`, no callback fires. Tokens are gone from the EVM and never arrive on NEAR.
7. User's ERC-20 balance is zero; NEP-141 balance of `"unregistered.near"` is zero. Funds are permanently destroyed. [10](#0-9) [11](#0-10)

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

**File:** Makefile.toml (L104-117)
```text
[tasks.clippy-contract]
extend = "clippy-base"
args = [
    "clippy",
    "--workspace",
    "--all-targets",
    "--features",
    "contract",
    "--",
    "-D",
    "warnings",
    "-D",
    "clippy::as_conversions",
]
```

**File:** Makefile.toml (L119-132)
```text
[tasks.clippy-contract-refund]
extend = "clippy-base"
args = [
    "clippy",
    "--workspace",
    "--all-targets",
    "--features",
    "contract,error_refund",
    "--",
    "-D",
    "warnings",
    "-D",
    "clippy::as_conversions",
]
```

**File:** engine/src/contract_methods/connector.rs (L195-245)
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
```

**File:** engine/src/engine.rs (L1176-1224)
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

**File:** engine-tests/src/tests/erc20_connector.rs (L771-775)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```
