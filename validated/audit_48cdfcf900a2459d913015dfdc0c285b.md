### Title
Permanent Fund Freeze When `ft_transfer` Promise Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`, `engine/src/contract_methods/connector.rs`)

### Summary
When the `ExitToNear` precompile is invoked (for ERC-20 or ETH base-token exits), tokens are burned/transferred before a NEAR `ft_transfer` promise is dispatched. If that promise fails and the `error_refund` compile-time feature is absent (which is the default), no callback is registered and no refund is issued. The tokens are permanently frozen.

### Finding Description

The `ExitToNear` precompile constructs a `ExitToNearPrecompileCallbackArgs` struct whose `refund` field is unconditionally `None` when the `error_refund` feature is not compiled in:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None in the default build
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

For the common ERC-20 and ETH exit paths, `transfer_near` is also `None`, so `callback_args` equals `ExitToNearPrecompileCallbackArgs::default()`. The branch that follows then creates a bare `PromiseArgs::Create` — **no callback at all**:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback registered
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [2](#0-1) 

Because no callback is registered, a failed `ft_transfer` NEAR promise has no handler. Even in the wNEAR-unwrap path where a callback *is* registered, the callback only handles the success branch; the failure branch falls through to `else { None }` with no refund:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(...)?;
    ...
} else {
    None   // ← no refund when error_refund is absent
};
``` [3](#0-2) 

`error_refund` is **not** listed in the `default` features of either crate, so the default production build is affected: [4](#0-3) [5](#0-4) 

The engine's own test suite explicitly acknowledges the loss:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [6](#0-5) 

### Impact Explanation

**Impact: Critical — Permanent freezing of funds.**

- **ERC-20 exit path:** The ERC-20 token's `burn` function is called inside the EVM before the NEAR promise is dispatched. If `ft_transfer` on the NEP-141 contract fails (e.g., recipient not storage-registered), the burned tokens are gone with no re-mint. The `refund_on_error` path that would call `setup_refund_on_error_input` to re-mint is never reached.
- **ETH (base-token) exit path:** ETH is transferred from the caller to `exit_to_near::ADDRESS` inside the EVM. If the subsequent `ft_transfer` fails, the ETH remains locked at the precompile address permanently. [7](#0-6) 

### Likelihood Explanation

**Likelihood: Low.**

The `ft_transfer` promise fails when the recipient NEAR account is not registered (has no storage deposit) with the NEP-141 token contract. This is a realistic condition: any user who supplies an unregistered recipient account ID triggers the failure. The scenario is confirmed reachable by the existing test `test_exit_to_near_refund`, which deliberately uses `"unregistered.near"` to trigger the failure path. [8](#0-7) 

### Recommendation

Enable `error_refund` as a **default** feature in both `engine-precompiles` and `engine`, or restructure the code so that a refund callback is always registered regardless of the feature flag. The `refund_on_error` function already implements the correct recovery logic; it simply needs to be reachable in the default build. [9](#0-8) 

### Proof of Concept

1. Deploy Aurora Engine compiled **without** the `error_refund` feature (the default).
2. Bridge a NEP-141 token to Aurora as an ERC-20.
3. From an EVM address, call the ERC-20's `withdrawToNear` targeting a NEAR account that has **no storage deposit** on the NEP-141 contract (e.g., a freshly created account).
4. The ERC-20 tokens are burned from the caller's EVM balance.
5. The NEAR `ft_transfer` promise fails because the recipient is unregistered.
6. No callback fires; no re-mint occurs.
7. The caller's ERC-20 balance is permanently reduced with no corresponding NEP-141 credit — funds are frozen.

The same sequence applies to ETH exits: ETH is moved to `exit_to_near::ADDRESS` and is irrecoverable after a failed `ft_transfer`. [10](#0-9) [11](#0-10)

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

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
```

**File:** engine/Cargo.toml (L42-48)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
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
