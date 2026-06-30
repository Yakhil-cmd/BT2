### Title
Permanent ERC-20 Token Loss When `ft_transfer` Fails in `ExitToNear` Precompile Without `error_refund` Feature - (`engine-precompiles/src/native.rs`)

### Summary

When the `error_refund` compile-time feature is not enabled, the `ExitToNear` precompile burns ERC-20 tokens (or deducts ETH) in the EVM as step 1, then schedules a NEAR `ft_transfer` promise as step 2. If the `ft_transfer` promise fails, no callback is attached to handle the failure and no refund is issued. The burned tokens are permanently lost, creating a permanent accounting inconsistency between the ERC-20 supply on Aurora and the NEP-141 supply held by the Aurora contract on NEAR.

### Finding Description

The `ExitToNear` precompile's `run` function constructs `callback_args` as follows:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None when feature is absent
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

For the standard ERC-20 legacy exit path (`ft_transfer`, no wNEAR unwrap), `transfer_near_args` is also `None`: [2](#0-1) 

When both fields are `None`, `callback_args` equals `ExitToNearPrecompileCallbackArgs::default()`, and the promise is created **without any callback**:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [3](#0-2) 

The `exit_to_near_precompile_callback` function, which is the only place a refund can be issued, is never scheduled: [4](#0-3) 

The `refund_on_error` function that would re-mint burned ERC-20 tokens or return ETH is therefore never called: [5](#0-4) 

The test suite explicitly documents this behavior as a known outcome:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [6](#0-5) 

The same permanent-loss behavior applies to the ETH (base token) exit path: [7](#0-6) 

### Impact Explanation

**Critical — Permanent freezing of funds / insolvency.**

When `ft_transfer` fails (e.g., unregistered receiver, insufficient gas forwarded, NEP-141 contract paused):

- **ERC-20 exit**: The ERC-20 tokens are burned from the user's EVM balance. The NEP-141 tokens remain locked in the Aurora contract on NEAR. The user receives nothing. The burned amount is irrecoverable — ERC-20 total supply is permanently deflated while the NEP-141 balance held by Aurora is not reduced, creating a permanent accounting inconsistency.
- **ETH exit**: ETH is deducted from the user's EVM balance and transferred to the `ExitToNear` precompile address. If `ft_transfer` fails, the ETH sits at the precompile address with no mechanism to return it to the user.

This is structurally identical to the INIT Capital bug: step 1 (seizing collateral / burning tokens) completes irreversibly, step 2 (clearing debt / transferring NEP-141) fails, and there is no code path to reconcile the resulting inconsistency.

### Likelihood Explanation

**High.** The `ft_transfer` promise can fail for multiple reasons entirely within normal operation:

1. The destination NEAR account is not registered with the NEP-141 contract (the exact scenario in `test_exit_to_near_refund`).
2. The NEP-141 contract is paused or has access controls.
3. Insufficient gas is forwarded (`FT_TRANSFER_GAS = 10 TGas` is a fixed constant that may be insufficient for some NEP-141 implementations).

Any EVM user holding ERC-20 tokens can trigger this by calling `withdrawToNear` with a destination that causes `ft_transfer` to fail. The user is the victim of their own call, but the accounting damage (ERC-20 supply deflation without corresponding NEP-141 release) is permanent and affects the integrity of the bridge invariant for all users. [8](#0-7) 

### Recommendation

Enable the `error_refund` feature in all production builds, or make it a default feature in `Cargo.toml`. The refund address must be included in the precompile input encoding (the `MIN_INPUT_SIZE` changes from 3 to 21 bytes), so the ERC-20 contract's `withdrawToNear` function must also be updated to pass the refund address. Alternatively, restructure the promise chain so that a callback is always attached regardless of the feature flag, using the `context.caller` (the ERC-20 contract address) as the implicit refund target.

### Proof of Concept

1. Deploy Aurora without the `error_refund` feature.
2. Bridge a NEP-141 token to an ERC-20 on Aurora; user holds `FT_TRANSFER_AMOUNT` ERC-20 tokens.
3. Call `withdrawToNear("unregistered.near", FT_EXIT_AMOUNT)` on the ERC-20 contract.
4. The ERC-20 burns `FT_EXIT_AMOUNT` tokens from the user's balance and calls the `ExitToNear` precompile.
5. The precompile schedules `ft_transfer` to `unregistered.near` on the NEP-141 with no callback.
6. `ft_transfer` fails because `unregistered.near` is not registered.
7. No callback fires; no refund is issued.
8. **Result**: User's ERC-20 balance is `FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT`. NEP-141 balance held by Aurora is still `FT_TRANSFER_AMOUNT`. The `FT_EXIT_AMOUNT` tokens are permanently lost — confirmed by the existing test `test_exit_to_near_refund` which asserts exactly this outcome when the feature is absent. [9](#0-8)

### Citations

**File:** engine-precompiles/src/native.rs (L36-39)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
```

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

**File:** engine-precompiles/src/native.rs (L627-646)
```rust
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
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

**File:** engine-tests/src/tests/erc20_connector.rs (L623-666)
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
    }
```

**File:** engine-tests/src/tests/erc20_connector.rs (L771-775)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```
