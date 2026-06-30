### Title
Permanent Loss of ETH and ERC-20 Tokens When `ExitToNear` NEAR-Side Promise Fails Without `error_refund` Feature - (File: engine-precompiles/src/native.rs)

### Summary

When the `error_refund` compile-time feature is not enabled, the `ExitToNear` precompile burns user ETH or ERC-20 tokens from EVM state and schedules a NEAR-side `ft_transfer` promise with **no failure callback**. If the NEAR-side promise fails for any reason (unregistered recipient, insufficient gas, NEP-141 rejection), the burned tokens are permanently unrecoverable. This is a direct analog to M05: tokens are consumed on one side of a two-step operation, but the contract has no mechanism to handle the case where the second step fails.

### Finding Description

The `ExitToNear` precompile in `engine-precompiles/src/native.rs` handles two token exit paths: ETH (base token) and ERC-20. In both cases, the EVM-side tokens are burned/debited before the NEAR-side promise is dispatched. The refund mechanism that would restore the user's balance on NEAR-side failure is entirely gated behind the `error_refund` compile-time feature flag.

When `error_refund` is **not** compiled in, the `refund` field of `ExitToNearPrecompileCallbackArgs` is hardcoded to `None`: [1](#0-0) 

Because `refund` is `None` and `transfer_near` is also `None` for standard ETH and ERC-20 exits, `callback_args` equals its default value, and the code takes the branch that attaches **no callback at all** to the NEAR promise: [2](#0-1) 

Without a callback, there is no `exit_to_near_precompile_callback` invocation when the NEAR-side `ft_transfer` or `near_withdraw` fails. The `exit_to_near_precompile_callback` function is the only place where `refund_on_error` is called to re-mint burned ERC-20 tokens or transfer ETH back from the precompile address: [3](#0-2) 

The `refund_on_error` function itself correctly handles both ETH and ERC-20 refunds, but it is unreachable when the feature is absent: [4](#0-3) 

The test suite explicitly documents this permanent-loss behavior as the expected outcome when `error_refund` is absent: [5](#0-4) [6](#0-5) 

### Impact Explanation

When the NEAR-side promise fails:
- **ETH exits**: The ETH was transferred from the user's EVM balance to the `exit_to_near` precompile address (`0xe9217bc7...`) before the promise fires. Without a refund callback, it remains stranded at that precompile address with no recovery path.
- **ERC-20 exits**: The ERC-20 tokens were burned from the user's balance before the promise fires. Without a refund callback to re-mint them, they are permanently destroyed.

In both cases the result is **permanent, irrecoverable loss of user funds** — matching the Critical impact tier of permanent freezing of funds.

### Likelihood Explanation

The NEAR-side `ft_transfer` promise can fail for reasons entirely within normal user behavior:
- Sending to a NEAR account that is not registered with the NEP-141 token contract (the most common failure mode, explicitly tested in `test_exit_to_near_refund`)
- Insufficient gas attached to the NEAR-side call (the `FT_TRANSFER_GAS` constant of 10 TGas is a fixed estimate)
- The NEP-141 contract rejecting the transfer for any contract-specific reason

Any unprivileged EVM user who calls the `ExitToNear` precompile and whose NEAR-side transfer fails is affected. The entry path requires no special privileges: a standard EVM transaction calling the precompile at `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` is sufficient. [7](#0-6) 

### Recommendation

Ensure the `error_refund` feature is always compiled into the production WASM artifact, or restructure the refund logic so it is unconditional rather than feature-gated. The refund callback should always be attached when tokens are burned/debited on the EVM side, regardless of compile-time configuration. The existing `refund_on_error` and `exit_to_near_precompile_callback` implementations are correct; the gap is solely that they are never reached when `error_refund` is absent.

### Proof of Concept

1. Deploy Aurora Engine **without** the `error_refund` feature.
2. Bridge a NEP-141 token to Aurora as an ERC-20.
3. Call the `ExitToNear` precompile from an EVM transaction, specifying a NEAR recipient account that is **not registered** with the NEP-141 contract (e.g., `"unregistered.near"`).
4. The ERC-20 tokens are burned from the caller's EVM balance.
5. The NEAR-side `ft_transfer` promise fails because the recipient is unregistered.
6. No `exit_to_near_precompile_callback` is invoked (no callback was attached).
7. Observe that the caller's ERC-20 balance is permanently reduced with no refund — confirmed by the existing test `test_exit_to_near_refund` which asserts `balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into()` in the `#[cfg(not(feature = "error_refund"))]` branch. [8](#0-7)

### Citations

**File:** engine-precompiles/src/native.rs (L270-278)
```rust
pub mod exit_to_near {
    use crate::prelude::types::{Address, make_address};

    /// Exit to NEAR precompile address
    ///
    /// Address: `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`
    /// This address is computed as: `&keccak("exitToNear")[12..]`
    pub const ADDRESS: Address = make_address(0xe9217bc7, 0x0b7ed1f598ddd3199e80b093fa71124f);
}
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

**File:** engine-tests/src/tests/erc20_connector.rs (L771-775)
```rust
        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```
