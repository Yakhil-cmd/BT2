### Title
ETH Permanently Frozen in `exit_to_near` Precompile on Failed `ft_transfer` When `error_refund` Feature Is Disabled - (`engine-precompiles/src/native.rs`)

---

### Summary

When a user calls the `exit_to_near` precompile with ETH (base token) and the subsequent `ft_transfer` promise to the eth-connector fails, the ETH is permanently frozen inside the `exit_to_near` precompile address. This occurs because the refund callback argument is unconditionally set to `None` when the `error_refund` compile-time feature is not enabled, leaving no recovery path for the stuck ETH.

---

### Finding Description

In `engine-precompiles/src/native.rs`, when the `exit_to_near` precompile processes an ETH exit, it constructs a callback argument struct that conditionally includes refund information: [1](#0-0) 

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
```

When `error_refund` is not enabled, `refund` is hardcoded to `None`. The callback handler in `engine/src/contract_methods/connector.rs` then processes the result of the `ft_transfer` promise: [2](#0-1) 

```rust
let maybe_result = if let Some(PromiseResult::Successful(_)) = handler.promise_result(0) {
    ...
    None
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
} else {
    None  // <-- reached when refund is None AND promise failed
};
```

When the `ft_transfer` promise fails and `args.refund` is `None`, execution falls into the final `else` branch and returns `None` — no refund is issued. The ETH that was transferred from the user's EVM balance to the `exit_to_near` precompile address at call time is permanently stranded there.

The `refund_on_error` function in `engine/src/engine.rs` that would have recovered the ETH is never called: [3](#0-2) 

The test `test_exit_to_near_eth_refund` in `engine-tests/src/tests/erc20_connector.rs` explicitly documents and confirms this behavior: [4](#0-3) 

```rust
#[cfg(feature = "error_refund")]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
// If the refund feature is not enabled, then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
```

The comment "there is no refund in the EVM" confirms the ETH is lost when the feature is absent.

---

### Impact Explanation

**Permanent freezing of funds.** ETH deducted from the user's EVM balance and credited to the `exit_to_near` precompile address has no recovery mechanism when `error_refund` is disabled. The precompile address is not a user-controlled account; no function exists to sweep or recover ETH stranded there. Every failed `exit_to_near` call under this configuration results in a permanent, irrecoverable loss of the user's ETH.

---

### Likelihood Explanation

The `ft_transfer` promise can fail under realistic conditions. The test demonstrates one concrete trigger: Aurora's NEP-141 ETH balance is drained via `ft_transfer` to a third party before the exit call, causing the subsequent `ft_transfer` in the exit flow to fail due to insufficient balance. [5](#0-4) 

Any unprivileged NEAR account holding NEP-141 ETH on Aurora can drain the Aurora contract's NEP-141 balance using the standard `ft_transfer` method, then trigger the freeze for any subsequent `exit_to_near` caller. This is a realistic, low-barrier attack path.

---

### Recommendation

Make the refund logic unconditional — remove the `#[cfg(feature = "error_refund")]` gate from the `refund` field construction in `ExitToNearPrecompileCallbackArgs`. The `refund_call_args` function should always be called so that a failed `ft_transfer` always triggers `refund_on_error`, restoring the ETH to the original sender's EVM balance regardless of build configuration. [6](#0-5) 

---

### Proof of Concept

The existing test `test_exit_to_near_eth_refund` in `engine-tests/src/tests/erc20_connector.rs` is a complete proof of concept:

1. Deploy Aurora; give a signer `INITIAL_ETH_BALANCE` of ETH on Aurora.
2. Drain Aurora's NEP-141 ETH balance via `ft_transfer` to a throwaway account.
3. Submit an EVM transaction calling `withdrawEthToNear` (the `exit_to_near` precompile) with `ETH_EXIT_AMOUNT`.
4. The `ft_transfer` promise fails because Aurora has no NEP-141 balance.
5. Without `error_refund`: signer's EVM balance is `INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT` — the `ETH_EXIT_AMOUNT` is permanently frozen in the precompile address. [7](#0-6)

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

**File:** engine/src/engine.rs (L1204-1224)
```rust
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

**File:** engine-tests/src/tests/erc20_connector.rs (L717-781)
```rust
    #[tokio::test]
    async fn test_exit_to_near_eth_refund() {
        // Test the case where the ft_transfer promise from the exit call fails;
        // ensure ETH is refunded.

        let TestExitToNearEthContext {
            signer,
            signer_address,
            chain_id,
            tester_address,
            aurora,
        } = test_exit_to_near_eth_common().await.unwrap();
        let exit_account_id = "any.near";

        // Make the ft_transfer call fail by draining the Aurora account
        let result = aurora
            .ft_transfer(
                &"tmp.near".parse().unwrap(),
                u128::from(INITIAL_ETH_BALANCE).into(),
                &None,
            )
            .max_gas()
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await
            .unwrap();
        assert!(result.is_success());

        // call exit to near
        let input = build_input(
            "withdrawEthToNear(bytes)",
            &[ethabi::Token::Bytes(exit_account_id.as_bytes().to_vec())],
        );
        let tx = utils::create_eth_transaction(
            Some(tester_address),
            Wei::new_u64(ETH_EXIT_AMOUNT),
            input,
            Some(chain_id),
            &signer.secret_key,
        );
        let result = aurora
            .submit(rlp::encode(&tx).to_vec())
            .max_gas()
            .transact()
            .await
            .unwrap();
        assert!(result.is_success());

        // check balances
        assert_eq!(
            nep_141_balance_of(aurora.as_raw_contract(), &exit_account_id.parse().unwrap()).await,
            0
        );

        #[cfg(feature = "error_refund")]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE);
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);

        assert_eq!(
            eth_balance_of(signer_address, &aurora).await,
            expected_balance
        );
    }
```
