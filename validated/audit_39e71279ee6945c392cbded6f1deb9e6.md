### Title
Permanent Fund Freeze When `exit_to_near` Promise Fails Without `error_refund` Feature - (`engine-precompiles/src/native.rs`)

### Summary

When a user bridges ERC-20 tokens or ETH out of Aurora via the `exit_to_near` precompile and the downstream NEAR-side `ft_transfer` promise fails, the refund mechanism is entirely absent unless the `error_refund` compile-time feature flag is enabled. Since `error_refund` is **not** in the default feature set, the production binary omits the refund callback entirely. Burned ERC-20 tokens are never re-minted and ETH transferred to the precompile address is never returned, leaving user funds permanently frozen.

### Finding Description

The `ExitToNear` precompile (`engine-precompiles/src/native.rs`) constructs a `ExitToNearPrecompileCallbackArgs` struct that conditionally includes a `refund` field only when the `error_refund` feature is compiled in: [1](#0-0) 

When `error_refund` is absent (the default), `refund` is `None`. The promise dispatch logic then checks whether `callback_args` equals its default (both fields `None`), and if so, schedules only a bare `PromiseArgs::Create` with no callback at all: [2](#0-1) 

The `error_refund` feature is not listed in the `default` features of the engine crate: [3](#0-2) 

When a callback **is** registered (e.g., for wNEAR unwrap), the `exit_to_near_precompile_callback` handler correctly calls `engine::refund_on_error` only when `args.refund` is `Some`. Without the feature, this branch is never reached: [4](#0-3) 

`refund_on_error` itself is correct — for ETH it transfers value back from the precompile address, and for ERC-20 it re-mints burned tokens: [5](#0-4) 

The tests explicitly confirm the fund-loss behavior when the feature is absent: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Critical — Permanent freezing of funds.**

- **ERC-20 exit path**: The ERC-20 contract burns the user's tokens before calling the precompile. If the NEAR-side `ft_transfer` fails (e.g., recipient not registered with the NEP-141 contract, NEP-141 paused, insufficient storage deposit), the tokens are burned with no re-mint. They are gone permanently.
- **ETH exit path**: ETH is transferred from the caller to the `exit_to_near` precompile address (`0xe9217bc70b7ed1f598ddd3199e80b093fa71124f`) before the NEAR promise fires. If the promise fails, the ETH sits in the precompile address with no recovery path.

### Likelihood Explanation

The NEAR-side `ft_transfer` promise can fail for several realistic, user-triggered reasons:

1. The recipient NEAR account is not registered (storage deposit missing) with the NEP-141 contract — a common mistake when specifying a new account.
2. The NEP-141 contract is paused or has transfer restrictions.
3. The recipient account ID is valid but does not exist on NEAR.

Any of these conditions, combined with the default build (no `error_refund`), results in permanent loss. The entry path is fully unprivileged: any EVM user can call the `exit_to_near` precompile directly or via an ERC-20 `withdraw` function.

### Recommendation

Enable `error_refund` in the default feature set of the `aurora-engine` crate, or unconditionally include the refund callback args and callback registration. The refund logic in `refund_on_error` is already correct; the issue is solely that it is never invoked in the default build. [8](#0-7) 

Change `default = ["std"]` to `default = ["std", "error_refund"]`, or remove the feature gate entirely and always populate `refund` in `ExitToNearPrecompileCallbackArgs`.

### Proof of Concept

The existing test `test_exit_to_near_refund` already demonstrates the issue. When compiled without `error_refund`:

1. User bridges `FT_EXIT_AMOUNT` of ERC-20 tokens via `exit_to_near` to `"unregistered.near"`.
2. The ERC-20 tokens are burned from the user's balance.
3. The NEAR `ft_transfer` promise fails because `"unregistered.near"` is not registered.
4. No callback fires; no re-mint occurs.
5. The user's ERC-20 balance is `FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT` instead of `FT_TRANSFER_AMOUNT`. [9](#0-8) 

The same pattern applies to ETH via `test_exit_to_near_eth_refund`: [10](#0-9)

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

**File:** engine/Cargo.toml (L43-48)
```text
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
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
