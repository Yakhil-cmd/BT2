### Title
Missing Refund on `exit_to_near` Promise Failure When `error_refund` Feature Is Disabled - (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile's refund logic is gated behind the `error_refund` compile-time feature flag. When this feature is not compiled in (which is the case in the default and production `contract` build), a failed `ft_transfer` or `ft_transfer_call` promise leaves the user's ERC-20 tokens permanently burned or ETH permanently locked in the precompile address, with no recovery path.

---

### Finding Description

In `engine-precompiles/src/native.rs`, the `ExitToNear::run()` method constructs `ExitToNearPrecompileCallbackArgs` with the `refund` field unconditionally set to `None` when the `error_refund` feature is absent: [1](#0-0) 

The `error_refund` feature is **not** listed in the `default` features of `engine-precompiles/Cargo.toml`: [2](#0-1) 

Nor is it activated by the `contract` feature in `engine/Cargo.toml`, which is the feature used for the production WASM build: [3](#0-2) 

The callback handler `exit_to_near_precompile_callback` in `engine/src/contract_methods/connector.rs` only issues a refund when `args.refund` is `Some(...)`. When the promise fails and `refund` is `None`, the `else` branch silently returns `None` — no refund, no error: [4](#0-3) 

The refund logic itself (`engine::refund_on_error`) is fully implemented and would re-mint burned ERC-20 tokens or transfer ETH back from the precompile address: [5](#0-4) 

The test suite explicitly acknowledges the fund-loss behavior when the feature is absent: [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

- **ERC-20 path**: The ERC-20 tokens are burned from the user's EVM balance before the `ft_transfer` promise is dispatched. If the promise fails and `error_refund` is not compiled in, the tokens are gone permanently — burned on the EVM side, never transferred on the NEAR side.
- **ETH path**: ETH is transferred from the user to the `exit_to_near` precompile address before the promise. If the promise fails without `error_refund`, the ETH is permanently locked in the precompile address with no mechanism to recover it.

---

### Likelihood Explanation

**High.** The `ft_transfer` promise can fail for ordinary, user-triggerable reasons:

- The recipient NEAR account is not registered with the NEP-141 contract (a common condition for new accounts).
- The NEP-141 contract rejects the transfer for any reason.

Any user who calls `exit_to_near` targeting an unregistered NEAR account will permanently lose their tokens. This requires no special privileges — it is reachable by any EVM user submitting a standard EVM transaction.

---

### Recommendation

Enable the `error_refund` feature in the production `contract` build profile by adding it to the `contract` feature in `engine/Cargo.toml`:

```toml
contract = ["log", "error_refund", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
```

This ensures `refund_call_args(...)` is always populated in `ExitToNearPrecompileCallbackArgs`, and the `exit_to_near_precompile_callback` will correctly re-mint or return funds to the user on promise failure.

---

### Proof of Concept

1. User holds ERC-20 tokens on Aurora (bridged from a NEP-141).
2. User calls the `exit_to_near` precompile (flag `0x1`) targeting a NEAR account that is **not registered** with the NEP-141 contract.
3. The precompile burns the user's ERC-20 tokens and schedules an `ft_transfer` promise.
4. The `ft_transfer` call fails (unregistered recipient).
5. `exit_to_near_precompile_callback` is invoked. Because `error_refund` is not compiled in, `args.refund` is `None`.
6. The callback falls into the `else { None }` branch — no refund is issued.
7. The user's ERC-20 tokens are permanently destroyed; the NEP-141 balance on the NEAR side is unchanged.

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` (lines 623–665) demonstrates exactly this scenario and confirms the balance loss when `error_refund` is absent. [7](#0-6)

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

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
```

**File:** engine/Cargo.toml (L42-50)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
integration-test = ["log"]
all-promise-actions = ["aurora-engine-sdk/all-promise-actions"]
```

**File:** engine/src/contract_methods/connector.rs (L231-242)
```rust
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
