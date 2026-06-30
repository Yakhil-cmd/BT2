### Title
Permanent Fund Loss When `ft_transfer` Promise Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

The `ExitToNear` precompile implements a cross-layer bridge from Aurora EVM to NEAR. When a user exits ERC-20 tokens or ETH, the EVM-side state change (burn/transfer) is committed atomically, but the NEAR-side `ft_transfer` promise is asynchronous and can fail independently. The compensation/refund mechanism that re-mints burned ERC-20 tokens or returns ETH is entirely gated behind the `error_refund` compile-time feature flag. When this feature is absent, no compensation is ever scheduled, and a failed `ft_transfer` promise results in permanent, irrecoverable fund loss for the user.

---

### Finding Description

**Step 1 — EVM-side state change is committed before the async promise.**

In `ExitToNear::run()`, for an ERC-20 exit the ERC-20 contract's burn function is called inside the EVM execution, which is committed atomically. The precompile then constructs a NEAR promise to call `ft_transfer` (or `ft_transfer_call`) on the NEP-141 contract: [1](#0-0) 

**Step 2 — The refund argument is unconditionally `None` without the feature flag.**

The `callback_args` struct that carries the refund information is built with `refund: None` when `error_refund` is not compiled in: [2](#0-1) 

**Step 3 — When `refund` is `None`, the callback does nothing on failure.**

In `exit_to_near_precompile_callback`, the failure branch is `else if let Some(args) = args.refund`. When `refund` is `None`, this branch is never entered, so no re-mint and no ETH return occurs: [3](#0-2) 

**Step 4 — `refund_on_error` (the compensation function) is never called.**

The function that would re-mint burned ERC-20 tokens or return ETH from the precompile address is `refund_on_error`: [4](#0-3) 

Without `error_refund`, this function is never invoked on a failed exit.

**Step 5 — The `error_refund` feature is not in `default`.** [5](#0-4) 

The feature is opt-in. Any deployment that does not explicitly enable it ships without the compensation mechanism.

**Step 6 — The test explicitly acknowledges the fund loss.** [6](#0-5) 

The test comment reads: *"If the refund feature is not enabled then there is no refund in the EVM"* — confirming the loss is a known code path, not a theoretical edge case.

---

### Impact Explanation

- **ERC-20 exit path**: ERC-20 tokens are burned in the EVM before the promise is dispatched. If `ft_transfer` fails (e.g., recipient account not registered with the NEP-141 contract, NEP-141 contract paused, insufficient storage deposit, or any other NEAR-side rejection), the tokens are permanently destroyed with no recovery path. The NEP-141 balance remains in Aurora's account, but the user's ERC-20 balance is gone.
- **ETH exit path**: ETH is transferred from the user to the `exit_to_near` precompile address in the EVM. If `ft_transfer` fails, the ETH is permanently locked in the precompile address with no recovery path.

Impact classification: **Critical — Permanent freezing/loss of user funds.**

---

### Likelihood Explanation

The `ft_transfer` promise can fail for multiple reasons that are reachable by any unprivileged user:

1. The recipient NEAR account is not registered with the NEP-141 contract (storage deposit missing). Any user can trigger this by specifying an unregistered recipient — the test `test_exit_to_near_refund` demonstrates exactly this scenario.
2. The NEP-141 contract is paused or has transfer restrictions.
3. The eth-connector contract has insufficient balance or is in an error state.

The attacker-controlled entry path is: call any EVM contract that invokes the `ExitToNear` precompile at address `0xe9217bc70b7ed1f598ddd3199e80b093fa71124f` with a recipient that will cause `ft_transfer` to fail. No special privileges are required. [7](#0-6) 

---

### Recommendation

1. **Enable `error_refund` unconditionally in production builds.** The feature should be moved into the `default` feature set of `aurora-engine-precompiles` so it is always active.
2. **Alternatively**, restructure the code so the refund/compensation path is not feature-gated and is always compiled in, removing the possibility of deploying without it.
3. **At minimum**, document clearly in the deployment guide that omitting `error_refund` creates a permanent fund-loss risk for all users of the `ExitToNear` precompile.

---

### Proof of Concept

1. Deploy Aurora Engine **without** the `error_refund` feature flag.
2. Bridge a NEP-141 token into Aurora, receiving ERC-20 tokens.
3. Call the ERC-20 contract's exit function targeting an unregistered NEAR account (e.g., `"unregistered.near"`). This invokes the `ExitToNear` precompile.
4. The ERC-20 tokens are burned in the EVM (committed).
5. The `ft_transfer` promise to the NEP-141 contract fails because `"unregistered.near"` has no storage deposit.
6. The `exit_to_near_precompile_callback` fires with `args.refund == None`; the failure branch is skipped entirely.
7. The user's ERC-20 balance is zero; the NEP-141 balance remains in Aurora's account; no retry is possible. Funds are permanently lost.

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` (lines 623–666) already demonstrates this exact scenario and explicitly confirms the balance discrepancy when `error_refund` is absent. [8](#0-7)

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

**File:** engine-precompiles/src/native.rs (L444-468)
```rust
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
            };

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

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
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
