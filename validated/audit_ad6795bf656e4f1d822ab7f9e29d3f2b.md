### Title
Permanent Loss of ERC-20 / ETH Funds When `ExitToNear` Downstream Promise Fails Without `error_refund` Feature — (`engine-precompiles/src/native.rs`)

---

### Summary

The Aurora Engine production WASM is compiled with `CARGO_FEATURES_BUILD = "contract"`, which excludes the `error_refund` feature. When a user calls the `ExitToNear` precompile to bridge ERC-20 tokens or ETH back to NEAR, the EVM-side assets are burned/deducted first, and a NEAR promise (`ft_transfer` or `ft_transfer_call`) is dispatched to the NEP-141 contract. If that promise fails for any reason (e.g., unregistered recipient storage, zero-balance NEP-141 contract, etc.), no callback is registered to re-mint the burned tokens. The user permanently loses their funds with no recovery path.

---

### Finding Description

**Step 1 — Production build excludes `error_refund`.**

`Makefile.toml` sets the production feature set to `"contract"` only: [1](#0-0) 

The `error_refund` feature is defined separately in both `engine-precompiles/Cargo.toml` and `engine/Cargo.toml` and is never included in the production build: [2](#0-1) [3](#0-2) 

**Step 2 — Without `error_refund`, the refund field is hardcoded to `None`.**

Inside `ExitToNear::run()`, the callback args struct is built with a compile-time branch: [4](#0-3) 

In production (`#[cfg(not(feature = "error_refund"))]`), `refund` is always `None`.

**Step 3 — When `refund` is `None` and `transfer_near` is also `None`, no callback promise is registered at all.** [5](#0-4) 

`ExitToNearPrecompileCallbackArgs::default()` has both fields as `None`. When the struct equals the default, only a bare `PromiseArgs::Create` is emitted — no callback. If the `ft_transfer` promise fails, there is no `exit_to_near_precompile_callback` invocation and therefore no `refund_on_error` call.

**Step 4 — `refund_on_error` is the only recovery path.**

The callback handler in `exit_to_near_precompile_callback` is the sole place that re-mints burned ERC-20 tokens or returns ETH from the precompile address: [6](#0-5) 

The re-mint logic calls back into the EVM to invoke `mint()` on the ERC-20 contract or transfers ETH from the precompile address: [7](#0-6) 

Without the callback, neither path executes.

**Step 5 — The codebase itself documents this loss.**

The integration tests explicitly acknowledge that without `error_refund`, tokens are permanently lost: [8](#0-7) [9](#0-8) 

---

### Impact Explanation

**Critical — Permanent freezing / loss of funds.**

- For ERC-20 exits: the ERC-20 tokens are burned on the EVM side before the NEAR promise is dispatched. If `ft_transfer` fails, the tokens are gone from the EVM and never arrive on NEAR. There is no admin recovery path (no equivalent of `call_to` force-mint).
- For ETH exits: ETH is deducted from the user's EVM balance and credited to the `ExitToNear` precompile address. If `ft_transfer` fails, the ETH sits locked in the precompile address with no mechanism to return it to the user.

---

### Likelihood Explanation

**High.** The failure condition for the downstream `ft_transfer` promise is easily triggered by any user who:
- Specifies a NEAR recipient account that has not registered storage with the NEP-141 contract (the most common failure mode, as shown in the test `test_exit_to_near_refund` which uses `"unregistered.near"`).
- Specifies a recipient account that does not exist on NEAR.
- Calls `ft_transfer_call` with a `msg` that causes the receiving contract to reject the transfer.

These are all realistic, non-malicious user mistakes. The `error_refund` feature exists precisely because this failure mode was anticipated, but it is not activated in production.

---

### Recommendation

Enable the `error_refund` feature in the production build by adding it to `CARGO_FEATURES_BUILD` in `Makefile.toml`:

```toml
CARGO_FEATURES_BUILD = "contract,error_refund"
```

This ensures `refund_call_args` populates the `refund` field in `ExitToNearPrecompileCallbackArgs`, a callback promise is always registered, and `refund_on_error` is invoked to re-mint ERC-20 tokens or return ETH when the downstream NEP-141 transfer fails.

---

### Proof of Concept

1. Deploy Aurora Engine with `CARGO_FEATURES_BUILD = "contract"` (current production default).
2. Bridge a NEP-141 token to Aurora to receive ERC-20 tokens.
3. Call the `ExitToNear` precompile from the ERC-20 contract's burn function, specifying an unregistered NEAR account as the recipient.
4. The ERC-20 tokens are burned on the EVM side.
5. The `ft_transfer` promise to the NEP-141 contract fails (unregistered storage).
6. No `exit_to_near_precompile_callback` is scheduled (because `callback_args == default()`).
7. Observe: ERC-20 balance is zero, NEP-141 balance of recipient is zero. Funds are permanently lost.

This is confirmed by the existing test `test_exit_to_near_refund` which explicitly asserts the lost balance under `#[cfg(not(feature = "error_refund"))]`: [10](#0-9)

### Citations

**File:** Makefile.toml (L8-8)
```text
CARGO_FEATURES_BUILD = "contract"
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

**File:** engine/src/engine.rs (L1184-1203)
```rust
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
