### Title
ERC-20 Tokens Permanently Frozen When `ExitToNear` Precompile's NEAR-Side Transfer Fails Without `error_refund` Feature - (`engine-precompiles/src/native.rs`)

---

### Summary

When a user calls the `ExitToNear` precompile to bridge ERC-20 tokens from Aurora to NEAR, the tokens are burned on the Aurora side first. If the subsequent NEAR-side `ft_transfer` fails (e.g., the recipient account is not registered in the NEP-141 contract), and the `error_refund` compile-time feature is **not** enabled, no callback is attached and no refund is issued. The burned ERC-20 tokens are permanently lost.

---

### Finding Description

The `ExitToNear` precompile in `engine-precompiles/src/native.rs` constructs a `callback_args` struct that conditionally includes a `refund` field:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

For a standard ERC-20 exit (not wNEAR unwrap), `transfer_near` is `None`. Without `error_refund`, `refund` is also `None`. This makes `callback_args` equal to its default value, triggering the branch that attaches **no callback at all**:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // no callback
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [2](#0-1) 

Without a callback, when the NEAR-side `ft_transfer` fails, `exit_to_near_precompile_callback` is never invoked, so `refund_on_error` is never called, and the burned ERC-20 tokens are never re-minted.

The `error_refund` feature is **not** part of the `default` or `contract` feature sets in `engine/Cargo.toml`:

```toml
[features]
default = ["std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
error_refund = ["aurora-engine-precompiles/error_refund"]
``` [3](#0-2) 

The production WASM binary is compiled with `--features contract`, which does not include `error_refund`. The same pattern holds in `engine-precompiles/Cargo.toml`:

```toml
[features]
default = ["std"]
...
error_refund = []
``` [4](#0-3) 

The test suite explicitly acknowledges this behavior:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

The same pattern applies to ETH exits:

```rust
// If the refund feature is not enabled, then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
``` [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

When the NEAR-side `ft_transfer` fails (e.g., recipient not registered in the NEP-141 contract), the ERC-20 tokens that were already burned on Aurora are permanently destroyed with no recovery path. The NEP-141 tokens remain in the Aurora engine's custody on NEAR (the `ft_transfer` was rejected), but the corresponding ERC-20 tokens no longer exist on Aurora. The user suffers a total, irrecoverable loss of the bridged amount.

---

### Likelihood Explanation

**High.** The `ExitToNear` precompile is callable by any EVM user. NEAR NEP-141 tokens require explicit storage registration before an account can receive them. A user who specifies any NEAR account that has not called `storage_deposit` on the target NEP-141 contract will trigger this failure path. This is a routine operational condition, not an exotic edge case — the test `test_exit_to_near_refund` explicitly exercises it with `"unregistered.near"` as the recipient. [7](#0-6) 

---

### Recommendation

Enable the `error_refund` feature in the production build by adding it to the `contract` feature set in `engine/Cargo.toml`:

```toml
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract", "aurora-engine-precompiles/error_refund"]
```

This ensures that `refund_call_args` is always populated and a callback is always attached to the `ft_transfer` promise, so that a failed NEAR-side transfer triggers `exit_to_near_precompile_callback` → `refund_on_error`, re-minting the burned ERC-20 tokens to the original sender. [8](#0-7) 

---

### Proof of Concept

1. Deploy Aurora Engine **without** the `error_refund` feature (the default production configuration).
2. Bridge a NEP-141 token to Aurora as an ERC-20 (standard `ft_transfer_call` → `ft_on_transfer` flow).
3. Call the `ExitToNear` precompile from the ERC-20 contract's burn function, specifying a NEAR recipient account that has **not** registered storage with the NEP-141 contract.
4. The ERC-20 tokens are burned on Aurora. The NEAR-side `ft_transfer` fails because the recipient is unregistered.
5. Since `error_refund` is not enabled, `callback_args.refund == None` and `callback_args.transfer_near == None`, so `callback_args == ExitToNearPrecompileCallbackArgs::default()` is true.
6. No callback is attached; `exit_to_near_precompile_callback` is never called; `refund_on_error` is never invoked.
7. The user's ERC-20 balance is permanently zero. The NEP-141 tokens remain locked in the Aurora engine account on NEAR with no mechanism to recover them to the user.

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` already demonstrates this exact scenario and confirms the balance discrepancy when `error_refund` is absent. [9](#0-8)

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

**File:** engine/Cargo.toml (L42-51)
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
impl-serde = ["aurora-engine-types/impl-serde", "aurora-engine-transactions/impl-serde", "aurora-evm/with-serde"]
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

**File:** engine-tests/src/tests/erc20_connector.rs (L773-775)
```rust
        // If the refund feature is not enabled, then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
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
