### Title
Permanent Fund Loss in `ExitToNear` Precompile When NEAR-Side `ft_transfer` Fails Without `error_refund` Feature — (File: `engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile burns ERC-20 tokens (or transfers ETH to the precompile address) in the EVM before dispatching a NEAR-side `ft_transfer` promise. Without the `error_refund` compile-time feature enabled, no refund callback is attached. If the NEAR-side transfer fails — a realistic scenario when the recipient is not registered with the NEP-141 contract — the burned tokens are permanently unrecoverable. This is a direct analog of the LayerZero blocking bug: the EVM side commits state (burn), the NEAR side fails, and no recovery path exists.

---

### Finding Description

In `engine-precompiles/src/native.rs`, the `ExitToNear::run` function constructs the outbound promise:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None without the feature
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

For a standard ERC-20 exit (no wNEAR unwrap), `transfer_near` is also `None`, so `callback_args` equals the default value. The branch taken is therefore:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback at all
} else { ... }
``` [2](#0-1) 

The `transfer_promise` calls `ft_transfer` on the NEP-141 contract:

```rust
let transfer_promise = PromiseCreateArgs {
    target_account_id: nep141_address,
    method,
    args: args.into_bytes(),
    attached_balance: Yocto::new(1),
    attached_gas,
};
``` [3](#0-2) 

By the time this NEAR promise executes, the ERC-20 tokens have already been burned inside the EVM (the ERC-20 `burn` function calls the precompile). If `ft_transfer` fails — for example because the recipient account is not registered with the NEP-141 storage — the NEP-141 tokens remain locked in the Aurora Engine account and the ERC-20 tokens are gone. The callback branch that would re-mint the burned tokens is:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
``` [4](#0-3) 

Without `error_refund`, `args.refund` is always `None`, so this branch is never reached and no re-mint occurs.

The same issue applies to the ETH (base-token) exit path: ETH is transferred to `exit_to_near::ADDRESS` inside the EVM, and if `ft_transfer` fails the ETH is permanently stranded at that precompile address with no recovery path.

The test suite explicitly documents this behavior:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

```rust
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
``` [6](#0-5) 

---

### Impact Explanation

**Critical — Permanent freezing / effective theft of user funds.**

When `ft_transfer` fails, the ERC-20 tokens are already burned in the EVM and cannot be recovered. The corresponding NEP-141 tokens remain in the Aurora Engine account, inaccessible to the user or anyone else. This is a one-way, irreversible loss of bridged assets.

---

### Likelihood Explanation

**Medium.**

NEP-141 tokens in NEAR require explicit storage registration before an account can receive them. Sending to any unregistered account — a common mistake — causes `ft_transfer` to fail. No admin action is required; any unprivileged EVM user can trigger this by specifying a recipient that has not called `storage_deposit` on the target NEP-141 contract. The `error_refund` feature changes the input wire format (`MIN_INPUT_SIZE` shifts from 3 to 21 bytes), making it a breaking change that is not enabled by default, as confirmed by the conditional compilation guards throughout the codebase. [7](#0-6) 

---

### Recommendation

1. **Enable `error_refund` unconditionally** (or make it the default feature) so that a refund callback is always attached to the `ft_transfer` promise. The `refund_on_error` path in `engine/src/engine.rs` already implements the correct re-mint logic.
2. **For `ExitToEthereum`**, add an analogous callback that re-mints ERC-20 tokens if the ETH-connector `withdraw` call fails, since that precompile has no refund path at all regardless of feature flags. [8](#0-7) 

---

### Proof of Concept

1. Deploy a NEP-141 token and bridge it to Aurora as an ERC-20.
2. From an EVM address, call `withdrawToNear(recipient, amount)` on the ERC-20 contract, where `recipient` is a NEAR account that has **not** called `storage_deposit` on the NEP-141 contract.
3. The ERC-20 `burn` executes successfully inside the EVM; the `ExitToNear` precompile emits a `PromiseArgs::Create` log targeting `ft_transfer`.
4. On the NEAR side, `ft_transfer` panics with `"The account <recipient> is not registered"`.
5. Because `error_refund` is not enabled, `callback_args.refund` is `None`; `exit_to_near_precompile_callback` is never scheduled; `refund_on_error` is never called.
6. The user's ERC-20 tokens are permanently destroyed; the NEP-141 tokens remain locked in the Aurora Engine account. [9](#0-8) [10](#0-9)

### Citations

**File:** engine-precompiles/src/native.rs (L36-39)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
```

**File:** engine-precompiles/src/native.rs (L449-501)
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
        let promise_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: Vec::new(),
            data: borsh::to_vec(&promise).unwrap(),
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
            cost: required_gas,
            output: Vec::new(),
        })
    }
```

**File:** engine/src/contract_methods/connector.rs (L196-245)
```rust
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

**File:** engine-tests/src/tests/erc20_connector.rs (L658-660)
```rust
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
```

**File:** engine-tests/src/tests/erc20_connector.rs (L774-775)
```rust
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
