### Title
Insufficient Gas Allocated to `exit_to_near_precompile_callback` Causes Permanent ERC-20 Token Freeze - (File: `engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToNear` precompile burns ERC-20 tokens in the EVM and then schedules a NEAR promise (`ft_transfer` / `ft_transfer_call`) to deliver the corresponding NEP-141 tokens to the recipient. A callback `exit_to_near_precompile_callback` is attached with a fixed gas budget of `EXIT_TO_NEAR_CALLBACK_GAS = 10 TGas`. When the `error_refund` feature is enabled and the base `ft_transfer` promise fails, this callback must execute a full EVM call (`refund_on_error`) to re-mint the burned ERC-20 tokens. 10 TGas is insufficient for a full EVM execution, causing the callback to run out of gas and fail. Because the ERC-20 burn occurred in the original EVM execution (not in the callback), it is not reverted when the callback fails. The user's ERC-20 tokens are permanently destroyed with no NEP-141 tokens received and no refund issued.

---

### Finding Description

**Root cause — `engine-precompiles/src/native.rs`, lines 456–482:**

```rust
let attached_gas = if method == "ft_transfer_call" {
    costs::FT_TRANSFER_CALL_GAS
} else {
    costs::FT_TRANSFER_GAS
};
// ...
PromiseArgs::Callback(PromiseWithCallbackArgs {
    base: transfer_promise,
    callback: PromiseCreateArgs {
        target_account_id: self.current_account_id.clone(),
        method: "exit_to_near_precompile_callback".to_string(),
        args: borsh::to_vec(&callback_args).unwrap(),
        attached_balance: Yocto::new(0),
        attached_gas: costs::EXIT_TO_NEAR_CALLBACK_GAS,  // ← 10 TGas
    },
})
``` [1](#0-0) 

`EXIT_TO_NEAR_CALLBACK_GAS` is defined as `10_000_000_000_000` (10 TGas), calibrated for the simple wNEAR-unwrap path (creating a NEAR transfer promise). However, when the `error_refund` feature is enabled and the base `ft_transfer` fails, the callback takes the refund branch in `exit_to_near_precompile_callback`: [2](#0-1) 

This branch calls `engine::refund_on_error`, which constructs a full `Engine` instance and executes an EVM call (`engine.call(...)` with `u64::MAX` EVM gas) to re-mint the burned ERC-20 tokens: [3](#0-2) 

A full EVM execution on NEAR — reading contract bytecode from storage, executing the ERC-20 mint function, writing the updated balance, emitting events — costs far more than 10 TGas (typically 100–300 TGas). The CHANGES.md itself records a prior instance of this class of problem: *"Fixed exceeded prepaid gas error in the `mirror_erc20_token` transaction"*, confirming that EVM operations inside NEAR callbacks routinely exceed their gas budgets. [4](#0-3) 

**Sequence of events leading to permanent freeze:**

1. User calls the `ExitToNear` precompile with ERC-20 tokens. The ERC-20 contract burns the tokens inside the EVM execution of the original `submit` call. This burn is committed to Aurora's state.
2. Aurora schedules a NEAR promise: `ft_transfer` on the NEP-141 contract (10 TGas), followed by `exit_to_near_precompile_callback` (10 TGas).
3. `ft_transfer` fails (e.g., recipient account not registered with the NEP-141 contract).
4. The callback is invoked with `PromiseResult::Failed`. It enters the `refund_on_error` branch and attempts to re-mint the ERC-20 tokens via a full EVM execution.
5. The callback exhausts its 10 TGas budget and panics. NEAR reverts the callback's state changes (the re-mint never completes).
6. The ERC-20 burn from step 1 is **not** reverted — it occurred in a prior receipt. The NEP-141 tokens were never transferred. The user has lost their tokens permanently. [5](#0-4) 

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

When the callback runs out of gas:
- The ERC-20 tokens are permanently burned (committed in the original EVM receipt, not reversible by the callback).
- The NEP-141 tokens remain in Aurora's custody, inaccessible to the user.
- No refund is issued.

The user suffers a total, irrecoverable loss of the bridged token value.

---

### Likelihood Explanation

**Medium.**

The preconditions are:
1. The `error_refund` feature must be compiled into the production binary. The feature is present in the codebase and tested (`test_exit_to_near_refund`), making production deployment plausible.
2. The base `ft_transfer` must fail. This is a normal operational scenario: any recipient account not registered with the NEP-141 contract will cause `ft_transfer` to fail. A user can trigger this accidentally (wrong recipient) or an attacker can deliberately target an unregistered account.
3. The callback must exhaust 10 TGas. Given that a full EVM execution costs 100–300 TGas, this condition is met systematically whenever the refund path is taken — it is not a probabilistic race condition.

No special privileges are required. Any Aurora user holding ERC-20 tokens can trigger this path.

---

### Recommendation

Increase `EXIT_TO_NEAR_CALLBACK_GAS` to a value sufficient to cover the full EVM execution in `refund_on_error`. Based on observed EVM execution costs on NEAR (100–300 TGas for ERC-20 operations), the callback gas should be raised to at least 200–300 TGas when the `error_refund` feature is enabled.

Alternatively, separate the gas budget into two constants: one for the wNEAR-unwrap path (NEAR transfer promise creation, ~10 TGas) and one for the ERC-20 refund path (full EVM execution, ~200–300 TGas), and select the appropriate constant at promise-creation time based on which path will be taken. [6](#0-5) 

---

### Proof of Concept

1. Deploy a NEP-141 token and bridge it to Aurora (creating an ERC-20 mirror).
2. Acquire ERC-20 tokens on Aurora.
3. Call the `ExitToNear` precompile specifying a NEAR recipient account that is **not registered** with the NEP-141 contract (no storage deposit). This causes `ft_transfer` to fail.
4. Observe that `exit_to_near_precompile_callback` is invoked with `PromiseResult::Failed` and enters the `refund_on_error` branch.
5. With `EXIT_TO_NEAR_CALLBACK_GAS = 10 TGas`, the callback exhausts its gas budget during the EVM execution in `refund_on_error` and panics.
6. Verify: the ERC-20 balance of the sender is zero (tokens burned), the NEP-141 balance of the recipient is unchanged (transfer never happened), and the ERC-20 balance is not restored (refund failed). The tokens are permanently lost. [7](#0-6) [8](#0-7)

### Citations

**File:** engine-precompiles/src/native.rs (L42-62)
```rust
mod costs {
    use crate::prelude::types::{EthGas, NearGas};

    // TODO(#483): Determine the correct amount of gas
    pub(super) const EXIT_TO_NEAR_GAS: EthGas = EthGas::new(0);

    // TODO(#483): Determine the correct amount of gas
    pub(super) const EXIT_TO_ETHEREUM_GAS: EthGas = EthGas::new(0);

    /// Value determined experimentally based on tests and mainnet data. Example:
    /// `https://explorer.mainnet.near.org/transactions/5CD7NrqWpK3H8MAAU4mYEPuuWz9AqR9uJkkZJzw5b8PM#D1b5NVRrAsJKUX2ZGs3poKViu1Rgt4RJZXtTfMgdxH4S`
    pub(super) const FT_TRANSFER_GAS: NearGas = NearGas::new(10_000_000_000_000);

    pub(super) const FT_TRANSFER_CALL_GAS: NearGas = NearGas::new(70_000_000_000_000);

    /// Value determined experimentally based on tests.
    pub(super) const EXIT_TO_NEAR_CALLBACK_GAS: NearGas = NearGas::new(10_000_000_000_000);

    // TODO(#332): Determine the correct amount of gas
    pub(super) const WITHDRAWAL_GAS: NearGas = NearGas::new(100_000_000_000_000);
}
```

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

**File:** CHANGES.md (L167-167)
```markdown
- Fixed exceeded prepaid gas error in the `mirror_erc20_token` transaction by [@aleksuss] ([#951])
```
