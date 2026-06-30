### Title
Permanent ERC-20 Token Loss When `ft_transfer` Fails in `ExitToNear` Precompile Without `error_refund` Feature - (File: `engine-precompiles/src/native.rs`)

---

### Summary

When the `error_refund` compile-time feature is not enabled (the default build), the `ExitToNear` precompile burns ERC-20 tokens on the EVM side and schedules a `ft_transfer` promise on the NEAR side. If that promise fails — for example, because the recipient NEAR account is not registered with the NEP-141 contract — no callback is scheduled to re-mint the burned tokens. The result is a permanent, unrecoverable loss of user funds. This is an asymmetric accounting bug: the EVM-side burn always executes, but the NEAR-side credit is not guaranteed, and the failure path has no compensating write-back.

---

### Finding Description

**Vulnerability class:** Connector/bridge accounting bug — asymmetric accounting between EVM-side token burn and NEAR-side token transfer.

**Root cause — `engine-precompiles/src/native.rs`, `ExitToNear::run()`:**

When a user calls `withdrawToNear` on a bridged ERC-20 (e.g., `EvmErc20::withdrawToNear`), the Solidity contract burns the caller's tokens and then calls the `ExitToNear` precompile. Inside the precompile's `run()` method, `callback_args` is constructed:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,          // ← always None in the default build
    transfer_near: transfer_near_args,
};
``` [1](#0-0) 

For a plain ERC-20 exit (not a wNEAR unwrap), `transfer_near` is also `None`. This makes `callback_args` equal to `ExitToNearPrecompileCallbackArgs::default()`, so the branch that attaches a callback is skipped:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)   // ← no callback attached
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs { ... })
};
``` [2](#0-1) 

The `ft_transfer` promise is fired at the NEP-141 contract with no callback. If it fails, `exit_to_near_precompile_callback` is never invoked, so `engine::refund_on_error` is never called, and the burned ERC-20 tokens are never re-minted.

The `error_refund` feature is declared as a non-default opt-in feature:

```toml
[features]
default = ["std"]
...
error_refund = []
``` [3](#0-2) 

The refund path in `exit_to_near_precompile_callback` is only reachable when `error_refund` is enabled:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
    ...
}
``` [4](#0-3) 

The ERC-20 Solidity contracts (`EvmErc20`, `EvmErc20V2`) always burn before calling the precompile, with no internal rollback:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    // ... calls ExitToNear precompile
}
``` [5](#0-4) [6](#0-5) 

---

### Impact Explanation

**Impact: Permanent freezing of funds (Critical).**

When `ft_transfer` fails, the ERC-20 tokens are permanently destroyed on the EVM side while the NEP-141 tokens remain locked in the Aurora contract on the NEAR side. Neither the user nor any protocol actor can recover them: the ERC-20 supply is reduced, the NEP-141 balance of Aurora is unchanged, and no refund callback exists to restore the EVM balance. The tokens are effectively frozen forever.

The test suite explicitly acknowledges this outcome:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [7](#0-6) 

The same acknowledgment appears for ETH exits:

```rust
// If the refund feature is not enabled, then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let expected_balance = Wei::new_u64(INITIAL_ETH_BALANCE - ETH_EXIT_AMOUNT);
``` [8](#0-7) 

---

### Likelihood Explanation

**Likelihood: High.**

Any unprivileged EVM user can trigger this by calling `withdrawToNear` with a recipient NEAR account that is not registered with the NEP-141 contract. NEAR's NEP-141 standard requires storage registration before receiving tokens; unregistered accounts cause `ft_transfer` to fail. This is a routine user error (e.g., mistyping an account ID, using a freshly created account, or targeting a contract that does not implement NEP-141 storage). No special privileges, governance access, or admin keys are required. The attacker-controlled entry path is:

1. User holds bridged ERC-20 tokens on Aurora.
2. User calls `EvmErc20::withdrawToNear(unregistered_account, amount)`.
3. `_burn` executes unconditionally, reducing the user's EVM balance.
4. `ExitToNear` precompile fires `ft_transfer` with no callback (default build).
5. `ft_transfer` fails; no refund occurs.
6. Tokens are permanently lost.

---

### Recommendation

Enable the `error_refund` feature in all production builds, or restructure the promise construction so that a refund callback is always attached regardless of the feature flag. The callback in `exit_to_near_precompile_callback` already contains the correct re-mint logic via `engine::refund_on_error`; it simply needs to be reachable in the default build. [9](#0-8) [10](#0-9) 

---

### Proof of Concept

**Attacker-controlled entry path:**

```
User EVM tx
  → EvmErc20::withdrawToNear("unregistered.near", amount)
      → _burn(msg.sender, amount)          // ERC-20 balance reduced, irreversible
      → call(ExitToNear precompile, ...)
          → ExitToNear::run()
              → callback_args.refund = None  // error_refund not enabled
              → PromiseArgs::Create(ft_transfer)  // no callback attached
                  → ft_transfer("unregistered.near", amount)
                      → FAILS (account not registered)
                          → no callback → no refund → tokens permanently lost
```

The test `test_exit_to_near_refund` in `engine-tests/src/tests/erc20_connector.rs` (lines 623–666) directly demonstrates this: when compiled without `error_refund`, the ERC-20 balance after a failed exit is `FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT` rather than `FT_TRANSFER_AMOUNT`, confirming the tokens are not returned. [11](#0-10)

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

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
```

**File:** engine/src/contract_methods/connector.rs (L195-246)
```rust
#[named]
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
}
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
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
