### Title
ERC-20 Mirror Token Permanent Loss on Failed Cross-Chain Exit Due to Burn-Before-Confirm Pattern — (`etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`)

---

### Summary

Both `EvmErc20` and `EvmErc20V2` implement the **Burn** approach for cross-chain exits: ERC-20 tokens are burned on the Aurora EVM side *before* the corresponding NEAR-side `ft_transfer` is confirmed. When the `error_refund` compile-time feature is absent, no callback is registered and no re-mint occurs on NEAR-side failure. The burned ERC-20 tokens are permanently destroyed while the NEP-141 tokens remain locked inside the Aurora engine contract with no recovery path.

---

### Finding Description

`EvmErc20::withdrawToNear` and `EvmErc20V2::withdrawToNear` both call `_burn` unconditionally before invoking the exit precompile:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);          // ← tokens destroyed here
    // ...
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, ...);
        // res is never checked
    }
}
``` [1](#0-0) [2](#0-1) 

The exit precompile (`ExitToNear::run`) schedules an asynchronous NEAR `ft_transfer` promise. Whether a callback is registered depends on the `error_refund` compile-time feature:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,                          // ← always None without the feature
    transfer_near: transfer_near_args,
};

let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)  // ← NO callback registered
} else {
    PromiseArgs::Callback(...)
};
``` [3](#0-2) 

For a standard `ft_transfer` exit (the common case), `transfer_near_args` is `None`. Without `error_refund`, `callback_args` equals `ExitToNearPrecompileCallbackArgs::default()`, so the engine schedules a bare `PromiseArgs::Create` with **no callback**. If the NEAR-side `ft_transfer` fails (e.g., recipient account not registered with the NEP-141 contract), there is no mechanism to detect the failure or re-mint the burned ERC-20 tokens.

Even when a callback *is* registered (e.g., for wNEAR unwrap), the callback handler explicitly does nothing on failure without `error_refund`:

```rust
} else if let Some(args) = args.refund {
    // Exit call failed; need to refund tokens
    let refund_result = engine::refund_on_error(...)?;
    ...
} else {
    None  // ← reached when refund: None; no action taken
};
``` [4](#0-3) 

The engine's own integration test explicitly documents this behavior:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [5](#0-4) 

The same Burn-without-guarantee pattern applies to `withdrawToEthereum` in both contracts, where the `ExitToEthereum` precompile schedules a `withdraw` promise with **no callback at all**, making fund loss on failure unconditional regardless of any feature flag. [6](#0-5) [7](#0-6) 

---

### Impact Explanation

When the NEAR-side `ft_transfer` fails:

- The ERC-20 tokens are **permanently burned** — the user's on-chain balance is zero.
- The NEP-141 tokens remain **permanently locked** inside the Aurora engine contract with no recovery path.
- The ERC-20 `totalSupply` is reduced without a corresponding reduction in the NEP-141 balance held by Aurora, creating a permanent accounting imbalance in the bridge.

This constitutes **permanent freezing of user funds** (Critical). The `refund_on_error` path that re-mints ERC-20 tokens only exists when `error_refund` is compiled in. [8](#0-7) 

---

### Likelihood Explanation

Any unprivileged EVM user holding bridged ERC-20 tokens can trigger this by calling `withdrawToNear` with a NEAR recipient account that is not registered with the underlying NEP-141 contract. NEP-141 contracts require explicit storage registration; unregistered accounts cause `ft_transfer` to fail. This is a realistic user-facing scenario (e.g., typo in account ID, account not yet created, account not registered for the specific token). The `error_refund` feature is a compile-time opt-in, not a default, making deployments without it vulnerable. [9](#0-8) 

---

### Recommendation

Replace the Burn-before-confirm pattern with a **Lock/Unlock** approach analogous to the fix recommended in the external report:

- On `withdrawToNear`: transfer ERC-20 tokens to a custody address (e.g., the contract itself) instead of burning them.
- On successful NEAR-side callback: burn the custodied tokens.
- On failed NEAR-side callback: return the custodied tokens to the sender.

Alternatively, make the `error_refund` feature unconditionally enabled in all production builds and ensure the `EvmErc20` input encoding always includes the `refund_address` field so the callback can re-mint on failure. [1](#0-0) [3](#0-2) 

---

### Proof of Concept

1. Alice holds 100 units of a bridged ERC-20 token on Aurora (backed by 100 NEP-141 tokens held by the Aurora engine contract).
2. Alice calls `EvmErc20::withdrawToNear("unregistered.near", 100)`.
3. `_burn(Alice, 100)` executes — Alice's ERC-20 balance is 0, `totalSupply` decreases by 100.
4. The exit precompile schedules `ft_transfer(receiver_id: "unregistered.near", amount: 100)` on the NEP-141 contract.
5. The NEP-141 `ft_transfer` fails because `"unregistered.near"` is not registered.
6. Without `error_refund`, no callback is registered; the failure is silently ignored.
7. Alice has 0 ERC-20 tokens and 0 NEP-141 tokens. The 100 NEP-141 tokens remain locked in the Aurora engine contract forever.

This matches the behavior confirmed by the engine's own test suite at: [10](#0-9)

### Citations

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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L65-76)
```text
    function withdrawToEthereum(address recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes20 recipient_b = bytes20(recipient);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
        uint input_size = 1 + 32 + 20;

        assembly {
            let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
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
    }
```

**File:** engine-precompiles/src/native.rs (L449-484)
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
```

**File:** engine-precompiles/src/native.rs (L977-1003)
```rust
        let withdraw_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method: "withdraw".to_string(),
            args: serialized_args,
            attached_balance: Yocto::new(1),
            attached_gas: costs::WITHDRAWAL_GAS,
        };

        let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
        let promise_log = Log {
            address: exit_to_ethereum::ADDRESS.raw(),
            topics: Vec::new(),
            data: promise,
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_ethereum::ADDRESS.raw(),
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
