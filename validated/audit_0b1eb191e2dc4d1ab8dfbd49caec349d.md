### Title
`ExitToEthereum` Burns EVM-Side Tokens Without a Failure Callback, Causing Permanent Fund Loss on Promise Failure — (`engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToEthereum` precompile burns EVM-side ETH or ERC-20 tokens and schedules a NEAR promise to call `withdraw` on the connector contract. Unlike `ExitToNear`, which attaches a `exit_to_near_precompile_callback` to handle promise failure and optionally refund tokens, `ExitToEthereum` wraps its promise in a bare `PromiseArgs::Create` with no callback. If the `withdraw` promise fails for any reason, the EVM-side tokens are already permanently removed from the user's control with no recovery path.

---

### Finding Description

In `engine-precompiles/src/native.rs`, the `ExitToEthereum::run()` function handles two cases:

**Flag `0x0` — ETH (base token) exit:**
The user sends ETH to the precompile address via a CALL with value. The ETH is transferred out of the user's EVM balance and into the precompile address. A NEAR promise is then scheduled to call `withdraw` on the connector.

**Flag `0x1` — ERC-20 exit:**
The ERC-20 contract calls the precompile after burning the user's tokens. The ERC-20 tokens are already destroyed in the EVM state. A NEAR promise is scheduled to call `withdraw` on the connector.

In both cases, the promise is constructed as:

```rust
let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
``` [1](#0-0) 

There is no callback attached. If the `withdraw` call on the connector fails (e.g., connector contract panics, insufficient NEP-141 balance, gas exhaustion), the NEAR runtime does not roll back the already-committed EVM state changes. The EVM-side tokens are permanently gone.

Contrast this with `ExitToNear`, which constructs a `PromiseArgs::Callback` with a dedicated `exit_to_near_precompile_callback` that can refund tokens on failure:

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs {
        base: transfer_promise,
        callback: PromiseCreateArgs {
            ...
            method: "exit_to_near_precompile_callback".to_string(),
            ...
        },
    })
};
``` [2](#0-1) 

The `exit_to_near_precompile_callback` in `engine/src/contract_methods/connector.rs` explicitly handles the failure case by calling `engine::refund_on_error`: [3](#0-2) 

No equivalent protection exists for `ExitToEthereum`.

---

### Impact Explanation

**Critical — Permanent freezing/loss of funds.**

When the `withdraw` NEAR promise fails:
- For ETH exits: the ETH is irrecoverably locked at the precompile address (`0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`) in the EVM state, with no function to retrieve it.
- For ERC-20 exits: the ERC-20 tokens are already burned in the EVM contract; they cannot be re-minted without privileged admin action.

In both cases, the user loses their funds permanently. The EVM-side accounting (supply/balance) is reduced, but the Ethereum-side withdrawal never completes — an exact structural analog to the `ibRatio`/`totalSupply` desynchronization in the reference report.

---

### Likelihood Explanation

The `withdraw` call on the connector contract can fail under realistic conditions:
1. The connector contract's NEP-141 balance is insufficient due to a prior accounting discrepancy.
2. The connector contract is paused or upgraded mid-flight.
3. The attached gas (`WITHDRAWAL_GAS = 100 TGas`) is insufficient for the connector's execution path. [4](#0-3) 

Any user who calls `ExitToEthereum` during a period of connector instability is exposed. The entry path is fully unprivileged — any EVM account can call the precompile.

---

### Recommendation

Attach a failure callback to the `ExitToEthereum` promise, mirroring the `ExitToNear` pattern. On promise failure, the callback should:
- For ETH exits: transfer the ETH from the precompile address back to the original sender's EVM address.
- For ERC-20 exits: re-mint the burned ERC-20 tokens to the original sender.

This requires storing the refund parameters (sender address, token address, amount) in the promise callback args, analogous to `ExitToNearPrecompileCallbackArgs` and `RefundCallArgs` already used by `ExitToNear`. [5](#0-4) 

---

### Proof of Concept

**ETH exit scenario:**

1. User holds 1 ETH on Aurora EVM.
2. User calls the `ExitToEthereum` precompile (`0xb0bd02f6...`) with flag `0x0` and their Ethereum recipient address.
3. The EVM transfers 1 ETH from the user's balance to the precompile address (EVM state committed to NEAR storage).
4. A NEAR promise is scheduled: `connector.withdraw(recipient, 1 ETH)`.
5. The connector's `withdraw` call fails (e.g., connector paused, gas issue).
6. NEAR runtime does not roll back the EVM state — the 1 ETH remains at the precompile address.
7. No callback fires. The user's 1 ETH is permanently inaccessible.

**ERC-20 exit scenario:**

1. User holds 100 bridged ERC-20 tokens on Aurora EVM.
2. User calls the ERC-20 contract's `withdrawTo` / burn function, which internally calls `ExitToEthereum` precompile with flag `0x1`, amount = 100, and their Ethereum address.
3. The ERC-20 contract burns 100 tokens (EVM state committed).
4. A NEAR promise is scheduled: `nep141_connector.withdraw(recipient, 100)`.
5. The promise fails.
6. No callback fires. The 100 ERC-20 tokens are permanently destroyed; the user receives nothing on Ethereum. [6](#0-5)

### Citations

**File:** engine-precompiles/src/native.rs (L61-62)
```rust
    pub(super) const WITHDRAWAL_GAS: NearGas = NearGas::new(100_000_000_000_000);
}
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

**File:** engine-precompiles/src/native.rs (L916-990)
```rust
            0x1 => {
                // ERC-20 transfer
                //
                // This precompile branch is expected to be called from the ERC20 withdraw function
                // (or burn function with some flag provided that this is expected to be withdrawn)
                //
                // Input slice format:
                //  amount (U256 big-endian bytes) - the amount that was burned
                //  eth_recipient (20 bytes) - the address of recipient which will receive ETH on Ethereum

                if context.apparent_value != U256::from(0) {
                    return Err(ExitError::Other(Cow::from(
                        "ERR_ETH_ATTACHED_FOR_ERC20_EXIT",
                    )));
                }

                let erc20_address = context.caller;
                let nep141_address = get_nep141_from_erc20(erc20_address.as_bytes(), &self.io)?;
                let amount = parse_amount(&input[..32])?;

                input = &input[32..];

                if input.len() == 20 {
                    // Parse ethereum address in hex
                    let mut buffer = [0; 40];
                    hex::encode_to_slice(input, &mut buffer).unwrap();
                    let recipient_in_hex = str::from_utf8(&buffer).map_err(|_| {
                        ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS"))
                    })?;
                    // unwrap cannot fail since we checked the length already
                    let recipient_address = Address::try_from_slice(input)
                        .map_err(|_| ExitError::Other(Cow::from("ERR_WRONG_ADDRESS")))?;

                    (
                        nep141_address,
                        // There is no way to inject json, given the encoding of both arguments
                        // as decimal and hexadecimal respectively.
                        format!(
                            r#"{{"amount": "{}", "recipient": "{}"}}"#,
                            amount.as_u128(),
                            recipient_in_hex
                        )
                        .into_bytes(),
                        events::ExitToEth {
                            sender: Address::new(erc20_address),
                            erc20_address: Address::new(erc20_address),
                            dest: recipient_address,
                            amount,
                        },
                    )
                } else {
                    return Err(ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")));
                }
            }
            _ => {
                return Err(ExitError::Other(Cow::from(
                    "ERR_INVALID_RECEIVER_ACCOUNT_ID",
                )));
            }
        };

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
