### Title
Unchecked `withdraw` Promise Result in `ExitToEthereum` Precompile Enables Permanent Fund Freeze — (File: `engine-precompiles/src/native.rs`)

---

### Summary

The `ExitToEthereum` precompile burns ERC-20 tokens inside the EVM and schedules a `withdraw` cross-contract call to the NEP-141 connector, but never attaches a callback to verify whether `withdraw` succeeded. If the connector's `withdraw` call fails for any reason, the ERC-20 tokens are permanently destroyed with no ETH released and no refund path — a permanent fund freeze.

---

### Finding Description

In `engine-precompiles/src/native.rs`, `ExitToEthereum::run()` constructs the outbound promise unconditionally as `PromiseArgs::Create`: [1](#0-0) 

```rust
let withdraw_promise = PromiseCreateArgs {
    target_account_id: nep141_address,
    method: "withdraw".to_string(),
    args: serialized_args,
    attached_balance: Yocto::new(1),
    attached_gas: costs::WITHDRAWAL_GAS,
};

let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
```

`PromiseArgs::Create` schedules a fire-and-forget call with **no callback**. There is no `exit_to_ethereum_precompile_callback` anywhere in `engine/src/contract_methods/connector.rs`. [2](#0-1) 

Contrast this with `ExitToNear`, which conditionally wraps its transfer promise in `PromiseArgs::Callback` to invoke `exit_to_near_precompile_callback` on failure (enabling token refunds via the `error_refund` feature): [3](#0-2) 

```rust
let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
    PromiseArgs::Create(transfer_promise)
} else {
    PromiseArgs::Callback(PromiseWithCallbackArgs {
        base: transfer_promise,
        callback: PromiseCreateArgs {
            method: "exit_to_near_precompile_callback".to_string(),
            ...
        },
    })
};
```

The ERC-20 burn is committed inside the EVM execution **before** the NEAR-side `withdraw` promise is dispatched. Once the EVM transaction completes, the token burn is irreversible. If the connector's `withdraw` call subsequently fails (panic, out-of-gas, paused state), the NEAR runtime silently drops the failed promise result — there is no callback to detect it, no re-mint, and no refund.

The `WITHDRAWAL_GAS` constant is set to 100 TGas: [4](#0-3) 

This is a fixed allocation that may be insufficient for certain connector implementations or future upgrades, making gas-exhaustion-induced failure a realistic trigger.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

A user who calls `exitToEthereum` on an ERC-20 contract will have their tokens burned in the EVM. If the connector's `withdraw` call fails for any reason, the ETH backing those tokens remains locked in the connector with no recovery path. The user permanently loses their assets with no on-chain recourse.

---

### Likelihood Explanation

**Low.** The connector is an Aurora-controlled trusted contract. Failure scenarios include: a bug in the connector contract, the connector being paused during a security incident, or gas exhaustion in the `withdraw` execution. An unprivileged user cannot directly force the connector to fail under normal conditions. However, the complete absence of any error-handling path means **any** connector failure — regardless of cause — results in irreversible user loss. The asymmetry with `ExitToNear` (which has the `error_refund` callback mechanism) confirms this is an unintended omission rather than a deliberate design choice.

---

### Recommendation

Add a callback to the `ExitToEthereum` promise analogous to `exit_to_near_precompile_callback`. The callback should:
1. Check `handler.promise_result(0)` for `PromiseResult::Successful`.
2. On failure, re-mint the burned ERC-20 tokens to the original sender (mirroring the `refund_on_error` path used in `ExitToNear`).

Alternatively, adopt the same `error_refund` feature flag pattern already present in `ExitToNear` and extend it to cover `ExitToEthereum`.

---

### Proof of Concept

1. User calls `withdraw(amount, ethRecipient)` on an Aurora ERC-20 contract.
2. The ERC-20 contract burns `amount` tokens and calls the `exitToEthereum` precompile at `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`.
3. `ExitToEthereum::run()` constructs `PromiseArgs::Create(withdraw_promise)` targeting the connector's `withdraw` method — **no callback attached**.
4. The EVM transaction completes; the token burn is committed to state.
5. The NEAR runtime executes the `withdraw` promise; the connector panics (e.g., due to a bug, pause, or gas exhaustion).
6. No callback exists to detect the failure; the failed promise result is silently discarded.
7. The user's ERC-20 tokens are permanently burned; no ETH is released on Ethereum; no refund is issued. [5](#0-4)

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

**File:** engine-precompiles/src/native.rs (L844-1000)
```rust
impl<I: IO> Precompile for ExitToEthereum<I> {
    fn required_gas(_input: &[u8]) -> Result<EthGas, ExitError> {
        Ok(costs::EXIT_TO_ETHEREUM_GAS)
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        is_static: bool,
    ) -> EvmPrecompileResult {
        // ETH (Base token) transfer input format (min size 21 bytes)
        //  - flag (1 byte)
        //  - eth_recipient (20 bytes)
        // ERC-20 transfer input format: max 53 bytes
        //  - flag (1 byte)
        //  - amount (32 bytes)
        //  - eth_recipient (20 bytes)
        validate_input_size(input, 21, 53)?;

        let required_gas = Self::required_gas(input)?;

        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_ethereum::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }

        // The first byte of the input is a flag, selecting the behavior to be triggered:
        //  0x00 -> ETH (Base token) token transfer
        //  0x01 -> ERC-20 transfer
        let mut input = input;
        let flag = input[0];
        input = &input[1..];

        let (nep141_address, serialized_args, exit_event) = match flag {
            0x0 => {
                // ETH (base) transfer
                //
                // Input slice format:
                //  eth_recipient (20 bytes) - the address of recipient which will receive ETH on Ethereum
                let recipient_address: Address = input
                    .try_into()
                    .map_err(|_| ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")))?;
                let serialize_fn = match get_withdraw_serialize_type(&self.io)? {
                    WithdrawSerializeType::Json => json_args,
                    WithdrawSerializeType::Borsh => borsh_args,
                };
                let eth_connector_account_id = self.get_eth_connector_contract_account()?;

                (
                    eth_connector_account_id,
                    // There is no way to inject json, given the encoding of both arguments
                    // as decimal and hexadecimal respectively.
                    serialize_fn(recipient_address, context.apparent_value)?,
                    events::ExitToEth {
                        sender: Address::new(context.caller),
                        erc20_address: events::ETH_ADDRESS,
                        dest: recipient_address,
                        amount: context.apparent_value,
                    },
                )
            }
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
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_ethereum::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
            cost: required_gas,
```

**File:** engine/src/contract_methods/connector.rs (L196-246)
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
}
```
