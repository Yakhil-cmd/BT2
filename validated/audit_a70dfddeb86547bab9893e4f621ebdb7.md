### Title
Missing Refund Callback in `ExitToEthereum` Precompile Permanently Freezes ETH on Promise Failure - (`engine-precompiles/src/native.rs`)

### Summary

The `ExitToEthereum` precompile burns a user's EVM ETH balance by transferring it to the precompile address, then schedules a `withdraw` promise to the eth-connector. If that NEAR promise fails (e.g., the eth-connector's `withdraw` is paused), the ETH is permanently frozen at the precompile address with no recovery path. Unlike `ExitToNear`, which has a full error-recovery callback (`exit_to_near_precompile_callback`), `ExitToEthereum` never registers a callback regardless of build configuration.

### Finding Description

In `ExitToEthereum::run()`, after parsing the input and building the `withdraw` promise, the code wraps it unconditionally as `PromiseArgs::Create`:

```rust
let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
``` [1](#0-0) 

There is no `PromiseArgs::Callback` wrapper and no call to `exit_to_near_precompile_callback` or any equivalent. This means the NEAR runtime has no instruction to execute if the `withdraw` call to the eth-connector reverts or panics.

By contrast, `ExitToNear::run()` (when the `error_refund` feature is enabled) wraps the transfer promise in a `PromiseArgs::Callback` that calls `exit_to_near_precompile_callback`:

```rust
PromiseArgs::Callback(PromiseWithCallbackArgs {
    base: transfer_promise,
    callback: PromiseCreateArgs {
        target_account_id: self.current_account_id.clone(),
        method: "exit_to_near_precompile_callback".to_string(),
        ...
    },
})
``` [2](#0-1) 

That callback invokes `engine::refund_on_error`, which transfers ETH back from the precompile address to the original sender:

```rust
} else if let Some(args) = args.refund {
    let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;
``` [3](#0-2) 

The `refund_on_error` function for the ETH case transfers ETH from `exit_to_near::ADDRESS` back to the user:

```rust
let exit_address = exit_to_near::ADDRESS;
// ...
engine.call(&exit_address, &refund_address, amount, ...)
``` [4](#0-3) 

No equivalent exists for `exit_to_ethereum::ADDRESS`. The ETH transferred there during the EVM execution phase is irrecoverable if the subsequent NEAR promise fails.

The eth-connector's `withdraw` method is explicitly pausable by the owner, as demonstrated by the `engine_withdraw` pause key: [5](#0-4) 

When `withdraw` is paused and a user calls `ExitToEthereum`, the EVM state commits (ETH leaves the user's account and arrives at the precompile address), but the NEAR-side `withdraw` promise fails silently with no refund.

### Impact Explanation

**Critical — Permanent freezing of funds.**

Any ETH sent through the `ExitToEthereum` precompile while the eth-connector's `withdraw` is paused (or fails for any other reason) is permanently frozen at `exit_to_ethereum::ADDRESS` (`0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`). No user, admin, or contract can recover it because:

1. The EVM state is already committed — the user's balance is zero.
2. There is no callback to transfer ETH back.
3. The precompile address has no private key and cannot initiate a transfer.

The analog to the original report's "last withdrawer bears all the loss" is: any user who calls `ExitToEthereum` during a pause window loses their entire exit amount permanently, while users who exited before the pause received their Ethereum-side tokens normally.

### Likelihood Explanation

The eth-connector's `withdraw` function is explicitly designed to be pausable by the contract owner. A pause event (for security, upgrade, or maintenance) is a realistic and documented operational scenario. Any user who calls `ExitToEthereum` during such a window — even in good faith — permanently loses their ETH. The entry path requires only a standard EVM transaction from any user.

### Recommendation

Add an error-recovery callback to `ExitToEthereum::run()` mirroring the `ExitToNear` pattern. Specifically:

1. Encode a `RefundCallArgs` with `erc20_address: None` (ETH case) and `recipient_address` set to the caller.
2. Wrap the `withdraw_promise` in `PromiseArgs::Callback` pointing to a new `exit_to_ethereum_precompile_callback` method (or reuse `exit_to_near_precompile_callback` with appropriate dispatch).
3. In the callback, if the promise failed, call `engine::refund_on_error` to transfer ETH from `exit_to_ethereum::ADDRESS` back to the original sender.

### Proof of Concept

**Attack path:**

1. Owner (or governance) pauses the eth-connector's `withdraw` feature.
2. User A calls `ExitToEthereum` with 10 ETH — EVM deducts 10 ETH from User A's balance and transfers it to `exit_to_ethereum::ADDRESS`.
3. The NEAR `withdraw` promise executes and fails (paused).
4. No callback fires. ETH remains at `exit_to_ethereum::ADDRESS` permanently.
5. User A's EVM balance is 0; they received nothing on Ethereum.

**Code path:**

- Entry: `ExitToEthereum::run()` in `engine-precompiles/src/native.rs` line 850.
- ETH deducted from caller during EVM `call` to precompile address.
- Promise created at line 985 as `PromiseArgs::Create` — no callback registered.
- On NEAR promise failure: no handler exists; ETH at `exit_to_ethereum::ADDRESS` is unrecoverable. [6](#0-5)

### Citations

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

**File:** engine-precompiles/src/native.rs (L844-1003)
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
            output: Vec::new(),
        })
    }
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

**File:** engine/src/engine.rs (L1204-1224)
```rust
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

**File:** engine-tests-connector/src/connector.rs (L478-530)
```rust
#[tokio::test]
async fn test_withdraw_from_near_pausability() -> anyhow::Result<()> {
    let contract = TestContract::new_with_owner("owner").await?;
    let user_acc = contract
        .create_sub_account(DEPOSITED_RECIPIENT_NAME)
        .await?;
    let res = contract
        .deposit_eth_to_near(user_acc.id(), DEPOSITED_AMOUNT.into())
        .await?;
    assert!(res.is_success(), "{res:#?}");
    let res = contract
        .deposit_eth_to_near(
            contract.owner.as_ref().unwrap().id(),
            DEPOSITED_AMOUNT.into(),
        )
        .await?;
    assert!(res.is_success(), "{res:#?}");

    let pause_args = json!({"key": "engine_withdraw"});

    let withdraw_amount = NEP141Wei::new(100);
    // 1st withdraw - should succeed
    let res = user_acc
        .call(contract.engine_contract.id(), "withdraw")
        .args_borsh((*RECIPIENT_ADDRESS, withdraw_amount))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_success());

    // Pause withdraw
    let res = contract
        .owner
        .as_ref()
        .unwrap()
        .call(contract.eth_connector_contract.id(), "pa_pause_feature")
        .args_json(&pause_args)
        .max_gas()
        .transact()
        .await?;
    assert!(res.is_success(), "{res:#?}");

    // 2nd withdraw - should be failed
    let res = user_acc
        .call(contract.engine_contract.id(), "withdraw")
        .args_borsh((*RECIPIENT_ADDRESS, withdraw_amount))
        .max_gas()
        .deposit(ONE_YOCTO)
        .transact()
        .await?;
    assert!(res.is_failure());
    assert!(contract.check_error_message(&res, "Pausable: Method is paused")?);
```
