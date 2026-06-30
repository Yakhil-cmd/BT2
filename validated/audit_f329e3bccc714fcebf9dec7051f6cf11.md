### Title
Missing Zero Address Check on Ethereum Recipient in `ExitToEthereum` Precompile - (File: engine-precompiles/src/native.rs)

### Summary
The `ExitToEthereum` precompile (`ExitToEthereum::run`) accepts a caller-supplied 20-byte Ethereum recipient address for both the ETH base-token path (flag `0x00`) and the ERC-20 path (flag `0x01`). Neither path validates that the parsed `recipient_address` is non-zero before constructing and dispatching the cross-contract withdrawal promise. An unprivileged EVM caller who supplies an all-zero recipient address will have their Aurora-side tokens burned while the withdrawal is routed to `0x0000…0000` on Ethereum, permanently destroying the funds.

### Finding Description
In `ExitToEthereum::run` the recipient address is parsed directly from user-supplied calldata with no subsequent zero-address guard:

**Flag `0x00` (ETH base-token exit):** [1](#0-0) 

`recipient_address` is taken verbatim from the 20 input bytes and forwarded to `serialize_fn(recipient_address, context.apparent_value)`, which produces the withdrawal arguments sent to the eth-connector contract. If those 20 bytes are all zero, `recipient_address == Address::zero()` and the withdrawal proceeds unchecked.

**Flag `0x01` (ERC-20 exit):** [2](#0-1) 

`recipient_address` is again parsed from the trailing 20 bytes of calldata. `recipient_in_hex` becomes `"0000000000000000000000000000000000000000"` and is embedded in the JSON withdrawal args without any zero-address rejection.

In both branches the resulting `withdraw_promise` is dispatched to the eth-connector: [3](#0-2) 

The Aurora-side balance is already debited (ETH reduced or ERC-20 burned) at the point the EVM call executes; the promise carries the zero address to the connector, which will attempt to release funds to `0x0000…0000` on Ethereum.

### Impact Explanation
Funds are permanently lost. The Aurora-side debit is irreversible once the EVM call succeeds, and the Ethereum-side recipient `0x0000…0000` is an uncontrolled burn address. There is no recovery path. This satisfies the **Critical – Permanent freezing of funds** impact tier.

### Likelihood Explanation
Low-to-medium. The scenario is reachable by:
1. A user who accidentally passes a zero-filled byte array (e.g., an uninitialized variable in a calling contract).
2. A Solidity contract that wraps the exit precompile and derives the recipient address from storage or a return value that can be zero (the exact pattern in the reference report).
3. A malicious contract that tricks a user into approving a call that routes their exit to the zero address.

No privileged access is required; any EVM account can call the precompile directly.

### Recommendation
Add an explicit zero-address guard immediately after parsing `recipient_address` in both the `0x00` and `0x01` branches of `ExitToEthereum::run`:

```rust
if recipient_address == Address::zero() {
    return Err(ExitError::Other(Cow::from("ERR_INVALID_RECIPIENT_ADDRESS")));
}
```

Apply the same guard symmetrically in `ExitToNear` if a future path ever accepts a raw EVM address as the NEAR-side recipient.

### Proof of Concept
1. Deploy a Solidity contract on Aurora that calls the `ExitToEthereum` precompile at `0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab`.
2. Construct calldata: `flag = 0x00` followed by 20 zero bytes (`0x00` × 20).
3. Attach any non-zero ETH value to the call.
4. The precompile parses `recipient_address = Address::zero()`, serializes the withdrawal args with the zero address, and dispatches the `withdraw` promise to the eth-connector.
5. Aurora-side ETH is debited; the eth-connector initiates a withdrawal to `0x0000…0000` on Ethereum.
6. Funds are permanently unrecoverable. [4](#0-3) [5](#0-4)

### Citations

**File:** engine-precompiles/src/native.rs (L888-914)
```rust
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
```

**File:** engine-precompiles/src/native.rs (L916-968)
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
```

**File:** engine-precompiles/src/native.rs (L977-985)
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
