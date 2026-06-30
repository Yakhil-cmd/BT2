### Title
Relayer Fee Silently Dropped in `receive_base_tokens` — (`engine/src/engine.rs`)

---

### Summary

`receive_base_tokens` in `engine/src/engine.rs` parses a `FtTransferMessageData` that may carry a relayer fee (legacy bridge message format), but the parsed fee is **never used**. The full bridged amount is credited to the recipient and the relayer receives nothing, permanently losing the fee they were promised.

---

### Finding Description

`FtTransferMessageData` supports two message formats:

- **Current (40-char hex address only):** no fee.
- **Legacy (`relayer_id:fee_hex+address_hex`):** includes a relayer fee.

The legacy format is still fully parsed and accepted without error: [1](#0-0) [2](#0-1) 

However, in `receive_base_tokens`, after parsing `message_data`, only `message_data.recipient` is used. `message_data.fee` is silently discarded: [3](#0-2) 

The full `args.amount` (including the fee portion) is credited to the recipient. The relayer's address is never looked up and no balance adjustment is made for the fee.

This is the direct analog of the MasterChef bug: a fee is parsed and acknowledged by the data structure, but is never routed to its intended recipient.

---

### Impact Explanation

**High — Theft of unclaimed yield.**

Any relayer who submits an ETH bridge transaction using the legacy message format (still accepted, no error returned) will permanently lose the fee they encoded in the message. The fee amount is instead silently gifted to the recipient (who receives `amount` instead of `amount − fee`). The relayer has no recourse; the fee is not locked in a recoverable location — it is simply credited to the wrong party.

---

### Likelihood Explanation

**Medium.** The legacy message format is still parsed and accepted without returning an error. No on-chain or off-chain mechanism prevents a relayer from submitting a transaction with a non-zero fee field. The `#[deprecated]` Rust attribute is a compile-time hint to developers, not a runtime guard — it does not reject or revert calls that include a fee. Any relayer operating from older tooling or documentation that references the legacy format will trigger this silently.

---

### Recommendation

Choose one of:

1. **Reject the legacy format at runtime:** if `message_data.fee` is `Some(_)` and non-zero, return an error so the caller is not misled.
2. **Honour the fee:** deduct `fee.amount` from the amount credited to the recipient and credit it to the relayer's EVM address (analogous to how `refund_unused_gas` credits the relayer in `engine/src/engine.rs`). [4](#0-3) 

---

### Proof of Concept

1. Relayer `R` registers their EVM address with Aurora Engine via `register_relayer`.
2. User `A` initiates an ETH bridge deposit. The bridge message is encoded in the legacy format: `"R.near:<32-byte fee hex><20-byte recipient hex>"` with fee = 100 wei.
3. The ETH connector calls `ft_on_transfer` on Aurora Engine with `amount = 1000` and the above message.
4. `ft_on_transfer` routes to `receive_base_tokens` (predecessor is the connector account).
5. `FtTransferMessageData::try_from` successfully parses `recipient` and `fee = Some(100 wei)`.
6. `receive_base_tokens` sets recipient's balance to `old_balance + 1000` (full amount, fee not deducted).
7. Relayer `R`'s balance is never touched. The 100 wei fee is permanently lost to the relayer. [5](#0-4) [6](#0-5)

### Citations

**File:** engine-types/src/parameters/connector.rs (L29-35)
```rust
#[derive(BorshSerialize, BorshDeserialize)]
#[cfg_attr(not(target_arch = "wasm32"), derive(Debug, PartialEq, Eq))]
pub struct FtTransferMessageData {
    pub recipient: Address,
    #[deprecated]
    pub fee: Option<FtTransferFee>,
}
```

**File:** engine-types/src/parameters/connector.rs (L59-103)
```rust
        // This logic is for backward compatibility to parse the message of the deprecated format.
        // "{relayer_id}:0000000000000000000000000000000000000000000000000000000000000000{hex_address}"

        // Split message by separator
        let (account, msg) = message
            .split_once(':')
            .ok_or(errors::ParseOnTransferMessageError::TooManyParts)?;

        // Check relayer account id from 1-th data element
        let account_id = account
            .parse()
            .map_err(|_| errors::ParseOnTransferMessageError::InvalidAccount)?;

        // Decode message array from 2-th element of data array
        // Length = fee[32] + eth_address[20] bytes
        let mut data = [0; 52];
        hex::decode_to_slice(msg, &mut data).map_err(|e| match e {
            hex::FromHexError::InvalidHexCharacter { .. } | hex::FromHexError::OddLength => {
                errors::ParseOnTransferMessageError::InvalidHexData
            }
            hex::FromHexError::InvalidStringLength => {
                errors::ParseOnTransferMessageError::WrongMessageFormat
            }
        })?;

        // Parse the fee from the message slice.
        // The fee is expected to be represented as a 32-byte value in the message.
        // However, it will be parsed and converted to u128 for further processing.
        // This parsing logic is implemented to ensure compatibility
        let fee_u128: u128 = U256::from_little_endian(&data[..32])
            .try_into()
            .map_err(|_| errors::ParseOnTransferMessageError::OverflowNumber)?;
        let fee_amount: Fee = fee_u128.into();

        // Get recipient Eth address from message slice
        let recipient = Address::try_from_slice(&data[32..]).unwrap();

        #[allow(deprecated)]
        Ok(Self {
            recipient,
            fee: Some(FtTransferFee {
                relayer: account_id,
                amount: fee_amount,
            }),
        })
```

**File:** engine/src/engine.rs (L773-790)
```rust
    pub fn receive_base_tokens(
        &mut self,
        args: &FtOnTransferArgs,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let message_data = FtTransferMessageData::try_from(args.msg.as_str())?;
        let amount = Wei::new_u128(args.amount.as_u128());
        let receipient = message_data.recipient;
        let balance = get_balance(&self.io, &receipient);
        let new_balance = balance
            .checked_add(amount)
            .ok_or(errors::ERR_BALANCE_OVERFLOW)?;

        set_balance(&mut self.io, &receipient, &new_balance);

        sdk::log!("Mint {amount} base tokens for: {}", receipient.encode());

        Ok(None)
    }
```

**File:** engine/src/engine.rs (L1262-1300)
```rust
pub fn refund_unused_gas<I: IO>(
    io: &mut I,
    sender: &Address,
    gas_used: u64,
    gas_result: &GasPaymentResult,
    relayer: &Address,
    fixed_gas: Option<EthGas>,
) -> Result<(), GasPaymentError> {
    if gas_result.effective_gas_price.is_zero() {
        return Ok(());
    }

    let (refund, relayer_reward) = {
        let gas_to_wei = |price: U256| {
            fixed_gas
                .map_or_else(|| gas_used.into(), EthGas::as_u256)
                .checked_mul(price)
                .map(Wei::new)
                .ok_or(GasPaymentError::EthAmountOverflow)
        };

        let spent_amount = gas_to_wei(gas_result.effective_gas_price)?;
        let reward_amount = gas_to_wei(gas_result.priority_fee_per_gas)?;

        let refund = gas_result
            .prepaid_amount
            .checked_sub(spent_amount)
            .ok_or(GasPaymentError::EthAmountOverflow)?;

        (refund, reward_amount)
    };

    if !refund.is_zero() {
        add_balance(io, sender, refund)?;
    }

    if !relayer_reward.is_zero() {
        add_balance(io, relayer, relayer_reward)?;
    }
```
